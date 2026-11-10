//! Cache configuration and DNS Response storage.

mod setup;
mod store;

use std::{fmt::Write, time::SystemTime};

use pharos_proto::{Message, MessageMut, Name, NameRef, Opcode, Rdata, ResponseType, Type};
use pharos_server::{Context, Next, Outcome, Plugin};

/// Configuration for the cache Plugin.
pub struct Cache {
    config: setup::Config,
    success: store::Store,
    denial: store::Store,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl Cache {
    pub(crate) fn parse(
        cursor: &mut pharos_corefile::Cursor<'_>,
        zones: &[String],
    ) -> Result<Self, pharos_corefile::Error> {
        let zones: Vec<&str> = zones.iter().map(String::as_str).collect();
        let config = setup::parse(cursor, &zones)?;
        Ok(Self {
            success: store::Store::new(config.success_capacity),
            denial: store::Store::new(config.denial_capacity),
            config,
        })
    }
}

impl Plugin for Cache {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let query = cx.query;
        let Some(question) = query.questions().next() else {
            return next.run(cx).await;
        };
        if query.opcode() != Opcode::QUERY
            || !self
                .config
                .zones
                .iter()
                .any(|zone| contains(question.name, zone))
        {
            return next.run(cx).await;
        }
        let key = key(&query);
        if self
            .denial
            .serve(key, &query, cx.response, self.config.keepttl)
            || self
                .success
                .serve(key, &query, cx.response, self.config.keepttl)
        {
            return Outcome::Response;
        }
        let outcome = next.run(cx).await;
        if outcome != Outcome::Response {
            return outcome;
        }
        let Ok(response) = Message::parse(cx.response) else {
            return outcome;
        };
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs().min(i64::MAX as u64) as i64);
        let response_type = pharos_proto::typify_response(Some(&response), now);
        let denial = matches!(response_type, ResponseType::NxDomain | ResponseType::NoData);
        let (minimum, maximum) = if denial {
            (self.config.denial_min_ttl, self.config.denial_max_ttl)
        } else {
            (self.config.success_min_ttl, self.config.success_max_ttl)
        };
        let minimum = minimum.as_secs().min(u64::from(u32::MAX)) as u32;
        let maximum = maximum.as_secs().min(u64::from(u32::MAX)) as u32;
        let mut ttl = maximum;
        let mut found = false;
        for record in response
            .answers()
            .chain(response.authorities())
            .chain(response.additionals())
        {
            if record.rtype == Type::OPT {
                continue;
            }
            found = true;
            ttl = ttl.min(record.ttl);
            if denial && let Ok(Rdata::Soa { minimum, .. }) = record.data() {
                ttl = ttl.min(minimum);
            }
        }
        if !found || response_type == ResponseType::Referral {
            ttl = 5;
        }
        ttl = ttl.max(minimum).min(maximum);
        let matches = response.questions().next().is_some_and(|q| {
            q.name == question.name && q.qtype == question.qtype && q.qclass == question.qclass
        });
        let has_soa = response.authorities().any(|rr| rr.rtype == Type::SOA);
        let cacheable = !response.tc()
            && matches
            && ttl > 0
            && (matches!(
                response_type,
                ResponseType::Positive | ResponseType::Referral | ResponseType::NoData
            ) || (response_type == ResponseType::NxDomain && has_soa));
        let disabled = if denial {
            &self.config.disable_denial
        } else {
            &self.config.disable_success
        };
        let cacheable = cacheable && !disabled.iter().any(|zone| contains(question.name, zone));
        if let Ok(mut mutable) = MessageMut::parse(cx.response) {
            mutable.rewrite_ttls(|_| ttl);
        }
        if cacheable && let Ok(response) = Message::parse(cx.response) {
            if denial {
                self.denial.insert(key, &response, ttl);
            } else {
                self.success.insert(key, &response, ttl);
            }
        }
        if !query.ad() && !query.opt().is_some_and(|opt| opt.dnssec_ok()) {
            cx.response[3] &= !0x20;
        }
        outcome
    }
}

fn contains(name: NameRef<'_>, domain: &Name) -> bool {
    let domain = NameRef::parse(domain.as_wire(), 0).expect("configured Domain");
    let count = name.labels().count();
    let suffix = domain.labels().count();
    count >= suffix
        && name
            .labels()
            .skip(count - suffix)
            .zip(domain.labels())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

struct KeyHash(u64);
impl KeyHash {
    fn bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        }
    }
}
impl std::fmt::Write for KeyHash {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        for byte in value.bytes() {
            self.bytes(&[byte.to_ascii_lowercase()]);
        }
        Ok(())
    }
}

fn key(query: &Message<'_>) -> u64 {
    let question = query.questions().next().expect("Query has a Question");
    let mut hash = KeyHash(0xcbf29ce484222325);
    hash.bytes(&[if query.opt().is_some_and(|opt| opt.dnssec_ok()) {
        b'1'
    } else {
        b'0'
    }]);
    hash.bytes(&[if query.cd() { b'1' } else { b'0' }]);
    hash.bytes(&question.qtype.0.to_be_bytes());
    hash.bytes(&question.qclass.0.to_be_bytes());
    write!(hash, "{}", question.name).expect("hash writer never fails");
    hash.0
}
