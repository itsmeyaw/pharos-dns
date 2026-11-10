//! Cache configuration and DNS Response storage.

mod setup;
mod store;

use std::{fmt::Write, net::SocketAddr, time::SystemTime};

use pharos_proto::{
    Message, MessageBuilder, MessageMut, Name, NameRef, Opcode, Rcode, Rdata, ResponseType, Type,
};
use pharos_server::{Context, Next, Outcome, Plugin};

/// Configuration for the cache Plugin.
pub struct Cache {
    config: setup::Config,
    success: store::Store,
    denial: store::Store,
    metrics: Vec<(SocketAddr, pharos_server::metrics::CacheMetrics)>,
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
            metrics: Vec::new(),
            config,
        })
    }

    pub(crate) fn set_metrics(
        &mut self,
        registry: &pharos_server::metrics::Registry,
        listeners: &[pharos_server::ListenerKey],
    ) {
        let zones = self
            .config
            .zones
            .iter()
            .map(Name::canonical)
            .collect::<Vec<_>>()
            .join(",");
        for listener in listeners {
            let address = listener.address;
            let server = if address.ip().is_unspecified() {
                format!("dns://:{}", address.port())
            } else {
                format!("dns://{address}")
            };
            self.metrics
                .push((address, registry.cache(&server, &zones, "")));
        }
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
        let metrics = self
            .metrics
            .iter()
            .find_map(|(address, metrics)| (*address == cx.local).then_some(metrics));
        if let Some(metrics) = metrics {
            metrics.request();
        }
        let key = key(&query);
        if self
            .denial
            .serve(key, &query, cx.response, self.config.keepttl)
        {
            if let Some(metrics) = metrics {
                metrics.hit(true);
            }
            return Outcome::Response;
        }
        if self
            .success
            .serve(key, &query, cx.response, self.config.keepttl)
        {
            if let Some(metrics) = metrics {
                metrics.hit(false);
            }
            return Outcome::Response;
        }
        if let Some(metrics) = metrics {
            metrics.miss();
        }
        // shortcut: downstream AD is not forced; separate Query and Metadata lifetimes to refresh authentication.
        let outcome = next.run(cx).await;
        if outcome != Outcome::Response {
            if matches!(
                outcome,
                Outcome::Unanswered(Rcode::SERVFAIL) | Outcome::Error(_)
            ) && !self.config.fail_ttl.is_zero()
                && !self
                    .config
                    .disable_denial
                    .iter()
                    .any(|zone| contains(question.name, zone))
            {
                let ttl = self.config.fail_ttl.as_secs() as u32;
                if ttl > 0
                    && let Ok(mut builder) = MessageBuilder::new(
                        cx.response,
                        65535,
                        query.id(),
                        0x8002 | (query.flags() & 0x0110),
                    )
                    && matches!(
                        builder.question(question.name, question.qtype, question.qclass),
                        Ok(true)
                    )
                {
                    let _ = builder.finish();
                    if let Ok(response) = Message::parse(cx.response)
                        && let Some(evicted) = self.denial.insert(key, &response, ttl)
                        && let Some(metrics) = metrics
                    {
                        if evicted {
                            metrics.evict(true);
                        }
                        metrics.entries(false, self.success.len());
                        metrics.entries(true, self.denial.len());
                    }
                }
            }
            return outcome;
        }
        let Ok(response) = Message::parse(cx.response) else {
            return outcome;
        };
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs().min(i64::MAX as u64) as i64);
        let mut response_type = pharos_proto::typify_response(Some(&response), now);
        let has_soa = response.authorities().any(|rr| rr.rtype == Type::SOA);
        let incomplete = response_type == ResponseType::Positive
            && response.answer_count() > 0
            && !answers_question(&response);
        if incomplete && has_soa {
            response_type = ResponseType::NoData;
        }
        let denial = matches!(
            response_type,
            ResponseType::NxDomain | ResponseType::NoData | ResponseType::ServerError
        );
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
        if response_type == ResponseType::ServerError {
            ttl = self.config.fail_ttl.as_secs() as u32;
        }
        let matches = response.questions().next().is_some_and(|q| {
            q.name == question.name && q.qtype == question.qtype && q.qclass == question.qclass
        });
        let eligible = !response.tc()
            && ttl > 0
            && (!incomplete || has_soa)
            && (matches!(
                response_type,
                ResponseType::Positive
                    | ResponseType::Referral
                    | ResponseType::NoData
                    | ResponseType::ServerError
            ) || (response_type == ResponseType::NxDomain && has_soa));
        if eligible
            && !matches
            && let Some(metrics) = metrics
        {
            metrics.drop_response();
        }
        let cacheable = eligible && matches;
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
            let inserted = if denial {
                self.denial.insert(key, &response, ttl)
            } else {
                self.success.insert(key, &response, ttl)
            };
            if let Some(evicted) = inserted
                && let Some(metrics) = metrics
            {
                if evicted {
                    metrics.evict(denial);
                }
                metrics.entries(false, self.success.len());
                metrics.entries(true, self.denial.len());
            }
        }
        if !query.ad() && !query.opt().is_some_and(|opt| opt.dnssec_ok()) {
            cx.response[3] &= !0x20;
        }
        strip_trailing_opt(cx.response);
        outcome
    }
}

fn strip_trailing_opt(wire: &mut Vec<u8>) {
    let Ok(message) = Message::parse(wire) else {
        return;
    };
    if message.rcode().0 > 15 {
        return;
    }
    let Some(opt) = message
        .additionals()
        .last()
        .filter(|record| record.rtype == Type::OPT)
    else {
        return;
    };
    let start = opt.ttl_offset - 4 - opt.name.wire_len();
    let count = message.additional_count() - 1;
    wire.truncate(start);
    wire[10..12].copy_from_slice(&count.to_be_bytes());
}

fn answers_question(message: &Message<'_>) -> bool {
    let Some(question) = message.questions().next() else {
        return false;
    };
    let matches_class =
        |class| question.qclass == pharos_proto::Class::ANY || question.qclass == class;
    if question.qtype == Type::ANY {
        return message
            .answers()
            .any(|rr| rr.name == question.name && matches_class(rr.class));
    }
    let mut name = question.name.to_name();
    let mut visited = Vec::new();
    loop {
        if visited.contains(&name) {
            return false;
        }
        visited.push(name.clone());
        let mut target: Option<Name> = None;
        for rr in message.answers() {
            if rr.rtype != Type::CNAME || rr.name != name || !matches_class(rr.class) {
                continue;
            }
            let Ok(Rdata::Cname(alias)) = rr.data() else {
                return false;
            };
            if target.as_ref().is_some_and(|existing| alias != *existing) {
                return false;
            }
            target = Some(alias.to_name());
        }
        if question.qtype == Type::CNAME {
            return target.is_some();
        }
        match target {
            Some(alias) => name = alias,
            None => {
                return message.answers().any(|rr| {
                    rr.rtype == question.qtype && rr.name == name && matches_class(rr.class)
                });
            }
        }
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
