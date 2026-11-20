//! On-the-fly DNSSEC signing.

#[cfg(feature = "dnssec-aws")]
mod aws;
pub(crate) mod setup;
mod signing;

use pharos_dnssec::{keys::KeyPair, sign::SigningKey};
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{Context, Error, Next, Outcome, Plugin, Protocol};
use std::sync::Mutex;

#[derive(Debug)]
pub struct Dnssec {
    zones: Vec<Name>,
    keys: Vec<KeyPair>,
    signers: Vec<SigningKey>,
    public: Vec<Vec<u8>>,
    capacity: usize,
    // shortcut: caches whole Responses; use RRset keys when canonicalization supports allocation-free buffers.
    // shortcut: expired entries persist until replacement or eviction; sweep when cache lifecycle supports cleanup.
    cache: Mutex<signing::SigCache>,
    metrics: Vec<(std::net::SocketAddr, pharos_server::metrics::DnssecMetrics)>,
}

// shortcut: all-feature debug chains can overflow 2 MiB stacks; flatten dispatch to remove this limit.
impl Plugin for Dnssec {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        // RFC 9824 §3.5: An implementing DNS server returns FORMERR for any QTYPE NXNAME query.
        if cx
            .query
            .questions()
            .any(|question| question.qtype == Type::NXNAME)
        {
            return match nxname_formerr(cx) {
                Ok(()) => Outcome::Response,
                Err(error) => Outcome::Error(error),
            };
        }
        let matching = cx.query.questions().next().and_then(|question| {
            let zone = self.zone_for(question.name)?;
            let has_zone_key = self.keys.iter().any(|key| key.public.owner == *zone);
            // RFC 4035 §3.1: DNSSEC proof processing applies only to signed zones.
            has_zone_key.then_some((question, zone))
        });
        // RFC 1035 §3.2.5: QCLASS=CH requests Chaos data, not the configured IN signing key.
        let class_matches = matching
            .as_ref()
            .is_some_and(|(question, _)| matches!(question.qclass, Class::IN | Class::ANY));
        // RFC 4033 §9: DO queries in configured zones receive DNSSEC records.
        let do_bit = class_matches && cx.query.opt().is_some_and(|opt| opt.dnssec_ok());
        // RFC 1035 §3.2.5: IN and ANY queries may use configured IN DNSKEYs.
        let intercepted = matching.is_some_and(|(question, zone)| {
            class_matches && question.qtype == Type::DNSKEY && question.name == *zone
        });
        let outcome = if intercepted {
            match self.dnskey(cx) {
                Ok(()) => Outcome::Response,
                Err(error) => Outcome::Error(error),
            }
        } else {
            next.run(cx).await
        };
        // RFC 4035 §3.1: DO responses from signed zones include required DNSSEC records.
        if do_bit && outcome == Outcome::Response {
            return match self.sign_response(cx) {
                Ok(()) => Outcome::Response,
                Err(error) => Outcome::Error(error),
            };
        }
        outcome
    }
}

fn nxname_formerr(cx: &mut Context<'_, '_>) -> Result<(), Error> {
    if cx.query.questions().next().is_none() {
        return Err(Error::InvalidQuery);
    }
    let max_size =
        Dnssec::ensure_response_capacity(cx.response, cx.protocol, cx.max_response_size)?;
    // RFC 1035 §4.1.1: FORMERR responses copy opcode and RD and set QR and RCODE.
    let flags = 0x8001 | (cx.query.flags() & 0x7900);
    let mut builder =
        MessageBuilder::new(cx.response, max_size, cx.query.id(), flags).map_err(Error::Build)?;
    for question in cx.query.questions() {
        builder
            .question(question.name, question.qtype, question.qclass)
            .map_err(Error::Build)?;
    }
    let _ = builder.finish();
    Ok(())
}

impl Dnssec {
    pub(crate) fn set_metrics(
        &mut self,
        registry: &pharos_server::metrics::Registry,
        listeners: &[pharos_server::ListenerKey],
    ) {
        for listener in listeners {
            let address = listener.address;
            let server = if address.ip().is_unspecified() {
                format!("dns://:{}", address.port())
            } else {
                format!("dns://{address}")
            };
            self.metrics.push((address, registry.dnssec(&server)));
        }
    }
    fn zone_for(&self, name: NameRef<'_>) -> Option<&Name> {
        let count = name.labels().count();
        self.zones
            .iter()
            .filter(|zone| {
                let suffix = NameRef::parse(zone.as_wire(), 0).expect("valid zone");
                let labels = zone.label_count();
                count >= labels
                    && name
                        .labels()
                        .skip(count - labels)
                        .zip(suffix.labels())
                        // RFC 4343 §3: match DNS labels using ASCII case-insensitive comparison.
                        .all(|(a, b)| a.eq_ignore_ascii_case(b))
            })
            .max_by_key(|zone| zone.label_count())
    }
    fn ensure_response_capacity(
        response: &mut Vec<u8>,
        protocol: Protocol,
        limit: usize,
    ) -> Result<usize, Error> {
        let max_size = limit.max(512);
        if response.capacity() < max_size {
            if protocol == Protocol::Tcp {
                response.reserve(max_size.saturating_sub(response.len()));
            } else {
                return Err(Error::ResponseBufferTooSmall);
            }
        }
        Ok(max_size)
    }
    fn dnskey(&self, cx: &mut Context<'_, '_>) -> Result<(), Error> {
        let question = cx.query.questions().next().ok_or(Error::InvalidQuery)?;
        let max_size =
            Self::ensure_response_capacity(cx.response, cx.protocol, cx.max_response_size)?;
        // RFC 4035 §2.1: the zone apex DNSKEY RRset carries the zone's public keys.
        // RFC 1035 §4.1.1: keep opcode and RD; RFC 4035 §3.1.6: clear CD in authoritative replies.
        let flags = 0x8400 | (cx.query.flags() & 0x7900);
        let mut builder = MessageBuilder::new(cx.response, max_size, cx.query.id(), flags)
            .map_err(Error::Build)?;
        builder
            .question(question.name, question.qtype, question.qclass)
            .map_err(Error::Build)?;
        // RFC 2181 §5.2: every record in an RRset uses its lowest TTL.
        // RFC 4035 §2.1: Publish only keys belonging to the queried zone.
        let keys = self
            .keys
            .iter()
            .zip(&self.public)
            .filter(|(key, _)| question.name == key.public.owner);
        let ttl = keys
            .clone()
            .map(|(key, _)| key.public.ttl.unwrap_or(3600))
            .min()
            .unwrap_or(3600);
        for (_, rdata) in keys {
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::DNSKEY,
                    Class::IN,
                    ttl,
                    rdata,
                )
                .map_err(Error::Build)?;
        }
        let _ = builder.finish();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
