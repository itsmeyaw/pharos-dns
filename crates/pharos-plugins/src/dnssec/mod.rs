//! On-the-fly DNSSEC signing.

#[cfg(feature = "dnssec-aws")]
mod aws;
pub(crate) mod setup;
mod signing;

use pharos_dnssec::keys::KeyPair;
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{Context, Error, Next, Outcome, Plugin, Protocol};
use std::{collections::HashMap, sync::Mutex};

#[derive(Debug)]
pub struct Dnssec {
    zones: Vec<Name>,
    keys: Vec<KeyPair>,
    public: Vec<Vec<u8>>,
    capacity: usize,
    // shortcut: caches whole Responses; use RRset keys when canonicalization supports allocation-free buffers.
    // shortcut: expired entries persist until replacement or eviction; sweep when cache lifecycle supports cleanup.
    cache: Mutex<HashMap<Vec<u8>, signing::CacheEntry>>,
    metrics: Vec<(std::net::SocketAddr, pharos_server::metrics::DnssecMetrics)>,
}

// shortcut: all-feature debug chains can overflow 2 MiB stacks; flatten dispatch to remove this limit.
impl Plugin for Dnssec {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let matching = cx.query.questions().next().and_then(|question| {
            self.zone_for(question.name)
                .map(|zone| question.qtype == Type::DNSKEY && question.name == *zone)
        });
        let do_bit = matching.is_some() && cx.query.opt().is_some_and(|opt| opt.dnssec_ok());
        let intercepted = matching.unwrap_or(false);
        let outcome = if intercepted {
            match self.dnskey(cx) {
                Ok(()) => Outcome::Response,
                Err(error) => Outcome::Error(error),
            }
        } else {
            next.run(cx).await
        };
        if do_bit && outcome == Outcome::Response {
            return match self.sign_response(cx) {
                Ok(()) => Outcome::Response,
                Err(error) => Outcome::Error(error),
            };
        }
        outcome
    }
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
                        .all(|(a, b)| a.eq_ignore_ascii_case(b))
            })
            .max_by_key(|zone| zone.label_count())
    }
    fn dnskey(&self, cx: &mut Context<'_, '_>) -> Result<(), Error> {
        let question = cx.query.questions().next().ok_or(Error::InvalidQuery)?;
        let max_size = cx.max_response_size.max(512);
        if cx.response.capacity() < max_size {
            if cx.protocol == Protocol::Tcp {
                cx.response
                    .reserve(max_size.saturating_sub(cx.response.len()));
            } else {
                return Err(Error::ResponseBufferTooSmall);
            }
        }
        // RFC 4035 §2.1: the zone apex DNSKEY RRset carries the zone's public keys.
        // RFC 1035 §4.1.1: keep the Query's opcode and RD; RFC 4035 §3.1.6: copy CD.
        let flags = 0x8400 | (cx.query.flags() & 0x7910);
        let mut builder = MessageBuilder::new(cx.response, max_size, cx.query.id(), flags)
            .map_err(Error::Build)?;
        builder
            .question(question.name, question.qtype, question.qclass)
            .map_err(Error::Build)?;
        for (key, rdata) in self.keys.iter().zip(&self.public) {
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::DNSKEY,
                    Class::IN,
                    key.public.ttl.unwrap_or(3600),
                    rdata,
                )
                .map_err(Error::Build)?;
        }
        let _ = builder.finish();
        Ok(())
    }
}
