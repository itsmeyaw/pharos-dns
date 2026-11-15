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
mod tests {
    use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Section, Type};
    use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

    struct QueryDnskeyReply;

    impl Next for QueryDnskeyReply {
        async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
            let question = cx.query.questions().next().unwrap();
            let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8400).unwrap();
            builder
                .question(question.name, question.qtype, question.qclass)
                .unwrap();
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::DNSKEY,
                    question.qclass,
                    300,
                    &[0, 1, 3, 13, 1],
                )
                .unwrap();
            let _ = builder.finish();
            Outcome::Response
        }
    }

    #[test]
    fn explicit_nxname_query_gets_formerr() {
        let domain: Name = "example.org.".parse().unwrap();
        let name = NameRef::parse(domain.as_wire(), 0).unwrap();
        let mut query = Vec::new();
        let mut builder = MessageBuilder::new(&mut query, 512, 7, 0x0110).unwrap();
        builder.question(name, Type::NXNAME, Class::IN).unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        super::nxname_formerr(&mut cx).unwrap();
        let reply = Message::parse(cx.response).unwrap();
        assert_eq!(reply.rcode(), Rcode::FORMERR);
        assert_eq!(reply.id(), 7);
        assert_eq!(reply.flags() & 0x0010, 0);
        assert_eq!(reply.answers().count(), 0);
    }

    // RFC 1035 §3.2.5: Explicit QCLASS CH must not receive an IN DNSKEY RRset.
    #[tokio::test]
    async fn non_in_dnskey_query_passes_through_without_in_records() {
        let key = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
        );
        let corefile = format!("miek.nl {{\n dnssec {{\n key file {key}\n }}\n}}");
        let mut chain = pharos_corefile::configure::<crate::Chain>(
            &pharos_corefile::parse("Corefile", &corefile).unwrap(),
            crate::directives(),
        )
        .unwrap();
        let dnssec = chain[0].config.dnssec.take().unwrap();

        let domain: Name = "miek.nl.".parse().unwrap();
        let name = NameRef::parse(domain.as_wire(), 0).unwrap();
        let mut query = Vec::new();
        let mut builder = MessageBuilder::new(&mut query, 512, 9, 0x0100).unwrap();
        builder.question(name, Type::DNSKEY, Class::CH).unwrap();
        builder
            .record(
                Section::Additional,
                NameRef::parse(&[0], 0).unwrap(),
                Type::OPT,
                Class(1232),
                0x8000,
                &[],
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };

        assert_eq!(
            dnssec.serve(&mut cx, QueryDnskeyReply).await,
            Outcome::Response
        );
        let reply = Message::parse(cx.response).unwrap();
        let answers: Vec<_> = reply.answers().collect();
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].class, Class::CH);
        assert!(!answers.iter().any(|rr| rr.rtype == Type::RRSIG));
    }

    // RFC 1035 §3.2.3: QCLASS=ANY selects DNSKEY data in any class.
    #[tokio::test]
    async fn qclass_any_dnskey_intercepts_signed_zone_key() {
        let key = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
        );
        let corefile = format!("miek.nl {{\n dnssec {{\n key file {key}\n }}\n}}");
        let mut chain = pharos_corefile::configure::<crate::Chain>(
            &pharos_corefile::parse("Corefile", &corefile).unwrap(),
            crate::directives(),
        )
        .unwrap();
        let dnssec = chain[0].config.dnssec.take().unwrap();

        let domain: Name = "miek.nl.".parse().unwrap();
        let name = NameRef::parse(domain.as_wire(), 0).unwrap();
        let mut query = Vec::new();
        let mut builder = MessageBuilder::new(&mut query, 512, 10, 0x0100).unwrap();
        builder.question(name, Type::DNSKEY, Class::ANY).unwrap();
        builder
            .record(
                Section::Additional,
                NameRef::parse(&[0], 0).unwrap(),
                Type::OPT,
                Class(1232),
                0x8000,
                &[],
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&query).unwrap(),
            client: "127.0.0.1:1".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };

        assert_eq!(
            dnssec.serve(&mut cx, QueryDnskeyReply).await,
            Outcome::Response
        );
        let reply = Message::parse(cx.response).unwrap();
        assert!(
            reply
                .answers()
                .any(|rr| rr.rtype == Type::DNSKEY && rr.class == Class::IN)
        );
        assert!(
            reply
                .answers()
                .any(|rr| rr.rtype == Type::RRSIG && rr.class == Class::IN)
        );
    }
}
