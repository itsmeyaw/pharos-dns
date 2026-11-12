#![cfg(feature = "plugin-dnssec")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

#[tokio::test]
async fn apex_dnskey_without_do_is_authoritative() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text = format!("miek.nl {{\n dnssec {{\n key file {base}\n }}\n}}");
    let chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let domain: Name = "miek.nl.".parse().unwrap();
    let name = NameRef::parse(domain.as_wire(), 0).unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0x100).unwrap();
    builder.question(name, Type::DNSKEY, Class::IN).unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(chain[0].config.serve(&mut cx).await, Outcome::Response);
    let reply = Message::parse(&response).unwrap();
    assert!(reply.aa());
    assert_eq!(
        reply.answers().map(|rr| rr.rtype).collect::<Vec<_>>(),
        [Type::DNSKEY]
    );
    assert_eq!(reply.answers().next().unwrap().ttl, 3600);
}

#[tokio::test]
async fn split_keys_sign_dnskey_with_ksk_only() {
    let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dnssec/");
    let text = format!(
        "miek.nl {{\n dnssec {{\n key file {directory}Kmiek.nl.+013+59725 {directory}miek-zsk\n }}\n}}"
    );
    let chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let domain: Name = "miek.nl.".parse().unwrap();
    let mut wire = Vec::with_capacity(1232);
    let mut b = MessageBuilder::new(&mut wire, 1232, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(domain.as_wire(), 0).unwrap(),
        Type::DNSKEY,
        Class::IN,
    )
    .unwrap();
    b.record(
        Section::Additional,
        NameRef::parse(&[0], 0).unwrap(),
        Type::OPT,
        Class(1232),
        0x8000,
        &[],
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    assert_eq!(chain[0].config.serve(&mut cx).await, Outcome::Response);
    let reply = Message::parse(cx.response).unwrap();
    let keys: Vec<_> = reply
        .answers()
        .filter(|rr| rr.rtype == Type::DNSKEY)
        .collect();
    assert_eq!(keys.len(), 2);
    let ksk_tag =
        pharos_dnssec::digest::key_tag(keys.iter().find(|rr| rr.rdata[1] == 1).unwrap().rdata)
            .unwrap();
    let tags: Vec<_> = reply
        .answers()
        .filter_map(|rr| match rr.data().unwrap() {
            pharos_proto::Rdata::Rrsig {
                type_covered: Type::DNSKEY,
                key_tag,
                ..
            } => Some(key_tag),
            _ => None,
        })
        .collect();
    assert_eq!(tags, [ksk_tag]);
}

struct Negative;
impl Next for Negative {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut b =
            MessageBuilder::new(cx.response, cx.max_response_size, cx.query.id(), 0x8403).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        let apex = NameRef::parse(cx.domain.as_wire(), 0).unwrap();
        b.record(
            Section::Authority,
            apex,
            Type::SOA,
            Class::IN,
            60,
            &[
                0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5,
            ],
        )
        .unwrap();
        let _ = b.finish();
        Outcome::Response
    }
}

struct Referral(bool);
impl Next for Referral {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut b =
            MessageBuilder::new(cx.response, cx.max_response_size, cx.query.id(), 0x8000).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        b.record(Section::Authority, q.name, Type::NS, Class::IN, 60, &[0])
            .unwrap();
        if self.0 {
            let mut ds = [0; 36];
            ds[..4].copy_from_slice(&[0, 1, 13, 2]);
            b.record(Section::Authority, q.name, Type::DS, Class::IN, 60, &ds)
                .unwrap();
        }
        let _ = b.finish();
        Outcome::Response
    }
}

#[tokio::test]
async fn referral_signs_nsec_but_not_ns() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text = format!("miek.nl {{\n dnssec {{\n key file {base}\n }}\n}}");
    let chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let domain: Name = "miek.nl.".parse().unwrap();
    let name: Name = "child.miek.nl.".parse().unwrap();
    let mut wire = Vec::with_capacity(1232);
    let mut b = MessageBuilder::new(&mut wire, 1232, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    b.record(
        Section::Additional,
        NameRef::parse(&[0], 0).unwrap(),
        Type::OPT,
        Class(1232),
        0x8000,
        &[],
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    for (has_ds, expected) in [(false, Type::NSEC), (true, Type::DS)] {
        assert_eq!(
            chain[0]
                .config
                .dnssec
                .as_ref()
                .unwrap()
                .serve(&mut cx, Referral(has_ds))
                .await,
            Outcome::Response
        );
        let reply = Message::parse(cx.response).unwrap();
        assert_eq!(
            reply
                .authorities()
                .filter(|rr| rr.rtype == Type::NSEC)
                .count(),
            usize::from(!has_ds)
        );
        let covered: Vec<_> = reply
            .authorities()
            .filter_map(|rr| match rr.data().unwrap() {
                pharos_proto::Rdata::Rrsig { type_covered, .. } => Some(type_covered),
                _ => None,
            })
            .collect();
        assert_eq!(covered, [expected]);
    }
}

#[tokio::test]
async fn nxdomain_gets_signed_black_lie_and_nodata_rcode() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text = format!("miek.nl {{\n dnssec {{\n key file {base}\n }}\n}}");
    let chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let domain: Name = "miek.nl.".parse().unwrap();
    let name: Name = "missing.miek.nl.".parse().unwrap();
    let mut wire = Vec::with_capacity(1232);
    let mut b = MessageBuilder::new(&mut wire, 1232, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(name.as_wire(), 0).unwrap(),
        Type::A,
        Class::IN,
    )
    .unwrap();
    b.record(
        Section::Additional,
        NameRef::parse(&[0], 0).unwrap(),
        Type::OPT,
        Class(1232),
        0x8000,
        &[],
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    assert_eq!(
        chain[0]
            .config
            .dnssec
            .as_ref()
            .unwrap()
            .serve(&mut cx, Negative)
            .await,
        Outcome::Response
    );
    let reply = Message::parse(cx.response).unwrap();
    assert_eq!(reply.rcode(), pharos_proto::Rcode::NOERROR);
    assert_eq!(
        reply
            .authorities()
            .filter(|rr| rr.rtype == Type::NSEC)
            .count(),
        1
    );
    assert_eq!(
        reply
            .authorities()
            .filter(|rr| rr.rtype == Type::RRSIG)
            .count(),
        2
    );
}

#[cfg(feature = "plugin-whoami")]
#[tokio::test]
async fn do_query_signs_whoami_records_and_reuses_signatures() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text = format!("miek.nl {{\n dnssec {{\n key file {base}\n }}\n whoami\n}}");
    let chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let domain: Name = "miek.nl.".parse().unwrap();
    let name: Name = "www.miek.nl.".parse().unwrap();
    let name = NameRef::parse(name.as_wire(), 0).unwrap();
    let root = NameRef::parse(&[0], 0).unwrap();
    let mut wire = Vec::with_capacity(1232);
    let mut builder = MessageBuilder::new(&mut wire, 1232, 1, 0x100).unwrap();
    builder.question(name, Type::A, Class::IN).unwrap();
    builder
        .record(
            Section::Additional,
            root,
            Type::OPT,
            Class(1232),
            0x8000,
            &[],
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(1232);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 1232,
    };
    assert_eq!(chain[0].config.serve(&mut cx).await, Outcome::Response);
    let reply = Message::parse(cx.response).unwrap();
    let signatures = reply
        .additionals()
        .filter(|rr| rr.rtype == Type::RRSIG)
        .count();
    assert_eq!(signatures, 2);
    let first = cx.response.clone();
    assert_eq!(chain[0].config.serve(&mut cx).await, Outcome::Response);
    assert_eq!(*cx.response, first);
}
