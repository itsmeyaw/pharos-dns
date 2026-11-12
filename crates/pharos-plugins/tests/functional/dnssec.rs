#![cfg(feature = "plugin-dnssec")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

fn verify_signatures(records: &[pharos_proto::Record<'_>]) {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    use pharos_dnssec::canonical::{CanonicalRecord, signed_data};
    use pharos_proto::Rdata;

    let key = pharos_dnssec::keys::parse_dnskey(include_str!(
        "../fixtures/dnssec/Kmiek.nl.+013+59725.key"
    ))
    .unwrap();
    let mut point = vec![4];
    point.extend_from_slice(&key.public_key);
    let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point);
    let mut checked = 0;
    for rr in records.iter().filter(|rr| rr.rtype == Type::RRSIG) {
        let sig = rr.data().unwrap();
        let Rdata::Rrsig {
            type_covered,
            algorithm,
            signature,
            ..
        } = sig
        else {
            unreachable!()
        };
        assert_eq!(algorithm, 13);
        let set: Vec<_> = records
            .iter()
            .filter(|r| r.name == rr.name && r.rtype == type_covered && r.class == rr.class)
            .map(|r| CanonicalRecord {
                owner: r.name,
                class: r.class,
                data: r.data().unwrap(),
            })
            .collect();
        let mut data = signed_data(&sig, &set).unwrap();
        verifier.verify(&data, signature).unwrap();
        data[0] ^= 1;
        assert!(verifier.verify(&data, signature).is_err());
        checked += 1;
    }
    assert!(checked > 0);
}

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

// CoreDNS plugin/dnssec/dnskey.go: the intercepted DNSKEY signature uses TTL 3600.
#[tokio::test]
async fn apex_dnskey_signature_ttl_is_independent_of_key_ttl() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/miek-ttl7200"
    );
    let text = format!("miek.nl {{\n dnssec {{\n key file {base}\n }}\n}}");
    let chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let domain: Name = "miek.nl.".parse().unwrap();
    let name = NameRef::parse(domain.as_wire(), 0).unwrap();
    let mut wire = Vec::with_capacity(1232);
    let mut builder = MessageBuilder::new(&mut wire, 1232, 1, 0x100).unwrap();
    builder.question(name, Type::DNSKEY, Class::IN).unwrap();
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
    let records: Vec<_> = reply.answers().collect();
    assert_eq!(
        records
            .iter()
            .find(|rr| rr.rtype == Type::DNSKEY)
            .unwrap()
            .ttl,
        7200
    );
    assert_eq!(
        records
            .iter()
            .find(|rr| rr.rtype == Type::RRSIG)
            .unwrap()
            .ttl,
        3600
    );
    verify_signatures(&records);
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
    verify_signatures(&reply.answers().collect::<Vec<_>>());
}

struct Negative(bool);
impl Next for Negative {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let mut b = MessageBuilder::new(
            cx.response,
            cx.max_response_size,
            cx.query.id(),
            if self.0 { 0x8403 } else { 0x8400 },
        )
        .unwrap();
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

// CoreDNS v1.15.0 plugin/dnssec/dnssec.go: NSEC queries move only the final two records.
#[tokio::test]
async fn negative_nsec_returns_last_two_records_for_any_key_count() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let domain: Name = "miek.nl.".parse().unwrap();
    let name: Name = "missing.miek.nl.".parse().unwrap();
    let mut wire = Vec::with_capacity(1232);
    let mut builder = MessageBuilder::new(&mut wire, 1232, 1, 0x100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::NSEC,
            Class::IN,
        )
        .unwrap();
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
    for keys in [
        String::new(),
        format!("key file {base}"),
        format!("key file {base} {base}"),
    ] {
        let text = format!("miek.nl {{\n dnssec {{\n {keys}\n }}\n}}");
        let chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
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
                .serve(&mut cx, Negative(true))
                .await,
            Outcome::Response
        );
        let reply = Message::parse(cx.response).unwrap();
        assert_eq!(reply.authority_count(), 0);
        let types: Vec<_> = reply.answers().map(|rr| rr.rtype).collect();
        assert_eq!(
            types,
            if keys.is_empty() {
                vec![Type::SOA, Type::NSEC]
            } else {
                vec![Type::RRSIG, Type::NSEC]
            },
            "{keys}"
        );
        if !keys.is_empty() {
            verify_signatures(&reply.answers().collect::<Vec<_>>());
        }
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
        verify_signatures(&reply.authorities().collect::<Vec<_>>());
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
    for nxdomain in [true, false] {
        assert_eq!(
            chain[0]
                .config
                .dnssec
                .as_ref()
                .unwrap()
                .serve(&mut cx, Negative(nxdomain))
                .await,
            Outcome::Response
        );
        let reply = Message::parse(cx.response).unwrap();
        verify_signatures(&reply.authorities().collect::<Vec<_>>());
        assert_eq!(reply.rcode(), pharos_proto::Rcode::NOERROR);
        assert!(
            reply
                .authorities()
                .filter(|rr| rr.rtype == Type::RRSIG)
                .all(|rr| rr.ttl == 60)
        );
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
    cx.query = cx.query.with_question_type(Type::NSEC);
    assert_eq!(
        chain[0]
            .config
            .dnssec
            .as_ref()
            .unwrap()
            .serve(&mut cx, Negative(true))
            .await,
        Outcome::Response
    );
    let reply = Message::parse(cx.response).unwrap();
    assert_eq!(reply.authority_count(), 0);
    assert_eq!(
        reply.answers().filter(|rr| rr.rtype == Type::NSEC).count(),
        1
    );
    verify_signatures(&reply.answers().collect::<Vec<_>>());
}

#[tokio::test]
async fn signing_rejects_undersized_udp_response_buffer() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text = format!("miek.nl {{\n dnssec {{\n key file {base}\n }}\n}}");
    let chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let domain: Name = "miek.nl.".parse().unwrap();
    let mut wire = Vec::with_capacity(1232);
    let mut b = MessageBuilder::new(&mut wire, 1232, 1, 0x100).unwrap();
    b.question(
        NameRef::parse(domain.as_wire(), 0).unwrap(),
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
        max_response_size: 1232,
    };
    assert_eq!(
        chain[0]
            .config
            .dnssec
            .as_ref()
            .unwrap()
            .serve(&mut cx, Negative(true))
            .await,
        Outcome::Error(pharos_server::Error::ResponseBufferTooSmall)
    );
}

#[cfg(feature = "plugin-whoami")]
#[tokio::test]
async fn do_query_signs_whoami_records_and_reuses_signatures() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let zsk = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/miek-zsk"
    );
    let text = format!("miek.nl {{\n dnssec {{\n key file {base} {zsk}\n }}\n whoami\n}}");
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
    verify_signatures(&reply.additionals().collect::<Vec<_>>());
    let signatures = reply
        .additionals()
        .filter(|rr| rr.rtype == Type::RRSIG)
        .count();
    assert_eq!(signatures, 2);
    let zsk =
        pharos_dnssec::keys::parse_dnskey(include_str!("../fixtures/dnssec/miek-zsk.key")).unwrap();
    let mut rdata = zsk.flags.to_be_bytes().to_vec();
    rdata.extend_from_slice(&[zsk.protocol, zsk.algorithm]);
    rdata.extend_from_slice(&zsk.public_key);
    let tag = pharos_dnssec::digest::key_tag(&rdata).unwrap();
    assert!(reply.additionals().filter(|rr| rr.rtype == Type::RRSIG).all(|rr| matches!(rr.data().unwrap(), pharos_proto::Rdata::Rrsig { key_tag, .. } if key_tag == tag)));
    let first = cx.response.clone();
    assert_eq!(chain[0].config.serve(&mut cx).await, Outcome::Response);
    assert_eq!(*cx.response, first);
}

#[cfg(feature = "plugin-whoami")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_cache_misses_produce_valid_signatures() {
    use std::sync::Arc;

    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text = format!("miek.nl {{\n dnssec {{\n key file {base}\n }}\n whoami\n}}");
    let mut configured =
        configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let chain = Arc::new(configured.remove(0).config);
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let chain = Arc::clone(&chain);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            let wire = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\x01\x03www\x04miek\x02nl\0\0\x01\0\x01\0\0\x29\x04\xd0\0\0\x80\0\0\0";
            let domain: Name = "miek.nl.".parse().unwrap();
            let mut response = Vec::with_capacity(1232);
            let mut slots = [];
            let mut cx = Context { query: Message::parse(wire).unwrap(), client: "127.0.0.1:1".parse().unwrap(), local: "127.0.0.1:53".parse().unwrap(), transport: Transport::Dns, protocol: Protocol::Udp, domain: &domain, metadata: Metadata::new(&mut slots), response: &mut response, max_response_size: 1232 };
            barrier.wait().await;
            assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
            response
        }));
    }
    for task in tasks {
        let response = task.await.unwrap();
        let message = Message::parse(&response).unwrap();
        verify_signatures(&message.additionals().collect::<Vec<_>>());
    }
}
