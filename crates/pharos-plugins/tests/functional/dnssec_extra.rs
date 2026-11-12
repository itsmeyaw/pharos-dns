#![cfg(feature = "plugin-dnssec")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

// Behavioral cases derived from CoreDNS v1.15.0 plugin/dnssec tests.
enum Downstream {
    Alias(&'static str),
    Dname,
    Negative(bool),
    Referral(bool),
}

impl Next for Downstream {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let flags = match self {
            Self::Negative(true) => 0x8403,
            Self::Referral(_) => 0x8000,
            _ => 0x8400,
        };
        let mut b =
            MessageBuilder::new(cx.response, cx.max_response_size, cx.query.id(), flags).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        match self {
            Self::Alias(target) => {
                let target: Name = target.parse().unwrap();
                b.record(
                    Section::Answer,
                    q.name,
                    Type::CNAME,
                    Class::IN,
                    1800,
                    target.as_wire(),
                )
                .unwrap();
                b.record(
                    Section::Answer,
                    NameRef::parse(target.as_wire(), 0).unwrap(),
                    Type::A,
                    Class::IN,
                    1800,
                    &[127, 0, 0, 1],
                )
                .unwrap();
            }
            Self::Dname => {
                let owner: Name = "dname.miek.nl.".parse().unwrap();
                let target: Name = "test.miek.nl.".parse().unwrap();
                let synthesized: Name = "a.test.miek.nl.".parse().unwrap();
                b.record(
                    Section::Answer,
                    q.name,
                    Type::CNAME,
                    Class::IN,
                    1800,
                    synthesized.as_wire(),
                )
                .unwrap();
                b.record(
                    Section::Answer,
                    NameRef::parse(synthesized.as_wire(), 0).unwrap(),
                    Type::A,
                    Class::IN,
                    1800,
                    &[127, 0, 0, 1],
                )
                .unwrap();
                b.record(
                    Section::Answer,
                    NameRef::parse(owner.as_wire(), 0).unwrap(),
                    Type::DNAME,
                    Class::IN,
                    1800,
                    target.as_wire(),
                )
                .unwrap();
            }
            Self::Negative(_) => {
                let apex = NameRef::parse(cx.domain.as_wire(), 0).unwrap();
                b.record(
                    Section::Authority,
                    apex,
                    Type::SOA,
                    Class::IN,
                    1800,
                    &[
                        0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5,
                    ],
                )
                .unwrap();
            }
            Self::Referral(has_ds) => {
                b.record(Section::Authority, q.name, Type::NS, Class::IN, 1800, &[0])
                    .unwrap();
                if has_ds {
                    let mut ds = [0; 36];
                    ds[..4].copy_from_slice(&[0, 1, 13, 2]);
                    b.record(Section::Authority, q.name, Type::DS, Class::IN, 1800, &ds)
                        .unwrap();
                }
                b.record(
                    Section::Additional,
                    q.name,
                    Type::A,
                    Class::IN,
                    1800,
                    &[192, 0, 2, 1],
                )
                .unwrap();
            }
        }
        let _ = b.finish();
        Outcome::Response
    }
}

async fn query(name: &str, qtype: Type, downstream: Downstream) -> Vec<u8> {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    let text = format!("miek.nl {{\n dnssec miek.nl example.org {{\n key file {base}\n }}\n}}");
    let chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let domain: Name = "miek.nl.".parse().unwrap();
    let name: Name = name.parse().unwrap();
    let mut wire = Vec::with_capacity(4096);
    let mut b = MessageBuilder::new(&mut wire, 4096, 1, 0x100).unwrap();
    b.question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
        .unwrap();
    b.record(
        Section::Additional,
        NameRef::parse(&[0], 0).unwrap(),
        Type::OPT,
        Class(4096),
        0x8000,
        &[],
    )
    .unwrap();
    let _ = b.finish();
    let mut response = Vec::with_capacity(4096);
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
        max_response_size: 4096,
    };
    assert_eq!(
        chain[0]
            .config
            .dnssec
            .as_ref()
            .unwrap()
            .serve(&mut cx, downstream)
            .await,
        Outcome::Response
    );
    response
}

fn signatures(records: &[pharos_proto::Record<'_>]) -> Vec<(Type, String)> {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    use pharos_dnssec::canonical::{CanonicalRecord, signed_data};

    let key = pharos_dnssec::keys::parse_dnskey(include_str!(
        "../fixtures/dnssec/Kmiek.nl.+013+59725.key"
    ))
    .unwrap();
    let mut point = vec![4];
    point.extend_from_slice(&key.public_key);
    let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point);
    records
        .iter()
        .filter_map(|rr| {
            let sig = rr.data().unwrap();
            let Rdata::Rrsig {
                type_covered,
                signer,
                signature,
                ..
            } = sig
            else {
                return None;
            };
            let set: Vec<_> = records
                .iter()
                .filter(|r| r.name == rr.name && r.rtype == type_covered && r.class == rr.class)
                .map(|r| CanonicalRecord {
                    owner: r.name,
                    class: r.class,
                    data: r.data().unwrap(),
                })
                .collect();
            verifier
                .verify(&signed_data(&sig, &set).unwrap(), signature)
                .unwrap();
            Some((type_covered, signer.to_string()))
        })
        .collect()
}

// RFC 4034 §4.1.2: NSEC type bitmaps contain windows of network-order bits.
fn has_type(bitmap: &[u8], rtype: Type) -> bool {
    let mut windows = bitmap;
    while !windows.is_empty() {
        let window = windows[0] as u16;
        let len = windows[1] as usize;
        let bits = &windows[2..2 + len];
        if window == rtype.0 / 256 {
            let offset = (rtype.0 % 256) as usize;
            return bits
                .get(offset / 8)
                .is_some_and(|byte| byte & (0x80 >> (offset % 8)) != 0);
        }
        windows = &windows[2 + len..];
    }
    false
}

#[tokio::test]
async fn cname_signs_only_owners_in_configured_zones() {
    for (target, expected) in [
        (
            "target.invalid.",
            vec![(Type::CNAME, "miek.nl.".to_string())],
        ),
        (
            "db.example.org.",
            vec![
                (Type::CNAME, "miek.nl.".to_string()),
                (Type::A, "example.org.".to_string()),
            ],
        ),
    ] {
        let wire = query("www.miek.nl.", Type::A, Downstream::Alias(target)).await;
        let msg = Message::parse(&wire).unwrap();
        let mut actual = signatures(&msg.answers().collect::<Vec<_>>());
        actual.sort();
        let mut expected = expected;
        expected.sort();
        assert_eq!(actual, expected, "{target}");
    }
}

#[tokio::test]
async fn dname_and_synthesized_cname_are_signed() {
    let wire = query("a.dname.miek.nl.", Type::A, Downstream::Dname).await;
    let msg = Message::parse(&wire).unwrap();
    let mut actual = signatures(&msg.answers().collect::<Vec<_>>());
    actual.sort();
    let mut expected = [Type::CNAME, Type::A, Type::DNAME].map(|t| (t, "miek.nl.".to_string()));
    expected.sort();
    assert_eq!(actual, expected);
}

#[tokio::test]
async fn black_lie_nsec_queries_have_apex_and_non_apex_bitmaps() {
    for (name, apex) in [("miek.nl.", true), ("www.miek.nl.", false)] {
        let wire = query(name, Type::NSEC, Downstream::Negative(true)).await;
        let msg = Message::parse(&wire).unwrap();
        assert_eq!(msg.rcode(), Rcode::NOERROR);
        assert_eq!(msg.authority_count(), 0);
        let answers = msg.answers().collect::<Vec<_>>();
        assert_eq!(signatures(&answers), [(Type::NSEC, "miek.nl.".to_string())]);
        let nsec = answers.iter().find(|rr| rr.rtype == Type::NSEC).unwrap();
        let expected_owner: Name = name.parse().unwrap();
        assert_eq!(
            nsec.name,
            NameRef::parse(expected_owner.as_wire(), 0).unwrap()
        );
        let Rdata::Nsec { next, bitmap } = nsec.data().unwrap() else {
            panic!("expected NSEC")
        };
        let mut next_wire = vec![1, 0];
        next_wire.extend_from_slice(expected_owner.as_wire());
        assert_eq!(next, NameRef::parse(&next_wire, 0).unwrap());
        assert!(has_type(bitmap, Type::NSEC));
        assert!(has_type(bitmap, Type::RRSIG));
        assert_eq!(has_type(bitmap, Type::SOA), apex);
    }
}

#[tokio::test]
async fn black_lie_ds_bitmaps_distinguish_apex_and_delegation() {
    for (name, apex) in [("miek.nl.", true), ("sub.miek.nl.", false)] {
        let wire = query(name, Type::DS, Downstream::Negative(true)).await;
        let msg = Message::parse(&wire).unwrap();
        assert_eq!(msg.rcode(), Rcode::NOERROR);
        let records = msg.authorities().collect::<Vec<_>>();
        let mut sigs = signatures(&records);
        sigs.sort();
        let mut expected = [
            (Type::SOA, "miek.nl.".to_string()),
            (Type::NSEC, "miek.nl.".to_string()),
        ];
        expected.sort();
        assert_eq!(sigs, expected);
        let nsec = records.iter().find(|rr| rr.rtype == Type::NSEC).unwrap();
        let Rdata::Nsec { bitmap, .. } = nsec.data().unwrap() else {
            panic!("expected NSEC")
        };
        for t in [Type::NS, Type::NSEC, Type::RRSIG] {
            assert!(has_type(bitmap, t), "{name}: {t:?}");
        }
        assert_eq!(has_type(bitmap, Type::SOA), apex);
        assert!(!has_type(bitmap, Type::DS));
    }
}

#[tokio::test]
async fn black_lie_excludes_missing_tlsa_for_nodata_and_nxdomain() {
    for nxdomain in [false, true] {
        let wire = query(
            "25._tcp.miek.nl.",
            Type::TLSA,
            Downstream::Negative(nxdomain),
        )
        .await;
        let msg = Message::parse(&wire).unwrap();
        assert_eq!(msg.rcode(), Rcode::NOERROR);
        let records = msg.authorities().collect::<Vec<_>>();
        assert_eq!(signatures(&records).len(), 2);
        let nsec = records.iter().find(|rr| rr.rtype == Type::NSEC).unwrap();
        let Rdata::Nsec { bitmap, .. } = nsec.data().unwrap() else {
            panic!("expected NSEC")
        };
        assert!(!has_type(bitmap, Type::TLSA));
        assert!(has_type(bitmap, Type::NSEC));
        assert!(has_type(bitmap, Type::RRSIG));
    }
}

#[tokio::test]
async fn referral_nsec_bitmap_and_glue_signing() {
    for has_ds in [false, true] {
        let wire = query("sub.miek.nl.", Type::NS, Downstream::Referral(has_ds)).await;
        let msg = Message::parse(&wire).unwrap();
        let records = msg.authorities().collect::<Vec<_>>();
        assert_eq!(
            signatures(&records),
            [(
                if has_ds { Type::DS } else { Type::NSEC },
                "miek.nl.".to_string()
            )]
        );
        assert!(signatures(&msg.additionals().collect::<Vec<_>>()).is_empty());
        if !has_ds {
            let nsec = records.iter().find(|rr| rr.rtype == Type::NSEC).unwrap();
            let Rdata::Nsec { bitmap, .. } = nsec.data().unwrap() else {
                panic!("expected NSEC")
            };
            for t in [Type::NS, Type::NSEC, Type::RRSIG] {
                assert!(has_type(bitmap, t));
            }
            assert!(!has_type(bitmap, Type::SOA));
            assert!(!has_type(bitmap, Type::DS));
        }
    }
}
