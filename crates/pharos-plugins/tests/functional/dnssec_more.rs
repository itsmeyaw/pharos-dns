#![cfg(feature = "plugin-dnssec")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, dnssec::Dnssec};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

const KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
);
const OTHER_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/dnssec/miek-ed25519-ksk"
);

fn plugin(zones: &str, keys: &str) -> Dnssec {
    let text = format!("miek.nl {{\n dnssec {zones} {{\n key file {keys}\n }}\n}}");
    let mut chain = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    chain[0].config.dnssec.take().unwrap()
}

// RFC 6891 §6.1.3: DO is carried in the OPT flags, not the DNS header.
fn query(name: &str, qtype: Type, id: u16, opt: Option<bool>) -> Vec<u8> {
    let name: Name = name.parse().unwrap();
    let mut wire = Vec::with_capacity(4096);
    let mut builder = MessageBuilder::new(&mut wire, 4096, id, 0x100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
        .unwrap();
    if let Some(do_bit) = opt {
        builder
            .record(
                Section::Additional,
                NameRef::parse(&[0], 0).unwrap(),
                Type::OPT,
                Class(4096),
                if do_bit { 0x8000 } else { 0 },
                &[],
            )
            .unwrap();
    }
    let _ = builder.finish();
    wire
}

#[derive(Clone, Copy)]
enum Reply {
    Negative { nxdomain: bool, extra: bool },
    Positive(Type),
    MixedCase,
    MixedTtl,
    Large,
}

impl Next for Reply {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        let q = cx.query.questions().next().unwrap();
        let flags = if matches!(self, Self::Negative { nxdomain: true, .. }) {
            0x8403
        } else {
            0x8400
        };
        let mut b =
            MessageBuilder::new(cx.response, cx.max_response_size, cx.query.id(), flags).unwrap();
        b.question(q.name, q.qtype, q.qclass).unwrap();
        match self {
            Self::Negative { extra, .. } => {
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
                if extra {
                    b.record(Section::Authority, apex, Type::NS, Class::IN, 1800, &[0])
                        .unwrap();
                }
            }
            Self::Positive(rtype) => {
                let ds = [
                    0, 1, 13, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ];
                let data: &[u8] = match rtype {
                    Type::DS => &ds,
                    Type::TXT => b"\x08response",
                    Type::DNSKEY => &[1, 1, 3, 13, 1, 2, 3, 4],
                    _ => &[127, 0, 0, 1],
                };
                b.record(Section::Answer, q.name, rtype, Class::IN, 1800, data)
                    .unwrap();
                if rtype == Type::DS {
                    b.record(
                        Section::Authority,
                        NameRef::parse(cx.domain.as_wire(), 0).unwrap(),
                        Type::NS,
                        Class::IN,
                        1800,
                        &[0],
                    )
                    .unwrap();
                }
            }
            Self::MixedCase => {
                let other: Name = "wWw.MiEk.nL.".parse().unwrap();
                for (name, data) in [
                    (q.name, [192, 0, 2, 1]),
                    (NameRef::parse(other.as_wire(), 0).unwrap(), [192, 0, 2, 2]),
                ] {
                    b.record(Section::Answer, name, Type::A, Class::IN, 1800, &data)
                        .unwrap();
                }
            }
            Self::MixedTtl => {
                let other: Name = "wWw.MiEk.nL.".parse().unwrap();
                for (name, ttl, data) in [
                    (q.name, 240, [192, 0, 2, 1]),
                    (
                        NameRef::parse(other.as_wire(), 0).unwrap(),
                        60,
                        [192, 0, 2, 2],
                    ),
                    (q.name, 3600, [192, 0, 2, 3]),
                ] {
                    b.record(Section::Answer, name, Type::A, Class::IN, ttl, &data)
                        .unwrap();
                }
                b.record(
                    Section::Answer,
                    q.name,
                    Type::TXT,
                    Class::IN,
                    480,
                    b"\x04test",
                )
                .unwrap();
            }
            Self::Large => {
                for i in 0..27 {
                    assert!(
                        b.record(
                            Section::Answer,
                            q.name,
                            Type::A,
                            Class::IN,
                            1800,
                            &[192, 0, 2, i]
                        )
                        .unwrap()
                    );
                }
            }
        }
        let _ = b.finish();
        Outcome::Response
    }
}

async fn serve(
    plugin: &Dnssec,
    wire: &[u8],
    reply: Reply,
    protocol: Protocol,
    limit: usize,
    capacity: usize,
) -> (Outcome, Vec<u8>) {
    let domain: Name = "miek.nl.".parse().unwrap();
    let mut response = Vec::with_capacity(capacity);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: limit,
    };
    let outcome = plugin.serve(&mut cx, reply).await;
    (outcome, response)
}

fn covered<'a>(records: impl Iterator<Item = pharos_proto::Record<'a>>) -> Vec<Type> {
    records
        .filter_map(|rr| match rr.data().unwrap() {
            Rdata::Rrsig { type_covered, .. } => Some(type_covered),
            _ => None,
        })
        .collect()
}

// RFC 2181 §5.2: inconsistent TTLs in an RRset are reduced to the lowest value.
#[tokio::test]
async fn signed_rrsets_use_the_lowest_ttl_for_records_and_signatures() {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    use pharos_dnssec::canonical::{CanonicalRecord, signed_data};

    let dnssec = plugin("miek.nl", KEY);
    let q = query("www.miek.nl.", Type::A, 1, Some(true));
    let (outcome, wire) = serve(&dnssec, &q, Reply::MixedTtl, Protocol::Udp, 4096, 4096).await;
    assert_eq!(outcome, Outcome::Response);
    let msg = Message::parse(&wire).unwrap();
    let records: Vec<_> = msg.answers().collect();
    assert_eq!(
        records
            .iter()
            .filter(|rr| rr.rtype == Type::A)
            .map(|rr| rr.ttl)
            .collect::<Vec<_>>(),
        [60, 60, 60]
    );
    assert_eq!(
        records.iter().find(|rr| rr.rtype == Type::TXT).unwrap().ttl,
        480
    );
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
            original_ttl,
            signature,
            ..
        } = sig
        else {
            unreachable!()
        };
        let expected = if type_covered == Type::A { 60 } else { 480 };
        assert_eq!((rr.ttl, original_ttl), (expected, expected));
        let set: Vec<_> = records
            .iter()
            .filter(|r| r.rtype == type_covered)
            .map(|r| CanonicalRecord {
                owner: r.name,
                class: r.class,
                data: r.data().unwrap(),
            })
            .collect();
        verifier
            .verify(&signed_data(&sig, &set).unwrap(), signature)
            .unwrap();
        checked += 1;
    }
    assert_eq!(checked, 2);
}

// RFC 2181 §5.2: DNSKEYs at the same Apex share their lowest TTL, even without DO.
#[tokio::test]
async fn apex_dnskeys_use_the_lowest_ttl_with_and_without_do() {
    let long_key = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/miek-ttl7200"
    );
    let dnssec = plugin("miek.nl", &format!("{long_key} {OTHER_KEY}"));
    for opt in [Some(false), Some(true)] {
        let q = query("miek.nl.", Type::DNSKEY, 1, opt);
        let (outcome, wire) = serve(
            &dnssec,
            &q,
            Reply::Positive(Type::A),
            Protocol::Udp,
            4096,
            4096,
        )
        .await;
        assert_eq!(outcome, Outcome::Response);
        let msg = Message::parse(&wire).unwrap();
        let records: Vec<_> = msg.answers().collect();
        assert_eq!(
            records
                .iter()
                .filter(|rr| rr.rtype == Type::DNSKEY)
                .map(|rr| rr.ttl)
                .collect::<Vec<_>>(),
            [3600, 3600]
        );
        for rr in records.iter().filter(|rr| rr.rtype == Type::RRSIG) {
            assert_eq!(rr.ttl, 3600);
            assert!(matches!(
                rr.data().unwrap(),
                Rdata::Rrsig {
                    original_ttl: 3600,
                    ..
                }
            ));
        }
    }
}

// CoreDNS v1.15.0 plugin/dnssec/handler.go: requests without DO bypass signing.
#[tokio::test]
async fn negative_without_do_passes_through_with_or_without_opt() {
    let dnssec = plugin("miek.nl", KEY);
    for nxdomain in [false, true] {
        for opt in [None, Some(false)] {
            let q = query("missing.miek.nl.", Type::A, 1, opt);
            let (outcome, wire) = serve(
                &dnssec,
                &q,
                Reply::Negative {
                    nxdomain,
                    extra: false,
                },
                Protocol::Udp,
                4096,
                4096,
            )
            .await;
            assert_eq!(outcome, Outcome::Response);
            let msg = Message::parse(&wire).unwrap();
            assert_eq!(
                msg.rcode(),
                if nxdomain {
                    Rcode::NXDOMAIN
                } else {
                    Rcode::NOERROR
                }
            );
            assert_eq!(
                msg.authorities().map(|rr| rr.rtype).collect::<Vec<_>>(),
                [Type::SOA]
            );
            assert_eq!(msg.answer_count(), 0);
        }
    }
}

// RFC 4035 §3.1.1: only an Apex DNSKEY query is intercepted.
#[tokio::test]
async fn non_apex_dnskey_and_out_of_zone_do_pass_through() {
    let dnssec = plugin("miek.nl", KEY);
    for (name, qtype) in [
        ("child.miek.nl.", Type::DNSKEY),
        ("www.example.org.", Type::A),
    ] {
        let q = query(name, qtype, 1, Some(true));
        let (outcome, wire) = serve(
            &dnssec,
            &q,
            Reply::Positive(qtype),
            Protocol::Udp,
            4096,
            4096,
        )
        .await;
        assert_eq!(outcome, Outcome::Response);
        let msg = Message::parse(&wire).unwrap();
        assert_eq!(msg.answers().next().unwrap().rtype, qtype);
        assert_eq!(
            msg.answer_count(),
            if qtype == Type::DNSKEY { 2 } else { 1 }
        );
        assert_eq!(
            covered(msg.answers()),
            if qtype == Type::DNSKEY {
                vec![Type::DNSKEY]
            } else {
                vec![]
            }
        );
    }
}

// CoreDNS v1.15.0 plugin/dnssec/dnssec.go: negative Responses require exactly one SOA.
async fn multiple_authorities_pass_through(nxdomain: bool) {
    let dnssec = plugin("miek.nl", KEY);
    let q = query("missing.miek.nl.", Type::A, 1, Some(true));
    let (outcome, wire) = serve(
        &dnssec,
        &q,
        Reply::Negative {
            nxdomain,
            extra: true,
        },
        Protocol::Udp,
        4096,
        4096,
    )
    .await;
    assert_eq!(outcome, Outcome::Response);
    let msg = Message::parse(&wire).unwrap();
    assert_eq!(
        msg.rcode(),
        if nxdomain {
            Rcode::NXDOMAIN
        } else {
            Rcode::NOERROR
        }
    );
    assert_eq!(
        msg.authorities().map(|rr| rr.rtype).collect::<Vec<_>>(),
        [Type::SOA, Type::NS]
    );
}

#[tokio::test]
async fn nodata_with_multiple_authority_records_passes_through() {
    multiple_authorities_pass_through(false).await;
}

#[tokio::test]
async fn nxdomain_with_multiple_authority_records_passes_through() {
    multiple_authorities_pass_through(true).await;
}

// CoreDNS v1.15.0 plugin/dnssec/handler_test.go: positive DS and authority NS are signed.
#[tokio::test]
async fn positive_ds_is_signed_without_synthetic_nsec() {
    let dnssec = plugin("miek.nl", KEY);
    let q = query("deleg.miek.nl.", Type::DS, 1, Some(true));
    let (outcome, wire) = serve(
        &dnssec,
        &q,
        Reply::Positive(Type::DS),
        Protocol::Udp,
        4096,
        4096,
    )
    .await;
    assert_eq!(outcome, Outcome::Response);
    let msg = Message::parse(&wire).unwrap();
    assert_eq!(covered(msg.answers()), [Type::DS]);
    assert_eq!(covered(msg.authorities()), [Type::NS]);
    assert!(
        !msg.answers()
            .chain(msg.authorities())
            .any(|rr| rr.rtype == Type::NSEC)
    );
}

// CoreDNS v1.15.0 plugin/dnssec/black_lies_test.go TestBlackLiesNoError.
#[tokio::test]
async fn positive_txt_has_no_synthetic_nsec() {
    let dnssec = plugin("miek.nl", KEY);
    let q = query("www.miek.nl.", Type::TXT, 1, Some(true));
    let (outcome, wire) = serve(
        &dnssec,
        &q,
        Reply::Positive(Type::TXT),
        Protocol::Udp,
        4096,
        4096,
    )
    .await;
    assert_eq!(outcome, Outcome::Response);
    let msg = Message::parse(&wire).unwrap();
    assert_eq!(
        msg.answers().map(|rr| rr.rtype).collect::<Vec<_>>(),
        [Type::TXT, Type::RRSIG]
    );
    assert_eq!(msg.authority_count(), 0);
}

// CoreDNS v1.15.0 plugin/dnssec/dnssec_test.go TestZoneSigningDouble.
#[tokio::test]
async fn two_non_split_keys_sign_each_rrset() {
    let dnssec = plugin("miek.nl", &format!("{KEY} {OTHER_KEY}"));
    let q = query("deleg.miek.nl.", Type::DS, 1, Some(true));
    let (outcome, wire) = serve(
        &dnssec,
        &q,
        Reply::Positive(Type::DS),
        Protocol::Udp,
        4096,
        4096,
    )
    .await;
    assert_eq!(outcome, Outcome::Response);
    let msg = Message::parse(&wire).unwrap();
    assert_eq!(covered(msg.answers()), [Type::DS, Type::DS]);
    assert_eq!(covered(msg.authorities()), [Type::NS, Type::NS]);
    let mut algorithms: Vec<_> = msg
        .answers()
        .filter_map(|rr| match rr.data().unwrap() {
            Rdata::Rrsig { algorithm, .. } => Some(algorithm),
            _ => None,
        })
        .collect();
    algorithms.sort();
    assert_eq!(algorithms, [13, 15]);
}

// RFC 4343 §3 and RFC 2181 §5: owner names differing only in ASCII case form one RRset.
#[tokio::test]
async fn mixed_case_owners_form_one_signed_rrset() {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    use pharos_dnssec::canonical::{CanonicalRecord, signed_data};

    let dnssec = plugin("miek.nl", KEY);
    let q = query("www.miek.nl.", Type::A, 1, Some(true));
    let (outcome, wire) = serve(&dnssec, &q, Reply::MixedCase, Protocol::Udp, 4096, 4096).await;
    assert_eq!(outcome, Outcome::Response);
    let msg = Message::parse(&wire).unwrap();
    let records: Vec<_> = msg.answers().filter(|rr| rr.rtype == Type::A).collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].name.to_string(), "www.miek.nl.");
    assert_eq!(records[1].name.to_string(), "wWw.MiEk.nL.");
    assert_eq!(covered(msg.answers()), [Type::A]);
    let signature = msg.answers().find(|rr| rr.rtype == Type::RRSIG).unwrap();
    let sig = signature.data().unwrap();
    let Rdata::Rrsig { signature, .. } = sig else {
        unreachable!()
    };
    let set: Vec<_> = records
        .iter()
        .map(|rr| CanonicalRecord {
            owner: rr.name,
            class: rr.class,
            data: rr.data().unwrap(),
        })
        .collect();
    let key = pharos_dnssec::keys::parse_dnskey(include_str!(
        "../fixtures/dnssec/Kmiek.nl.+013+59725.key"
    ))
    .unwrap();
    let mut point = vec![4];
    point.extend_from_slice(&key.public_key);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
        .verify(&signed_data(&sig, &set).unwrap(), signature)
        .unwrap();
}

// RFC 4343 §2: DNS name matching is case-insensitive; select the longest matching zone.
#[tokio::test]
async fn nested_zone_selection_is_case_insensitive() {
    let dnssec = plugin("miek.nl sub.miek.nl", KEY);
    for (name, expected) in [
        ("WWW.SuB.MiEk.Nl.", "sub.miek.nl."),
        ("WWW.MiEk.Nl.", "miek.nl."),
    ] {
        let q = query(name, Type::A, 1, Some(true));
        let (outcome, wire) = serve(
            &dnssec,
            &q,
            Reply::Positive(Type::A),
            Protocol::Udp,
            4096,
            4096,
        )
        .await;
        assert_eq!(outcome, Outcome::Response);
        let msg = Message::parse(&wire).unwrap();
        let signer = msg
            .answers()
            .find_map(|rr| match rr.data().unwrap() {
                Rdata::Rrsig { signer, .. } => Some(signer.to_string()),
                _ => None,
            })
            .unwrap();
        assert_eq!(signer, expected);
    }
}

// RFC 1035 §4.1.1: a Response repeats the Query's ID even when signatures are cached.
#[tokio::test]
async fn cached_signature_reuses_data_but_not_query_id() {
    let dnssec = plugin("miek.nl", KEY);
    let mut responses = Vec::new();
    for id in [0x1234, 0x5678] {
        let q = query("www.miek.nl.", Type::A, id, Some(true));
        let (outcome, wire) = serve(
            &dnssec,
            &q,
            Reply::Positive(Type::A),
            Protocol::Udp,
            4096,
            4096,
        )
        .await;
        assert_eq!(outcome, Outcome::Response);
        let msg = Message::parse(&wire).unwrap();
        assert_eq!(msg.id(), id);
        assert_eq!(covered(msg.answers()), [Type::A]);
        responses.push(wire);
    }
    assert_eq!(&responses[0][2..], &responses[1][2..]);
}

// CoreDNS v1.15.0 plugin/dnssec/black_lies_test.go TestZoneSigningBlackLies.
#[tokio::test]
async fn nxdomain_synthesizes_expected_nsec_owner_and_next() {
    let dnssec = plugin("miek.nl", KEY);
    let q = query("ww.miek.nl.", Type::TXT, 1, Some(true));
    let (outcome, wire) = serve(
        &dnssec,
        &q,
        Reply::Negative {
            nxdomain: true,
            extra: false,
        },
        Protocol::Udp,
        4096,
        4096,
    )
    .await;
    assert_eq!(outcome, Outcome::Response);
    let msg = Message::parse(&wire).unwrap();
    assert_eq!(msg.rcode(), Rcode::NOERROR);
    let rr = msg.authorities().find(|rr| rr.rtype == Type::NSEC).unwrap();
    assert_eq!(rr.name.to_string(), "ww.miek.nl.");
    let Rdata::Nsec { next, .. } = rr.data().unwrap() else {
        panic!("expected NSEC")
    };
    let expected: Name = "\\000.ww.miek.nl.".parse().unwrap();
    assert_eq!(next, NameRef::parse(expected.as_wire(), 0).unwrap());
    let mut sigs = covered(msg.authorities());
    sigs.sort();
    let mut expected = [Type::SOA, Type::NSEC];
    expected.sort();
    assert_eq!(sigs, expected);
}

// RFC 1035 §4.1.1: TC marks a truncated but complete DNS Message.
#[tokio::test]
async fn udp_truncation_remains_parseable_on_repeat() {
    let dnssec = plugin("miek.nl", KEY);
    let q = query("www.miek.nl.", Type::A, 1, Some(true));
    for _ in 0..2 {
        let (outcome, wire) = serve(&dnssec, &q, Reply::Large, Protocol::Udp, 512, 512).await;
        assert_eq!(outcome, Outcome::Response);
        assert!(wire.len() <= 512);
        let msg = Message::parse(&wire).unwrap();
        assert!(msg.tc());
        assert_eq!(msg.questions().count(), 1);
        assert_eq!(msg.answers().count(), msg.answer_count() as usize);
    }
}

// RFC 7766 §8: DNS over TCP supports Messages larger than the UDP minimum.
#[tokio::test]
async fn tcp_dnskey_response_grows_small_buffer() {
    let dnssec = plugin("miek.nl", &format!("{KEY} {OTHER_KEY}"));
    let q = query("miek.nl.", Type::DNSKEY, 1, Some(true));
    let (outcome, wire) = serve(
        &dnssec,
        &q,
        Reply::Positive(Type::A),
        Protocol::Tcp,
        4096,
        1,
    )
    .await;
    assert_eq!(outcome, Outcome::Response);
    let msg = Message::parse(&wire).unwrap();
    assert!(!msg.tc());
    assert_eq!(
        msg.answers().filter(|rr| rr.rtype == Type::DNSKEY).count(),
        2
    );
    assert_eq!(covered(msg.answers()), [Type::DNSKEY, Type::DNSKEY]);
}
