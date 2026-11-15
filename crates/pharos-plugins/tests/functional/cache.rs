#![forbid(unsafe_code)]
#![cfg(feature = "plugin-cache")]

use std::sync::atomic::{AtomicUsize, Ordering};

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

struct Backend<'a> {
    calls: &'a AtomicUsize,
    rcode: u16,
    truncated: bool,
    cname: bool,
}

struct PolicyResponse<'a> {
    calls: &'a AtomicUsize,
    authoritative: bool,
    cname: bool,
    mixed_ttl: bool,
    unrelated_answer: bool,
    unrelated_authority: bool,
    additional_rrset: bool,
}

impl Next for PolicyResponse<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let target: Name = "target.example.".parse().unwrap();
        let unrelated: Name = "unrelated.other.".parse().unwrap();
        let flags = 0x8080 | (u16::from(self.authoritative) * 0x0400);
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), flags).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        if self.cname {
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::CNAME,
                    question.qclass,
                    30,
                    target.as_wire(),
                )
                .unwrap();
            builder
                .record(
                    Section::Answer,
                    target.as_name_ref(),
                    Type::A,
                    question.qclass,
                    10,
                    &[192, 0, 2, 1],
                )
                .unwrap();
        } else {
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::A,
                    question.qclass,
                    30,
                    &[192, 0, 2, 1],
                )
                .unwrap();
            if self.mixed_ttl {
                builder
                    .record(
                        Section::Answer,
                        question.name,
                        Type::A,
                        question.qclass,
                        10,
                        &[192, 0, 2, 2],
                    )
                    .unwrap();
            }
        }
        if self.unrelated_answer {
            builder
                .record(
                    Section::Answer,
                    unrelated.as_name_ref(),
                    Type::A,
                    question.qclass,
                    30,
                    &[192, 0, 2, 3],
                )
                .unwrap();
        }
        if self.unrelated_authority {
            builder
                .record(
                    Section::Authority,
                    unrelated.as_name_ref(),
                    Type::SOA,
                    question.qclass,
                    30,
                    b"\0\0\0\0\0\x01\0\0\0\x02\0\0\0\x03\0\0\0\x04\0\0\0\x03",
                )
                .unwrap();
        }
        if self.additional_rrset {
            builder
                .record(
                    Section::Additional,
                    unrelated.as_name_ref(),
                    Type::A,
                    question.qclass,
                    30,
                    &[192, 0, 2, 3],
                )
                .unwrap();
            builder
                .record(
                    Section::Additional,
                    unrelated.as_name_ref(),
                    Type::A,
                    question.qclass,
                    10,
                    &[192, 0, 2, 4],
                )
                .unwrap();
        }
        let _ = builder.finish();
        Outcome::Response
    }
}

struct Nsec3Negative<'a> {
    calls: &'a AtomicUsize,
    rcode: u16,
}

impl Next for Nsec3Negative<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let zone: Name = "example.com.".parse().unwrap();
        let owner: Name = "00000000000000000000000000.example.com.".parse().unwrap();
        let mut nsec3 = vec![1, 0, 0, 0, 0, 20];
        nsec3.extend([1; 20]);
        nsec3.extend([0, 1, 0x40]);
        let mut builder =
            MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8080 | self.rcode).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Authority,
                zone.as_name_ref(),
                Type::SOA,
                question.qclass,
                30,
                b"\0\0\0\0\0\x01\0\0\0\x02\0\0\0\x03\0\0\0\x04\0\0\0\x03",
            )
            .unwrap();
        builder
            .record(
                Section::Authority,
                owner.as_name_ref(),
                Type::NSEC3,
                question.qclass,
                30,
                &nsec3,
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

struct SiblingNsecNegative<'a>(&'a AtomicUsize);

impl Next for SiblingNsecNegative<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let zone: Name = "example.com.".parse().unwrap();
        let owner: Name = "a.example.com.".parse().unwrap();
        let next_owner: Name = "z.example.com.".parse().unwrap();
        let mut nsec = next_owner.as_wire().to_vec();
        nsec.extend_from_slice(&[0, 1, 0x40]);
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8083).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Authority,
                zone.as_name_ref(),
                Type::SOA,
                question.qclass,
                30,
                b"\0\0\0\0\0\x01\0\0\0\x02\0\0\0\x03\0\0\0\x04\0\0\0\x03",
            )
            .unwrap();
        builder
            .record(
                Section::Authority,
                owner.as_name_ref(),
                Type::NSEC,
                question.qclass,
                30,
                &nsec,
            )
            .unwrap();
        builder
            .record(
                Section::Authority,
                zone.as_name_ref(),
                Type::RRSIG,
                question.qclass,
                30,
                &rrsig(Type::SOA),
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

struct SignedReferral<'a>(&'a AtomicUsize);

impl Next for SignedReferral<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let owner: Name = "child.example.com.".parse().unwrap();
        let nameserver: Name = "ns.child.example.com.".parse().unwrap();
        let next_owner: Name = "z.example.com.".parse().unwrap();
        let mut nsec = next_owner.as_wire().to_vec();
        nsec.extend_from_slice(&[0, 6, 0x20, 0, 0, 0, 0, 0x13]);
        let mut ds = vec![0, 1, 8, 2];
        ds.extend([0x11; 32]);
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8080).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Authority,
                owner.as_name_ref(),
                Type::NS,
                Class::IN,
                30,
                nameserver.as_wire(),
            )
            .unwrap();
        builder
            .record(
                Section::Authority,
                owner.as_name_ref(),
                Type::DS,
                Class::IN,
                30,
                &ds,
            )
            .unwrap();
        builder
            .record(
                Section::Authority,
                owner.as_name_ref(),
                Type::NSEC,
                Class::IN,
                10,
                &nsec,
            )
            .unwrap();
        builder
            .record(
                Section::Authority,
                owner.as_name_ref(),
                Type::RRSIG,
                Class::IN,
                30,
                &rrsig(Type::DS),
            )
            .unwrap();
        builder
            .record(
                Section::Authority,
                owner.as_name_ref(),
                Type::RRSIG,
                Class::IN,
                10,
                &rrsig(Type::NSEC),
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

fn rrsig(type_covered: Type) -> Vec<u8> {
    let mut data = Vec::with_capacity(20);
    data.extend_from_slice(&type_covered.0.to_be_bytes());
    data.extend_from_slice(&[8, 0]);
    data.extend_from_slice(&30_u32.to_be_bytes());
    data.extend_from_slice(&3_000_000_000_u32.to_be_bytes());
    data.extend_from_slice(&1_000_000_000_u32.to_be_bytes());
    data.extend_from_slice(&1_u16.to_be_bytes());
    data.extend_from_slice(b"\x07example\x03com\0\x01");
    data
}

struct DnameResponse<'a>(&'a AtomicUsize);

impl Next for DnameResponse<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let owner: Name = "example.com.".parse().unwrap();
        let target: Name = "target.net.".parse().unwrap();
        let alias: Name = "a.target.net.".parse().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8080).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Answer,
                owner.as_name_ref(),
                Type::DNAME,
                question.qclass,
                30,
                target.as_wire(),
            )
            .unwrap();
        builder
            .record(
                Section::Answer,
                question.name,
                Type::CNAME,
                question.qclass,
                30,
                alias.as_wire(),
            )
            .unwrap();
        builder
            .record(
                Section::Answer,
                alias.as_name_ref(),
                Type::A,
                question.qclass,
                20,
                &[192, 0, 2, 1],
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

struct ManyRrsets<'a> {
    calls: &'a AtomicUsize,
    count: u16,
}

impl Next for ManyRrsets<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 65535, cx.query.id(), 0x8080).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        for offset in 0..self.count {
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type(1000 + offset),
                    question.qclass,
                    30,
                    &[],
                )
                .unwrap();
        }
        let _ = builder.finish();
        Outcome::Response
    }
}

struct Unanswered<'a>(&'a AtomicUsize);
impl Next for Unanswered<'_> {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL)
    }
}

struct EmptyNoData<'a>(&'a AtomicUsize);
impl Next for EmptyNoData<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8080).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

struct Referral<'a>(&'a AtomicUsize);
impl Next for Referral<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let root = pharos_proto::NameRef::parse(&[0], 0).unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8080).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Authority,
                root,
                Type::NS,
                Class::IN,
                1,
                b"\x02ns\0",
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

struct EcsResponse<'a>(&'a AtomicUsize);
impl Next for EcsResponse<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let root = pharos_proto::NameRef::parse(&[0], 0).unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8080).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Answer,
                question.name,
                Type::A,
                Class::IN,
                30,
                &[192, 0, 2, 1],
            )
            .unwrap();
        builder
            .record(
                Section::Additional,
                root,
                Type::OPT,
                Class(1232),
                0,
                &[0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2],
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

struct TkeyResponse<'a>(&'a AtomicUsize);
impl Next for TkeyResponse<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let root = pharos_proto::NameRef::parse(&[0], 0).unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8080).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Answer,
                question.name,
                Type::A,
                Class::IN,
                30,
                &[192, 0, 2, 1],
            )
            .unwrap();
        builder
            .record(Section::Additional, root, Type::TKEY, Class::IN, 30, &[])
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

struct Pending;
impl Next for Pending {
    async fn run(self, _: &mut Context<'_, '_>) -> Outcome {
        std::future::pending().await
    }
}

struct SignedBackend<'a>(&'a AtomicUsize);
impl Next for SignedBackend<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        let q = cx.query.questions().next().unwrap();
        let root = pharos_proto::NameRef::parse(&[0], 0).unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x80a0).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        builder
            .record(
                Section::Answer,
                q.name,
                Type::A,
                Class::IN,
                30,
                &[192, 0, 2, 1],
            )
            .unwrap();
        builder
            .record(Section::Additional, root, Type::TSIG, Class::ANY, 0, &[])
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

struct ExpiredSignature<'a>(&'a AtomicUsize);
impl Next for ExpiredSignature<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        let q = cx.query.questions().next().unwrap();
        let root = pharos_proto::NameRef::parse(&[0], 0).unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8080).unwrap();
        builder.question(q.name, q.qtype, q.qclass).unwrap();
        builder
            .record(
                Section::Answer,
                q.name,
                Type::A,
                q.qclass,
                30,
                &[192, 0, 2, 1],
            )
            .unwrap();
        builder
            .record(
                Section::Answer,
                q.name,
                Type::RRSIG,
                q.qclass,
                30,
                b"\0\x01\x08\0\0\0\0\x1e\0\0\0\x02\0\0\0\x01\0\x01\0",
            )
            .unwrap();
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
        Outcome::Response
    }
}

struct ZeroTtlExpiredSignature<'a>(&'a AtomicUsize);
impl Next for ZeroTtlExpiredSignature<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), 0x8080).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Answer,
                question.name,
                Type::A,
                Class::IN,
                0,
                &[192, 0, 2, 1],
            )
            .unwrap();
        builder
            .record(
                Section::Answer,
                question.name,
                Type::RRSIG,
                Class::IN,
                0,
                b"\0\x01\x08\0\0\0\0\x1e\0\0\0\x02\0\0\0\x01\0\x01\0",
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

struct AuthenticatedBackend<'a>(&'a AtomicUsize);
impl Next for AuthenticatedBackend<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let mut flags = 0x8080;
        if cx.query.ad() {
            flags |= 0x20;
        }
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), flags).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        builder
            .record(
                Section::Answer,
                question.name,
                Type::A,
                Class::IN,
                30,
                &[192, 0, 2, 1],
            )
            .unwrap();
        let _ = builder.finish();
        Outcome::Response
    }
}

impl Next for Backend<'_> {
    async fn run(self, cx: &mut Context<'_, '_>) -> Outcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if cx.query.additionals().any(|rr| rr.rtype == Type::TSIG) {
            assert!(!cx.query.ad());
            assert_eq!(
                cx.query.flags(),
                u16::from_be_bytes([cx.query.as_wire()[2], cx.query.as_wire()[3]])
            );
        }
        let question = cx.query.questions().next().unwrap();
        let flags = 0x80a0 | self.rcode | (u16::from(self.truncated) * 0x0200);
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), flags).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        if self.rcode == 3 {
            if self.cname {
                let target: Name = "missing.example.net.".parse().unwrap();
                builder
                    .record(
                        Section::Answer,
                        question.name,
                        Type::CNAME,
                        question.qclass,
                        30,
                        target.as_wire(),
                    )
                    .unwrap();
            }
            // SOA with root MNAME/RNAME and MINIMUM 3.
            builder
                .record(
                    Section::Authority,
                    question.name,
                    Type::SOA,
                    question.qclass,
                    30,
                    b"\0\0\0\0\0\x01\0\0\0\x02\0\0\0\x03\0\0\0\x04\0\0\0\x03",
                )
                .unwrap();
        } else {
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::A,
                    question.qclass,
                    30,
                    &[192, 0, 2, 1],
                )
                .unwrap();
        }
        if cx.query.opt().is_some() {
            let root = pharos_proto::NameRef::parse(&[0], 0).unwrap();
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
        }
        let _ = builder.finish();
        Outcome::Response
    }
}

fn cache() -> Chain {
    cache_with("cache")
}

fn cache_with(directive: &str) -> Chain {
    let text = format!(".:0 {{\n {directive}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config
}

fn query_wire(qtype: Type, name: &[u8], ecs: bool) -> Vec<u8> {
    let mut wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0".to_vec();
    wire.extend_from_slice(name);
    wire.extend_from_slice(&qtype.0.to_be_bytes());
    wire.extend_from_slice(&Class::IN.0.to_be_bytes());
    if ecs {
        // RFC 7871 §6: Encode a valid IPv4 /24 ECS option.
        wire[10..12].copy_from_slice(&1_u16.to_be_bytes());
        wire.extend_from_slice(b"\0\0\x29\x04\xd0\0\0\0\0\0\x0b\0\x08\0\x07\0\x01\x18\0\xc0\0\x02");
    }
    wire
}

#[tokio::test]
async fn ad_is_per_request_and_do_and_cd_use_separate_keys() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let base = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let mut wire = base.to_vec();
    let miss = query(&chain, &wire, &calls, 0, false).await;
    assert!(!Message::parse(&miss).unwrap().ad());
    wire[3] |= 0x20;
    let hit = query(&chain, &wire, &calls, 0, false).await;
    assert!(Message::parse(&hit).unwrap().ad());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    wire[3] |= 0x10;
    let cd = query(&chain, &wire, &calls, 0, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert!(Message::parse(&cd).unwrap().ad());
    wire[3] &= !0x10;
    wire[11] = 1;
    wire.extend_from_slice(b"\0\0\x29\x04\xd0\0\0\x80\0\0\0");
    let _ = query(&chain, &wire, &calls, 0, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn query_class_uses_separate_cache_entries() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let mut wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01".to_vec();
    let _ = query(&chain, &wire, &calls, 0, false).await;
    *wire.last_mut().unwrap() = 3;
    let _ = query(&chain, &wire, &calls, 0, false).await;
    *wire.last_mut().unwrap() = 1;
    let _ = query(&chain, &wire, &calls, 0, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn expired_dnssec_signature_is_not_cached() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\x01\x01x\0\0\x01\0\x01\0\0\x29\x04\xd0\0\0\x80\0\0\0";
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    for _ in 0..2 {
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(wire).unwrap(),
            client: "127.0.0.1:1000".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .cache
                .as_ref()
                .unwrap()
                .serve(&mut cx, ExpiredSignature(&calls))
                .await,
            Outcome::Response
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn positive_zero_ttl_floor_cannot_outlive_expired_rrsig() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let query = query_wire(Type::A, b"\x01x\0", false);
    for _ in 0..2 {
        let (outcome, response) = query_with(&chain, &query, ZeroTtlExpiredSignature(&calls)).await;
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(
            Message::parse(&response)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .ttl,
            0
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn cache_removes_upstream_opt_on_miss_and_hit() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\x01\x01x\0\0\x01\0\x01\0\0\x29\x04\xd0\0\0\x80\0\0\0";
    for _ in 0..2 {
        let response = query(&chain, wire, &calls, 0, false).await;
        assert!(Message::parse(&response).unwrap().opt().is_none());
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn miss_requests_authenticated_upstream_data_for_later_ad_clients() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let mut wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01".to_vec();
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    for ad in [false, true] {
        if ad {
            wire[3] |= 0x20;
        }
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1000".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .cache
                .as_ref()
                .unwrap()
                .serve(&mut cx, AuthenticatedBackend(&calls))
                .await,
            Outcome::Response
        );
        assert_eq!(Message::parse(cx.response).unwrap().ad(), ad);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "plugin-forward")]
#[tokio::test]
async fn authenticated_refresh_sets_ad_on_forwarded_wire() {
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut wire = [0_u8; 512];
        let (len, peer) = upstream.recv_from(&mut wire).await.unwrap();
        assert!(Message::parse(&wire[..len]).unwrap().ad());
        let mut response = wire[..len].to_vec();
        response[2] |= 0x80;
        response[3] |= 0x20;
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        // RFC 2308 §5: Use a positive answer so this test exercises a cacheable response.
        response.splice(
            19..19,
            [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 1],
        );
        upstream.send_to(&response, peer).await.unwrap();
    });
    let text = format!(".:0 {{\n cache\n forward . {address}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let domain: Name = ".".parse().unwrap();
    let mut wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\x01\x01x\0\0\x01\0\x01\0\0\x29\x04\xd0\0\0\0\0\0\x06\xfd\xe9\0\x02\xc0\x01".to_vec();
    let mut response = Vec::with_capacity(65535);
    for ad in [false, true] {
        if ad {
            wire[3] |= 0x20;
        }
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1000".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(2), chain.serve(&mut cx))
                .await
                .unwrap(),
            Outcome::Response
        );
        assert_eq!(Message::parse(cx.response).unwrap().ad(), ad);
        assert_eq!(cx.query.ad(), ad, "the client Query must be restored");
    }
    task.await.unwrap();
}

#[cfg(feature = "plugin-forward")]
#[tokio::test]
async fn compressed_query_survives_ad_refresh() {
    let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut wire = [0_u8; 512];
        let (len, peer) = upstream.recv_from(&mut wire).await.unwrap();
        assert!(!Message::parse(&wire[..len]).unwrap().ad());
        wire[2] |= 0x80;
        upstream.send_to(&wire[..len], peer).await.unwrap();
    });
    let text = format!(".:0 {{\n cache\n forward . {address}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    let chain = configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config;
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\xc0\x03\0\x01\0\x01";
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1000".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(chain.serve(&mut cx).await, Outcome::Response);
    task.await.unwrap();
}

#[tokio::test]
async fn opaque_label_bytes_do_not_prevent_authenticated_caching() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x02\xc0\x03\0\0\x01\0\x01";
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    for _ in 0..2 {
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(wire).unwrap(),
            client: "127.0.0.1:1000".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .cache
                .as_ref()
                .unwrap()
                .serve(&mut cx, AuthenticatedBackend(&calls))
                .await,
            Outcome::Response
        );
        assert!(!Message::parse(cx.response).unwrap().ad());
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn cancellation_restores_the_client_query() {
    let chain = cache();
    let domain: Name = ".".parse().unwrap();
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1000".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            chain.cache.as_ref().unwrap().serve(&mut cx, Pending)
        )
        .await
        .is_err()
    );
    assert!(!cx.query.ad());
}

#[tokio::test]
async fn tsig_queries_bypass_cache_without_modification() {
    let mut wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\x01\x01x\0\0\x01\0\x01".to_vec();
    wire.extend_from_slice(b"\0\0\xfa\0\xff\0\0\0\0\0\0");
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let _ = query(&chain, &wire, &calls, 0, false).await;
    let _ = query(&chain, &wire, &calls, 0, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn tsig_responses_are_not_cached_or_rewritten() {
    let chain = cache_with("cache 1");
    let calls = AtomicUsize::new(0);
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    for _ in 0..2 {
        let mut slots = [];
        let mut cx = Context {
            query: Message::parse(wire).unwrap(),
            client: "127.0.0.1:1000".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        assert_eq!(
            chain
                .cache
                .as_ref()
                .unwrap()
                .serve(&mut cx, SignedBackend(&calls))
                .await,
            Outcome::Response
        );
        let message = Message::parse(cx.response).unwrap();
        assert!(message.ad());
        assert_eq!(message.answers().next().unwrap().ttl, 30);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn disabled_domain_bypasses_only_selected_response_class() {
    let chain = cache_with("cache {\n disable success x.\n}");
    let calls = AtomicUsize::new(0);
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let _ = query(&chain, wire, &calls, 0, false).await;
    let _ = query(&chain, wire, &calls, 0, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    let _ = query(&chain, wire, &calls, 3, false).await;
    let _ = query(&chain, wire, &calls, 3, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn keepttl_retains_the_inserted_ttl() {
    let chain = cache_with("cache {\n keepttl\n}");
    let calls = AtomicUsize::new(0);
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let _ = query(&chain, wire, &calls, 0, false).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let hit = query(&chain, wire, &calls, 0, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        Message::parse(&hit).unwrap().answers().next().unwrap().ttl,
        30
    );
}

#[tokio::test]
async fn servfail_zero_is_cached() {
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let chain = cache_with("cache {\n servfail 0\n}");
    let calls = AtomicUsize::new(0);
    let _ = query(&chain, wire, &calls, 2, false).await;
    let _ = query(&chain, wire, &calls, 2, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn caches_refused_with_failure_ttl() {
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let chain = cache();
    let calls = AtomicUsize::new(0);
    for _ in 0..2 {
        let response = query(&chain, wire, &calls, 5, false).await;
        assert_eq!(
            Message::parse(&response)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .ttl,
            5
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn caches_unanswered_servfail() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1000".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let plugin = chain.cache.as_ref().unwrap();
    assert_eq!(
        plugin.serve(&mut cx, Unanswered(&calls)).await,
        Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL)
    );
    assert_eq!(
        plugin.serve(&mut cx, Unanswered(&calls)).await,
        Outcome::Response
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(Message::parse(cx.response).unwrap().rcode().0, 2);
}

#[tokio::test]
async fn ttl_caps_and_negative_soa_minimum_apply_on_miss_and_hit() {
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let chain = cache_with("cache {\n success 1024 7 0\n denial 1024 30 0\n}");
    let calls = AtomicUsize::new(0);
    for _ in 0..2 {
        let response = query(&chain, wire, &calls, 0, false).await;
        assert_eq!(
            Message::parse(&response)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .ttl,
            7
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let chain = cache_with("cache {\n denial 1024 30 0\n}");
    let calls = AtomicUsize::new(0);
    for _ in 0..2 {
        let response = query(&chain, wire, &calls, 3, false).await;
        assert_eq!(
            Message::parse(&response)
                .unwrap()
                .authorities()
                .next()
                .unwrap()
                .ttl,
            3
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn denial_minimum_does_not_raise_negative_soa_ttl() {
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let chain = cache_with("cache {\n denial 1024 30 5\n}");
    let calls = AtomicUsize::new(0);
    let response = query(&chain, wire, &calls, 3, false).await;
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .authorities()
            .next()
            .unwrap()
            .ttl,
        3
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn incomplete_positive_without_soa_is_not_cached() {
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x1c\0\x01";
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let _ = query(&chain, wire, &calls, 0, false).await;
    let _ = query(&chain, wire, &calls, 0, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn cached_rrsets_keep_their_own_minimum_ttls() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let query = query_wire(Type::A, b"\x01x\0", false);
    let next = || PolicyResponse {
        calls: &calls,
        authoritative: true,
        cname: true,
        mixed_ttl: false,
        unrelated_answer: false,
        unrelated_authority: false,
        additional_rrset: false,
    };

    let _ = query_with(&chain, &query, next()).await;
    let (_, hit) = query_with(&chain, &query, next()).await;
    let hit = Message::parse(&hit).unwrap();
    let mut answers = hit.answers();
    assert_eq!(answers.next().unwrap().ttl, 30);
    assert_eq!(answers.next().unwrap().ttl, 10);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn non_authoritative_rrsets_with_mismatched_ttls_are_not_cached() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let query = query_wire(Type::A, b"\x01x\0", false);
    let next = || PolicyResponse {
        calls: &calls,
        authoritative: false,
        cname: false,
        mixed_ttl: true,
        unrelated_answer: false,
        unrelated_authority: false,
        additional_rrset: false,
    };

    let (_, miss) = query_with(&chain, &query, next()).await;
    assert_eq!(
        Message::parse(&miss)
            .unwrap()
            .answers()
            .map(|record| record.ttl)
            .collect::<Vec<_>>(),
        [10, 10]
    );
    let _ = query_with(&chain, &query, next()).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn authoritative_mixed_ttl_rrset_uses_its_minimum_ttl() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let query = query_wire(Type::A, b"\x01x\0", false);
    let next = || PolicyResponse {
        calls: &calls,
        authoritative: true,
        cname: false,
        mixed_ttl: true,
        unrelated_answer: false,
        unrelated_authority: false,
        additional_rrset: false,
    };

    let _ = query_with(&chain, &query, next()).await;
    let (_, hit) = query_with(&chain, &query, next()).await;
    let answers = Message::parse(&hit).unwrap();
    assert_eq!(
        answers
            .answers()
            .map(|record| record.ttl)
            .collect::<Vec<_>>(),
        [10, 10]
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn response_with_unrelated_answer_records_is_not_cached() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let query = query_wire(Type::A, b"\x01x\0", false);
    let next = || PolicyResponse {
        calls: &calls,
        authoritative: false,
        cname: false,
        mixed_ttl: false,
        unrelated_answer: true,
        unrelated_authority: false,
        additional_rrset: false,
    };

    let _ = query_with(&chain, &query, next()).await;
    let _ = query_with(&chain, &query, next()).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn response_with_out_of_domain_authority_records_is_not_cached() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let query = query_wire(Type::A, b"\x01x\0", false);
    let next = || PolicyResponse {
        calls: &calls,
        authoritative: false,
        cname: false,
        mixed_ttl: false,
        unrelated_answer: false,
        unrelated_authority: true,
        additional_rrset: false,
    };

    let _ = query_with(&chain, &query, next()).await;
    let _ = query_with(&chain, &query, next()).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn additional_rrsets_are_normalized_on_cache_misses() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let query = query_wire(Type::A, b"\x01x\0", false);
    let next = PolicyResponse {
        calls: &calls,
        authoritative: true,
        cname: false,
        mixed_ttl: false,
        unrelated_answer: false,
        unrelated_authority: false,
        additional_rrset: true,
    };

    let (_, wire) = query_with(&chain, &query, next).await;
    assert_eq!(
        Message::parse(&wire)
            .unwrap()
            .additionals()
            .map(|record| record.ttl)
            .collect::<Vec<_>>(),
        [10, 10]
    );
}

#[tokio::test]
async fn nsec3_negative_proofs_are_cached_for_nxdomain_and_nodata() {
    let query = query_wire(Type::A, b"\x07missing\x07example\x03com\0", false);
    for rcode in [3, 0] {
        let chain = cache();
        let calls = AtomicUsize::new(0);
        for _ in 0..2 {
            let (outcome, wire) = query_with(
                &chain,
                &query,
                Nsec3Negative {
                    calls: &calls,
                    rcode,
                },
            )
            .await;
            assert_eq!(outcome, Outcome::Response);
            let response = Message::parse(&wire).unwrap();
            assert_eq!(response.rcode().0, rcode);
            assert_eq!(
                response
                    .authorities()
                    .filter(|record| record.rtype == Type::NSEC3)
                    .count(),
                1
            );
        }
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }
}

#[tokio::test]
async fn nxdomain_sibling_nsec_proof_is_cached_with_bounded_ttls() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let query = query_wire(Type::A, b"\x01b\x07example\x03com\0", false);
    let _ = query_with(&chain, &query, SiblingNsecNegative(&calls)).await;
    let (_, hit) = query_with(&chain, &query, SiblingNsecNegative(&calls)).await;
    let response = Message::parse(&hit).unwrap();
    let negative_ttl = response
        .authorities()
        .find(|record| record.rtype == Type::SOA)
        .unwrap()
        .ttl;
    for record in response.authorities().filter(|record| {
        record.rtype == Type::NSEC
            || (record.rtype == Type::RRSIG
                && matches!(
                    record.data(),
                    Ok(pharos_proto::Rdata::Rrsig {
                        type_covered: Type::SOA,
                        ..
                    })
                ))
    }) {
        assert!(record.ttl <= negative_ttl);
    }
    assert_eq!(negative_ttl, 3);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn referral_keeps_distinct_rrsig_covered_type_ttls() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let query = query_wire(Type::A, b"\x04host\x05child\x07example\x03com\0", false);
    let _ = query_with(&chain, &query, SignedReferral(&calls)).await;
    let (_, hit) = query_with(&chain, &query, SignedReferral(&calls)).await;
    let signatures = Message::parse(&hit)
        .unwrap()
        .authorities()
        .filter(|record| record.rtype == Type::RRSIG)
        .map(|record| record.ttl)
        .collect::<Vec<_>>();
    assert_eq!(signatures, [30, 10]);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn dname_answer_above_the_question_is_cacheable() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let query = query_wire(Type::A, b"\x01a\x07example\x03com\0", false);
    let _ = query_with(&chain, &query, DnameResponse(&calls)).await;
    let (_, hit) = query_with(&chain, &query, DnameResponse(&calls)).await;
    assert!(
        Message::parse(&hit)
            .unwrap()
            .answers()
            .any(|record| record.rtype == Type::DNAME)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn many_distinct_rrsets_are_indexed_and_cached() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let query = query_wire(Type::ANY, b"\x01x\0", false);
    for _ in 0..2 {
        let (outcome, response) = query_with_limit(
            &chain,
            &query,
            ManyRrsets {
                calls: &calls,
                count: 4096,
            },
            65535,
        )
        .await;
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(Message::parse(&response).unwrap().answer_count(), 4096);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

async fn query(
    chain: &Chain,
    wire: &[u8],
    calls: &AtomicUsize,
    rcode: u16,
    truncated: bool,
) -> Vec<u8> {
    query_with_cname(chain, wire, calls, rcode, truncated, false).await
}

async fn query_with_cname(
    chain: &Chain,
    wire: &[u8],
    calls: &AtomicUsize,
    rcode: u16,
    truncated: bool,
    cname: bool,
) -> Vec<u8> {
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1000".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    assert_eq!(
        chain
            .cache
            .as_ref()
            .unwrap()
            .serve(
                &mut cx,
                Backend {
                    calls,
                    rcode,
                    truncated,
                    cname,
                }
            )
            .await,
        Outcome::Response
    );
    response
}

async fn query_with<N: Next + Send>(chain: &Chain, wire: &[u8], next: N) -> (Outcome, Vec<u8>) {
    query_with_limit(chain, wire, next, 512).await
}

async fn query_with_limit<N: Next + Send>(
    chain: &Chain,
    wire: &[u8],
    next: N,
    max_response_size: usize,
) -> (Outcome, Vec<u8>) {
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(max_response_size);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(wire).unwrap(),
        client: "127.0.0.1:1000".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size,
    };
    let outcome = chain.cache.as_ref().unwrap().serve(&mut cx, next).await;
    drop(cx);
    (outcome, response)
}

#[tokio::test]
async fn caches_nxdomain_with_cname_answer() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let first = query_with_cname(&chain, wire, &calls, 3, false, true).await;
    let hit = query_with_cname(&chain, wire, &calls, 3, false, true).await;
    for response in [&first, &hit] {
        let message = Message::parse(response).unwrap();
        assert_eq!(message.rcode().0, 3);
        assert_eq!(
            message
                .answers()
                .filter(|rr| rr.rtype == Type::CNAME)
                .count(),
            1
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn caches_positive_response_and_patches_question_and_id() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let first = b"\x00\x01\x01\x00\0\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";
    let second = b"\x00\x02\x00\x00\0\x01\0\0\0\0\0\0\x03WWW\x07example\x03com\0\0\x01\0\x01";
    let miss = query(&chain, first, &calls, 0, false).await;
    let hit = query(&chain, second, &calls, 0, false).await;
    let (miss, hit) = (
        Message::parse(&miss).unwrap(),
        Message::parse(&hit).unwrap(),
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(hit.id(), 2);
    assert!(!hit.rd());
    assert!(!hit.aa() && hit.ra());
    assert_eq!(
        hit.questions().next().unwrap().name.to_string(),
        "WWW.example.com."
    );
    assert_eq!(hit.answers().next().unwrap().ttl, 30);
    assert_eq!(miss.answers().next().unwrap().ttl, 30);
}

#[tokio::test]
async fn caches_denial_but_not_truncated_response() {
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let _ = query(&chain, wire, &calls, 3, false).await;
    let hit = query(&chain, wire, &calls, 3, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(Message::parse(&hit).unwrap().rcode().0, 3);
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let _ = query(&chain, wire, &calls, 0, true).await;
    let _ = query(&chain, wire, &calls, 0, true).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn nxdomain_for_a_is_reused_for_aaaa() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let a = query_wire(Type::A, b"\x01x\0", false);
    let aaaa = query_wire(Type::AAAA, b"\x01x\0", false);
    let _ = query(&chain, &a, &calls, 3, false).await;
    let hit = query(&chain, &aaaa, &calls, 3, false).await;
    let hit = Message::parse(&hit).unwrap();
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(hit.rcode(), pharos_proto::Rcode::NXDOMAIN);
    assert_eq!(hit.questions().next().unwrap().qtype, Type::AAAA);
}

#[tokio::test]
async fn ecs_queries_and_ecs_responses_are_not_cached() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let ecs_query = query_wire(Type::A, b"\x01x\0", true);
    let _ = query(&chain, &ecs_query, &calls, 0, false).await;
    let _ = query(&chain, &ecs_query, &calls, 0, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);

    let calls = AtomicUsize::new(0);
    let query = query_wire(Type::A, b"\x01x\0", false);
    for _ in 0..2 {
        let (outcome, response) = query_with(&chain, &query, EcsResponse(&calls)).await;
        assert_eq!(outcome, Outcome::Response);
        assert!(
            Message::parse(&response)
                .unwrap()
                .opt()
                .unwrap()
                .options()
                .iter()
                .any(|option| matches!(option, pharos_proto::EdnsOption::ClientSubnet(_)))
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn explicit_wildcard_and_tkey_responses_are_not_cached() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let wildcard = query_wire(Type::A, b"\x01*\x01x\0", false);
    let _ = query(&chain, &wildcard, &calls, 0, false).await;
    let _ = query(&chain, &wildcard, &calls, 0, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);

    let calls = AtomicUsize::new(0);
    let ordinary = query_wire(Type::A, b"\x01x\0", false);
    for _ in 0..2 {
        let (outcome, _) = query_with(&chain, &ordinary, TkeyResponse(&calls)).await;
        assert_eq!(outcome, Outcome::Response);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn referral_lifetime_uses_ns_ttl() {
    let chain = cache_with("cache {\nsuccess 1024 60 0\n}");
    let query = query_wire(Type::A, b"\x01x\0", false);
    let calls = AtomicUsize::new(0);
    let (outcome, response) = query_with(&chain, &query, Referral(&calls)).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .authorities()
            .next()
            .unwrap()
            .ttl,
        1
    );
    let (outcome, response) = query_with(&chain, &query, Referral(&calls)).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(
        Message::parse(&response)
            .unwrap()
            .authorities()
            .next()
            .unwrap()
            .ttl,
        1
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn referral_ttl_uses_positive_minimum_floor() {
    let chain = cache_with("cache {\nsuccess 1024 60 5\n}");
    let query = query_wire(Type::A, b"\x01x\0", false);
    let calls = AtomicUsize::new(0);
    for _ in 0..2 {
        let (outcome, response) = query_with(&chain, &query, Referral(&calls)).await;
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(
            Message::parse(&response)
                .unwrap()
                .authorities()
                .next()
                .unwrap()
                .ttl,
            5
        );
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn soa_less_nodata_is_not_cached() {
    let chain = cache();
    let query = query_wire(Type::A, b"\x01x\0", false);
    let calls = AtomicUsize::new(0);
    for _ in 0..2 {
        let (outcome, response) = query_with(&chain, &query, EmptyNoData(&calls)).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&response).unwrap();
        assert_eq!(response.rcode(), pharos_proto::Rcode::NOERROR);
        assert_eq!(response.answer_count(), 0);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn failure_backoff_and_stale_rejection_work_end_to_end() {
    let chain = cache_with("cache {\nservfail 1s\nserve_stale 10s immediate\n}");
    let query = query_wire(Type::A, b"\x01x\0", false);
    let calls = AtomicUsize::new(0);
    let (outcome, _) = query_with(&chain, &query, Unanswered(&calls)).await;
    assert_eq!(outcome, Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (outcome, _) = query_with(&chain, &query, Unanswered(&calls)).await;
    assert_eq!(outcome, Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL));
    assert_eq!(calls.load(Ordering::Relaxed), 2);

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (outcome, response) = query_with(&chain, &query, Unanswered(&calls)).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(
        Message::parse(&response).unwrap().rcode(),
        pharos_proto::Rcode::SERVFAIL
    );
    assert_eq!(calls.load(Ordering::Relaxed), 2);

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let (outcome, _) = query_with(&chain, &query, Unanswered(&calls)).await;
    assert_eq!(outcome, Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL));
    assert_eq!(calls.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn cached_response_ttl_ages() {
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let _ = query(&chain, wire, &calls, 0, false).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let hit = query(&chain, wire, &calls, 0, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(Message::parse(&hit).unwrap().answers().next().unwrap().ttl < 30);
}
