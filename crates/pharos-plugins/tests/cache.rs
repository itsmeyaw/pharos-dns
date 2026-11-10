#![forbid(unsafe_code)]
#![cfg(feature = "plugin-cache")]
#![recursion_limit = "512"]

use std::sync::atomic::{AtomicUsize, Ordering};

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, Section, Type};
use pharos_server::{Context, Metadata, Next, Outcome, Plugin, Protocol, Transport};

struct Backend<'a> {
    calls: &'a AtomicUsize,
    rcode: u16,
    truncated: bool,
}

struct Unanswered<'a>(&'a AtomicUsize);
impl Next for Unanswered<'_> {
    async fn run(self, _: &mut Context<'_>) -> Outcome {
        self.0.fetch_add(1, Ordering::Relaxed);
        Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL)
    }
}

struct AuthenticatedBackend<'a>(&'a AtomicUsize);
impl Next for AuthenticatedBackend<'_> {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
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
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let flags = 0x80a0 | self.rcode | u16::from(self.truncated) * 0x0200;
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), flags).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        if self.rcode == 3 {
            // SOA with root MNAME/RNAME and MINIMUM 3.
            builder
                .record(
                    Section::Authority,
                    question.name,
                    Type::SOA,
                    Class::IN,
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
                    Class::IN,
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
#[ignore = "downstream Query AD is not set during cache refresh"]
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
async fn caches_servfail_and_can_disable_it() {
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let _ = query(&chain, wire, &calls, 2, false).await;
    let hit = query(&chain, wire, &calls, 2, false).await;
    assert_eq!(Message::parse(&hit).unwrap().rcode().0, 2);
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let chain = cache_with("cache {\n servfail 0\n}");
    let calls = AtomicUsize::new(0);
    let _ = query(&chain, wire, &calls, 2, false).await;
    let _ = query(&chain, wire, &calls, 2, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
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
async fn incomplete_positive_without_soa_is_not_cached() {
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x1c\0\x01";
    let chain = cache();
    let calls = AtomicUsize::new(0);
    let _ = query(&chain, wire, &calls, 0, false).await;
    let _ = query(&chain, wire, &calls, 0, false).await;
    assert_eq!(calls.load(Ordering::Relaxed), 2);
}

async fn query(
    chain: &Chain,
    wire: &[u8],
    calls: &AtomicUsize,
    rcode: u16,
    truncated: bool,
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
                    truncated
                }
            )
            .await,
        Outcome::Response
    );
    response
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
