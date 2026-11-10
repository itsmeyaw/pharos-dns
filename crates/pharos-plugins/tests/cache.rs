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

impl Next for Backend<'_> {
    async fn run(self, cx: &mut Context<'_>) -> Outcome {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let question = cx.query.questions().next().unwrap();
        let flags = 0x8080 | self.rcode | u16::from(self.truncated) * 0x0200;
        let mut builder = MessageBuilder::new(cx.response, 512, cx.query.id(), flags).unwrap();
        builder
            .question(question.name, question.qtype, question.qclass)
            .unwrap();
        if self.rcode == 3 {
            // SOA with root MNAME/RNAME and MINIMUM 30.
            builder
                .record(
                    Section::Authority,
                    question.name,
                    Type::SOA,
                    Class::IN,
                    30,
                    b"\0\0\0\0\0\x01\0\0\0\x02\0\0\0\x03\0\0\0\x04\0\0\0\x1e",
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
        let _ = builder.finish();
        Outcome::Response
    }
}

fn cache() -> Chain {
    let blocks = parse("Corefile", ".:0 {\n cache\n}").unwrap();
    configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config
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
