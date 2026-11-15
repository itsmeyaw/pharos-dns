#![forbid(unsafe_code)]
#![cfg(feature = "plugin-forward")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{
    Class, EdnsOption, Message, MessageBuilder, Name, NameRef, Rcode, Rdata, Section, Type,
};
use pharos_server::{Action, Context, Handler, Metadata, Outcome, Protocol, Transport};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::net::UdpSocket;

const QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";

async fn run(chain: &Chain) -> (Outcome, Vec<u8>, Option<String>) {
    run_query(chain, QUERY).await
}

async fn run_query(chain: &Chain, query: &[u8]) -> (Outcome, Vec<u8>, Option<String>) {
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    let mut slots = [];
    let mut context = Context {
        query: Message::parse(query).unwrap(),
        client: "127.0.0.1:1000".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let outcome = chain.serve(&mut context).await;
    let upstream = context.metadata.get("forward/upstream").map(str::to_owned);
    (outcome, response, upstream)
}

fn ecs_query() -> Vec<u8> {
    let mut query = QUERY.to_vec();
    query[10..12].copy_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&[
        0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 11, 0, 8, 0, 7, 0, 1, 24, 8, 192, 0, 2,
    ]);
    query
}

async fn ecs_refused_upstream(
    mismatch_retry: bool,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
        let query = Message::parse(&wire[..len]).unwrap();
        let ecs = query
            .opt()
            .unwrap()
            .options()
            .iter()
            .find_map(|option| match option {
                EdnsOption::ClientSubnet(subnet) => Some(subnet),
                _ => None,
            })
            .unwrap();
        assert_eq!(ecs.scope_prefix(), 0);
        let mut refused = wire[..len].to_vec();
        refused[2] |= 0x80;
        refused[3] = Rcode::REFUSED.0 as u8;
        socket.send_to(&refused, peer).await.unwrap();

        let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
        let query = Message::parse(&wire[..len]).unwrap();
        assert!(
            query
                .opt()
                .unwrap()
                .options()
                .iter()
                .all(|option| !matches!(option, EdnsOption::ClientSubnet(_)))
        );
        let mut reply = wire[..len].to_vec();
        reply[2] |= 0x80;
        if mismatch_retry {
            let question_end = 12 + query.questions().next().unwrap().name.wire_len();
            reply[question_end..question_end + 2].copy_from_slice(&28_u16.to_be_bytes());
        }
        socket.send_to(&reply, peer).await.unwrap();
    });
    (address, task)
}

fn chain(text: &str) -> Chain {
    let blocks = parse("Corefile", text).unwrap();
    configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config
}

fn named_query(name: &str) -> Vec<u8> {
    named_query_class(name, Class::IN)
}

fn named_query_class(name: &str, class: Class) -> Vec<u8> {
    named_query_with_opcode(name, class, 0)
}

fn named_query_with_opcode(name: &str, class: Class, opcode: u16) -> Vec<u8> {
    let name: Name = name.parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 7, (opcode << 11) | 0x0100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), Type::A, class)
        .unwrap();
    let _ = builder.finish();
    wire
}

async fn counting_upstream() -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&requests);
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        loop {
            let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
            count.fetch_add(1, Ordering::Relaxed);
            let mut response = wire[..len].to_vec();
            response[2] |= 0x80;
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    (address, requests, task)
}

async fn answering_upstream() -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&requests);
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        loop {
            let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
            count.fetch_add(1, Ordering::Relaxed);
            let query = Message::parse(&wire[..len]).unwrap();
            let question = query.questions().next().unwrap();
            let mut response = Vec::with_capacity(512);
            let mut builder = MessageBuilder::new(
                &mut response,
                512,
                query.id(),
                0x8180 | (query.flags() & 0x0100),
            )
            .unwrap();
            builder
                .question(question.name, question.qtype, question.qclass)
                .unwrap();
            builder
                .record(
                    Section::Answer,
                    question.name,
                    Type::A,
                    Class::IN,
                    60,
                    &[192, 0, 2, 44],
                )
                .unwrap();
            let _ = builder.finish();
            socket.send_to(&response, peer).await.unwrap();
        }
    });
    (address, requests, task)
}

#[tokio::test]
async fn cache_and_forward_block_reserved_names_without_upstream_queries() {
    let (address, requests, upstream) = counting_upstream().await;
    let corefile = format!(".:0 {{\n cache\n forward . {address}\n}}");
    let blocks = configure::<Chain>(&parse("Corefile", &corefile).unwrap(), directives()).unwrap();
    let (mut listeners, _) = servers(blocks).unwrap();
    let (_, server) = listeners.drain().next().unwrap();
    for name in ["service.test.", "service.invalid.", "1.10.in-addr.arpa."] {
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            server
                .handle(
                    &named_query(name),
                    "127.0.0.1:1000".parse().unwrap(),
                    Protocol::Udp,
                    &mut response,
                )
                .await,
            Action::Respond,
            "{name}"
        );
        let response = Message::parse(&response).unwrap();
        assert_eq!(response.rcode(), Rcode::NXDOMAIN, "{name}");
        assert_eq!(response.aa(), name.ends_with("arpa."), "{name}");
        assert_ne!(response.flags() & 0x0080, 0, "RA must be set: {name}");
        let soa = response
            .authorities()
            .find(|record| record.rtype == Type::SOA)
            .unwrap();
        assert_eq!(soa.ttl, 604_800, "{name}");
        match soa.data().unwrap() {
            Rdata::Soa {
                mname,
                rname,
                minimum,
                ..
            } => {
                assert_eq!(mname.to_string(), "localhost.");
                assert_eq!(rname.to_string(), "nobody.invalid.");
                assert_eq!(minimum, 604_800);
            }
            other => panic!("expected SOA, got {other:?}"),
        }
    }
    let forward_only = format!(".:0 {{\n forward . {address}\n}}");
    let blocks =
        configure::<Chain>(&parse("Corefile", &forward_only).unwrap(), directives()).unwrap();
    let (mut listeners, _) = servers(blocks).unwrap();
    let (_, server) = listeners.drain().next().unwrap();
    for name in ["service.test.", "service.invalid."] {
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            server
                .handle(
                    &named_query(name),
                    "127.0.0.1:1000".parse().unwrap(),
                    Protocol::Udp,
                    &mut response,
                )
                .await,
            Action::Respond,
            "{name}"
        );
        assert_eq!(
            Message::parse(&response).unwrap().rcode(),
            Rcode::NXDOMAIN,
            "{name}"
        );
    }
    assert_eq!(requests.load(Ordering::Relaxed), 0);
    upstream.abort();
}

#[tokio::test]
async fn allow_special_opt_in_forwards_test_and_reverse_but_never_invalid() {
    let (address, requests, upstream) = counting_upstream().await;
    let corefile = format!(".:0 {{\n cache\n forward . {address} {{\n allow_special\n }}\n}}");
    let blocks = configure::<Chain>(&parse("Corefile", &corefile).unwrap(), directives()).unwrap();
    let (mut listeners, _) = servers(blocks).unwrap();
    let (_, server) = listeners.drain().next().unwrap();
    for name in ["service.test.", "1.10.in-addr.arpa."] {
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            server
                .handle(
                    &named_query(name),
                    "127.0.0.1:1000".parse().unwrap(),
                    Protocol::Udp,
                    &mut response,
                )
                .await,
            Action::Respond,
            "{name}"
        );
        assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOERROR);
    }
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(
                &named_query("service.invalid."),
                "127.0.0.1:1000".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NXDOMAIN);
    assert_eq!(requests.load(Ordering::Relaxed), 2);
    upstream.abort();
}

#[tokio::test]
async fn cache_and_forward_block_special_names_for_non_in_classes() {
    let (address, requests, upstream) = counting_upstream().await;
    let corefile = format!(".:0 {{\n cache\n forward . {address}\n}}");
    let blocks = configure::<Chain>(&parse("Corefile", &corefile).unwrap(), directives()).unwrap();
    let (mut listeners, _) = servers(blocks).unwrap();
    let (_, server) = listeners.drain().next().unwrap();
    for class in [Class::CH, Class::ANY] {
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            server
                .handle(
                    &named_query_class("service.test.", class),
                    "127.0.0.1:1000".parse().unwrap(),
                    Protocol::Udp,
                    &mut response,
                )
                .await,
            Action::Respond
        );
        let response = Message::parse(&response).unwrap();
        assert_eq!(response.rcode(), Rcode::NXDOMAIN);
        assert!(!response.aa());
        assert_eq!(response.questions().next().unwrap().qclass, class);
        assert_eq!(
            response.authorities().next().unwrap().class,
            if class == Class::ANY {
                Class::IN
            } else {
                class
            }
        );
    }
    assert_eq!(requests.load(Ordering::Relaxed), 0);
    upstream.abort();
}

#[tokio::test]
async fn terminal_special_fallback_ignores_non_query_opcodes() {
    let chain = chain(".:0 {\n cache\n forward . 127.0.0.1:5300\n}");
    let (outcome, response, _) = run_query(
        &chain,
        &named_query_with_opcode("service.test.", Class::IN, 5),
    )
    .await;
    assert_eq!(outcome, Outcome::Error(pharos_server::Error::NoNextPlugin));
    assert!(response.is_empty());
}

#[tokio::test]
async fn cache_stores_opted_in_special_upstream_answers() {
    let (address, requests, upstream) = answering_upstream().await;
    let corefile = format!(".:0 {{\n cache\n forward . {address} {{\n allow_special\n }}\n}}");
    let blocks = configure::<Chain>(&parse("Corefile", &corefile).unwrap(), directives()).unwrap();
    let (mut listeners, _) = servers(blocks).unwrap();
    let (_, server) = listeners.drain().next().unwrap();
    for _ in 0..2 {
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            server
                .handle(
                    &named_query("service.test."),
                    "127.0.0.1:1000".parse().unwrap(),
                    Protocol::Udp,
                    &mut response,
                )
                .await,
            Action::Respond
        );
        assert_eq!(
            Message::parse(&response)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rdata,
            [192, 0, 2, 44]
        );
    }
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    upstream.abort();
}

#[tokio::test]
async fn example_domains_follow_normal_forwarding() {
    let (address, requests, upstream) = counting_upstream().await;
    let corefile = format!(".:0 {{\n cache\n forward . {address}\n}}");
    let blocks = configure::<Chain>(&parse("Corefile", &corefile).unwrap(), directives()).unwrap();
    let (mut listeners, _) = servers(blocks).unwrap();
    let (_, server) = listeners.drain().next().unwrap();
    for name in ["example.", "example.com.", "example.net.", "example.org."] {
        let mut response = Vec::with_capacity(65535);
        assert_eq!(
            server
                .handle(
                    &named_query(name),
                    "127.0.0.1:1000".parse().unwrap(),
                    Protocol::Udp,
                    &mut response,
                )
                .await,
            Action::Respond,
            "{name}"
        );
        assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOERROR);
    }
    assert_eq!(requests.load(Ordering::Relaxed), 4);
    upstream.abort();
}

#[tokio::test]
async fn explicit_special_forward_zones_opt_in_without_allow_special() {
    let (address, requests, upstream) = counting_upstream().await;
    for (from, name) in [
        ("corp.test", "service.corp.test."),
        ("10.in-addr.arpa", "1.10.in-addr.arpa."),
    ] {
        let forward = chain(&format!(".:0 {{\n forward {from} {address}\n}}"));
        let (outcome, response, _) = run_query(&forward, &named_query(name)).await;
        assert_eq!(outcome, Outcome::Response, "{from}");
        assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOERROR);
    }
    assert_eq!(requests.load(Ordering::Relaxed), 2);
    upstream.abort();
}

#[test]
fn explicit_invalid_forward_zone_is_rejected() {
    let corefile = ".:0 {\n forward invalid. 127.0.0.1:5300\n}";
    let blocks = parse("Corefile", corefile).unwrap();
    assert!(configure::<Chain>(&blocks, directives()).is_err());
}

#[cfg(feature = "plugin-secondary")]
#[tokio::test]
async fn cache_and_secondary_special_miss_returns_nxdomain() {
    let corefile = concat!(
        ".:0 {\n",
        " cache\n",
        " secondary example.org {\n",
        "  transfer from 127.0.0.1:5300\n",
        " }\n",
        "}"
    );
    let secondary = chain(corefile);
    let (outcome, response, _) = run_query(&secondary, &named_query("missing.invalid.")).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NXDOMAIN);
}

#[tokio::test]
async fn local_disable_with_cache_and_forward_uses_opted_in_upstream() {
    let (address, requests, upstream) = counting_upstream().await;
    let corefile = format!(
        ".:0 {{\n local {{\n disable 10.in-addr.arpa\n }}\n cache\n forward . {address} {{\n allow_special\n }}\n}}"
    );
    let blocks = configure::<Chain>(&parse("Corefile", &corefile).unwrap(), directives()).unwrap();
    let (mut listeners, _) = servers(blocks).unwrap();
    let (_, server) = listeners.drain().next().unwrap();
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(
                &named_query("1.10.in-addr.arpa."),
                "127.0.0.1:1000".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOERROR);
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    upstream.abort();
}

async fn fake(
    rcode: u8,
    wrong_question: bool,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
        wire[2] |= 0x80;
        wire[3] = rcode;
        if wrong_question {
            wire[len - 4] = 0;
            wire[len - 3] = 28;
        }
        socket.send_to(&wire[..len], peer).await.unwrap();
    });
    (address, task)
}

#[tokio::test]
async fn forward_alone_allows_non_in_queries_through_listener_admission() {
    let (address, upstream) = fake(0, false).await;
    let text = format!(".:0 {{\n forward . {address}\n}}");
    let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
    let (mut listeners, _) = servers(blocks).unwrap();
    let (_, server) = listeners.drain().next().unwrap();
    let mut query = QUERY.to_vec();
    *query.last_mut().unwrap() = 3;
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        server
            .handle(
                &query,
                "127.0.0.1:1000".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await,
        Action::Respond
    );
    let reply = Message::parse(&response).unwrap();
    assert_eq!(reply.rcode(), pharos_proto::Rcode::NOERROR);
    assert_eq!(
        reply.questions().next().unwrap().qclass,
        pharos_proto::Class::CH
    );
    upstream.await.unwrap();
}

#[tokio::test]
async fn forwards_query_and_restores_client_id() {
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = upstream.recv_from(&mut wire).await.unwrap();
        wire[2] |= 0x80;
        upstream.send_to(&wire[..len], peer).await.unwrap();
    });
    let text = format!(".:0 {{\n forward . {address}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let wire = QUERY;
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    let mut slots = [];
    let mut context = Context {
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
        configured[0].config.serve(&mut context).await,
        Outcome::Response
    );
    let answer = Message::parse(context.response).unwrap();
    assert_eq!(answer.id(), 0x1234);
    assert!(answer.qr());
    task.await.unwrap();
}

#[tokio::test]
async fn refused_ecs_query_retries_without_ecs() {
    let (address, upstream) = ecs_refused_upstream(false).await;
    let chain = chain(&format!(".:0 {{\n forward . {address}\n}}"));
    let query = ecs_query();
    let (outcome, response, _) = run_query(&chain, &query).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOERROR);
    upstream.await.unwrap();
}

#[tokio::test]
async fn failed_ecs_retry_preserves_original_refused_response() {
    let (address, upstream) = ecs_refused_upstream(true).await;
    let chain = chain(&format!(".:0 {{\n forward . {address}\n}}"));
    let query = ecs_query();
    let (outcome, response, _) = run_query(&chain, &query).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::REFUSED);
    upstream.await.unwrap();
}

#[tokio::test]
async fn failed_ecs_retry_still_fails_over_from_refused() {
    let (first, refused) = ecs_refused_upstream(true).await;
    let (second, answer) = fake(Rcode::NOERROR.0 as u8, false).await;
    let chain = chain(&format!(
        ".:0 {{\n forward . {first} {second} {{\n policy sequential\n failover REFUSED\n }}\n}}"
    ));
    let (outcome, response, _) = run_query(&chain, &ecs_query()).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(Message::parse(&response).unwrap().rcode(), Rcode::NOERROR);
    refused.await.unwrap();
    answer.await.unwrap();
}

#[tokio::test]
async fn refuses_unsafe_modified_query_view() {
    let chain = chain(".:0 {\n forward . 127.0.0.1:53\n}");
    let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\xc0\x03\0\x01\0\x01";
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(wire).unwrap().with_ad(),
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
        tokio::time::timeout(std::time::Duration::from_millis(200), chain.serve(&mut cx))
            .await
            .unwrap(),
        Outcome::Unanswered(pharos_proto::Rcode::FORMERR)
    );
}

#[tokio::test]
async fn forwards_with_more_than_fifteen_expanded_upstreams() {
    let (address, task) = fake(0, false).await;
    let path = std::env::temp_dir().join(format!("pharos-forward-expanded-{}", std::process::id()));
    let nameservers = (1..=16)
        .map(|i| format!("nameserver 192.0.2.{i}\n"))
        .collect::<String>();
    std::fs::write(&path, nameservers).unwrap();
    let chain = chain(&format!(
        ".:0 {{\n forward . {address} {} {{\n policy sequential\n }}\n}}",
        path.display()
    ));
    assert_eq!(run(&chain).await.0, Outcome::Response);
    task.await.unwrap();
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn invalid_file_nameserver_falls_back_to_next_upstream() {
    let (address, task) = fake(0, false).await;
    let path = std::env::temp_dir().join(format!("pharos-forward-invalid-{}", std::process::id()));
    std::fs::write(&path, "nameserver #\n").unwrap();
    let chain = chain(&format!(
        ".:0 {{\n forward . {} {address} {{\n policy sequential\n }}\n}}",
        path.display()
    ));
    assert_eq!(run(&chain).await.0, Outcome::Response);
    task.await.unwrap();
    std::fs::remove_file(path).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn all_invalid_upstreams_fail_fast() {
    let path = std::env::temp_dir().join(format!("pharos-forward-busy-{}", std::process::id()));
    std::fs::write(&path, "nameserver #\n").unwrap();
    let chain = chain(&format!(
        ".:0 {{\n forward . {} {{\n max_connect_attempts 0\n }}\n}}",
        path.display()
    ));
    let result = tokio::time::timeout(std::time::Duration::from_millis(50), run(&chain))
        .await
        .expect("all-invalid upstream set should fail fast");
    assert_eq!(result.0, Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL));
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn next_rcode_passes_to_following_forward_and_records_upstream() {
    let (first, task1) = fake(3, false).await;
    let (second, task2) = fake(0, false).await;
    let chain = chain(&format!(
        ".:0 {{\n {}\n forward . {first} {{\n next NXDOMAIN\n }}\n forward . {second}\n}}",
        if cfg!(feature = "plugin-metadata") {
            "metadata"
        } else {
            ""
        }
    ));
    let (outcome, response, upstream) = run(&chain).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(Message::parse(&response).unwrap().rcode().0, 0);
    assert_eq!(
        upstream.as_deref(),
        cfg!(feature = "plugin-metadata")
            .then_some(second.to_string())
            .as_deref()
    );
    task1.await.unwrap();
    task2.await.unwrap();
}

#[tokio::test]
async fn failover_discards_mismatched_upstream_response() {
    let (first, task1) = fake(2, false).await;
    let (second, task2) = fake(0, true).await;
    let chain = chain(&format!(
        ".:0 {{\n forward . {first} {second} {{\n policy sequential\n failover SERVFAIL\n }}\n}}"
    ));
    assert_eq!(
        run(&chain).await.0,
        Outcome::Unanswered(pharos_proto::Rcode::SERVFAIL)
    );
    task1.await.unwrap();
    task2.await.unwrap();
}

#[tokio::test]
#[cfg(feature = "plugin-whoami")]
async fn except_and_nonmatching_domains_reach_next_plugin() {
    let first = chain(".:0 {\n forward other.org 127.0.0.1\n whoami\n}");
    assert_eq!(run(&first).await.0, Outcome::Response);
    let second = chain(".:0 {\n forward . 127.0.0.1 {\n except example.com\n }\n whoami\n}");
    assert_eq!(run(&second).await.0, Outcome::Response);
}

#[tokio::test]
async fn max_concurrent_rejects_without_leaking_a_slot() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (received, wait) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let mut wire = [0; 512];
        let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
        received.send(()).unwrap();
        released.await.unwrap();
        wire[2] |= 0x80;
        socket.send_to(&wire[..len], peer).await.unwrap();
    });
    let chain = std::sync::Arc::new(chain(&format!(
        ".:0 {{\n forward . {address} {{\n max_concurrent 1\n }}\n}}"
    )));
    let first_chain = chain.clone();
    let first = tokio::spawn(async move { run(&first_chain).await });
    wait.await.unwrap();
    assert_eq!(
        run(&chain).await.0,
        Outcome::Unanswered(pharos_proto::Rcode::REFUSED)
    );
    release.send(()).unwrap();
    assert_eq!(first.await.unwrap().0, Outcome::Response);
    server.await.unwrap();
}

#[tokio::test]
async fn shutdown_stops_upstream_proxy() {
    shutdown_stops_upstream_proxy_body().await;
}

async fn shutdown_stops_upstream_proxy_body() {
    use pharos_server::{Action, Handler, Phase};
    let (upstream, task) = fake(0, false).await;
    let text = format!(".:0 {{\n forward . {upstream}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, lifecycle) =
        pharos_plugins::servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let mut response = Vec::with_capacity(65535);
    let peer = "127.0.0.1:1000".parse().unwrap();
    assert_eq!(
        server
            .handle(QUERY, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    assert_eq!(Message::parse(&response).unwrap().rcode().0, 0);
    task.await.unwrap();
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert_eq!(
        server
            .handle(QUERY, peer, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    assert_eq!(
        Message::parse(&response).unwrap().rcode(),
        pharos_proto::Rcode::SERVFAIL
    );
}
