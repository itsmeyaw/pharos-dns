#![forbid(unsafe_code)]
#![cfg(feature = "plugin-forward")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
use tokio::net::UdpSocket;

const QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";

async fn run(chain: &Chain) -> (Outcome, Vec<u8>, Option<String>) {
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    let mut slots = [];
    let mut context = Context {
        query: Message::parse(QUERY).unwrap(),
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

fn chain(text: &str) -> Chain {
    let blocks = parse("Corefile", text).unwrap();
    configure::<Chain>(&blocks, directives())
        .unwrap()
        .remove(0)
        .config
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
async fn unlimited_invalid_upstream_does_not_block_runtime() {
    let path = std::env::temp_dir().join(format!("pharos-forward-busy-{}", std::process::id()));
    std::fs::write(&path, "nameserver #\n").unwrap();
    let chain = chain(&format!(
        ".:0 {{\n forward . {} {{\n max_connect_attempts 0\n }}\n}}",
        path.display()
    ));
    let result = tokio::time::timeout(std::time::Duration::from_millis(50), run(&chain)).await;
    assert!(result.is_err(), "invalid upstream blocked the runtime");
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn next_rcode_passes_to_following_forward_and_records_upstream() {
    let (first, task1) = fake(3, false).await;
    let (second, task2) = fake(0, false).await;
    let chain = chain(&format!(
        ".:0 {{\n forward . {first} {{\n next NXDOMAIN\n }}\n forward . {second}\n}}"
    ));
    let (outcome, response, upstream) = run(&chain).await;
    assert_eq!(outcome, Outcome::Response);
    assert_eq!(Message::parse(&response).unwrap().rcode().0, 0);
    assert_eq!(upstream.as_deref(), Some(second.to_string().as_str()));
    task1.await.unwrap();
    task2.await.unwrap();
}

#[tokio::test]
async fn failover_tries_next_upstream_and_question_mismatch_is_formerr() {
    let (first, task1) = fake(2, false).await;
    let (second, task2) = fake(0, true).await;
    let chain = chain(&format!(
        ".:0 {{\n forward . {first} {second} {{\n policy sequential\n failover SERVFAIL\n }}\n}}"
    ));
    assert_eq!(
        run(&chain).await.0,
        Outcome::Unanswered(pharos_proto::Rcode::FORMERR)
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
