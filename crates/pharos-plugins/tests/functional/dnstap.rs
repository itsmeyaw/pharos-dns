#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-dnstap", feature = "plugin-whoami"))]

use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pharos_corefile::{configure, parse};
use pharos_plugins::{
    Chain, directives,
    dnstap::framestream::{CONTENT_TYPE, ControlType, read_control},
    servers_with_registry,
};
use pharos_proto::Message;
use pharos_server::{
    Action, Handler, Lifecycle, Phase, Protocol,
    metrics::Registry,
    tls::{ClientAuth, ClientOptions, ServerName, ServerOptions, ServerTls, TlsConnector},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
    time::{sleep, timeout},
};

// The test decoder of the Plugin's unit tests: it panics on anything dnstap.proto does not allow.
#[allow(dead_code)]
#[path = "../../src/dnstap/msg/decode.rs"]
mod decode;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

// example.org. IN A, id 1, RD.
const QUERY: [u8; 29] = [
    0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'o', b'r',
    b'g', 0, 0, 1, 0, 1,
];

// dnstap.proto Message.Type, SocketFamily and SocketProtocol.
const CLIENT_QUERY: u64 = 5;
const CLIENT_RESPONSE: u64 = 6;
const INET: u64 = 1;
const INET6: u64 = 2;
const UDP: u64 = 1;
const TCP: u64 = 2;

/// One frame as a collector sees it.
#[derive(Debug, Eq, PartialEq)]
enum Frame {
    Data(Vec<u8>),
    /// STOP, already answered with FINISH.
    Stop,
}

// fstrm control.h: escape, control length, control type, then the content type field.
fn control(kind: ControlType, content_type: &[u8]) -> Vec<u8> {
    let mut frame = 0_u32.to_be_bytes().to_vec();
    frame.extend(((4 + 8 + content_type.len()) as u32).to_be_bytes());
    frame.extend((kind as u32).to_be_bytes());
    frame.extend(1_u32.to_be_bytes());
    frame.extend((content_type.len() as u32).to_be_bytes());
    frame.extend(content_type);
    frame
}

/// The receiving end of a bidirectional Frame Streams connection, as golang-framestream's `Decoder`.
struct Collector<S> {
    stream: S,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Collector<S> {
    /// READY, ACCEPT, START.
    async fn accept(mut stream: S) -> Self {
        let ready = read_control(&mut stream).await.unwrap();
        assert_eq!(ready.kind, ControlType::Ready as u32);
        assert_eq!(ready.content_types, [CONTENT_TYPE]);
        stream
            .write_all(&control(ControlType::Accept, CONTENT_TYPE))
            .await
            .unwrap();
        let start = read_control(&mut stream).await.unwrap();
        assert_eq!(start.kind, ControlType::Start as u32);
        assert_eq!(start.content_types, [CONTENT_TYPE]);
        Self { stream }
    }

    async fn frame(&mut self) -> Frame {
        timeout(Duration::from_secs(10), async {
            let length = self.stream.read_u32().await.unwrap();
            if length != 0 {
                let mut payload = vec![0; length as usize];
                self.stream.read_exact(&mut payload).await.unwrap();
                return Frame::Data(payload);
            }
            let size = self.stream.read_u32().await.unwrap();
            let mut body = vec![0; size as usize];
            self.stream.read_exact(&mut body).await.unwrap();
            assert_eq!(body[..4], (ControlType::Stop as u32).to_be_bytes());
            let finish = [0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, ControlType::Finish as u8];
            self.stream.write_all(&finish).await.unwrap();
            Frame::Stop
        })
        .await
        .expect("no frame in time")
    }

    async fn next(&mut self) -> decode::Dnstap {
        match self.frame().await {
            Frame::Data(payload) => decode::dnstap(&payload),
            Frame::Stop => panic!("expected a data frame, got STOP"),
        }
    }

    /// The next CLIENT_QUERY whose query port is `port`, skipping what came before it.
    async fn until_query_port(&mut self, port: u64) {
        loop {
            let message = self.next().await.message.unwrap();
            if message.kind == Some(CLIENT_QUERY) && message.query_port == Some(port) {
                return;
            }
        }
    }
}

fn block(directive: &str) -> String {
    format!(".:0 {{\n {directive}\n whoami\n}}")
}

// Starts the Server Block's Plugins as the process does at Startup.
async fn up(corefile: &str) -> (impl Handler, Registry, Lifecycle) {
    let blocks = parse("Corefile", corefile).unwrap();
    let registry = Registry::new("test", "test", "test");
    let (mut servers, lifecycle) = servers_with_registry(
        configure::<Chain>(&blocks, directives()).unwrap(),
        registry.clone(),
    )
    .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    (servers.drain().next().unwrap().1, registry, lifecycle)
}

async fn ask(server: &impl Handler, peer: &str, protocol: Protocol) -> Vec<u8> {
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        Box::pin(server.handle(&QUERY, peer.parse().unwrap(), protocol, &mut response)).await,
        Action::Respond
    );
    response
}

/// The value of a series, spelled as in the encoded metrics.
fn metric(registry: &Registry, series: &str) -> u64 {
    let mut text = String::new();
    registry.encode(&mut text);
    text.lines()
        .find_map(|line| line.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
        .unwrap_or_else(|| panic!("no series {series} in\n{text}"))
}

async fn eventually(mut condition: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if condition() {
            return;
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("condition not met in time");
}

async fn unix_collector(listener: &UnixListener) -> Collector<UnixStream> {
    let (stream, _) = timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the Plugin did not dial")
        .unwrap();
    Collector::accept(stream).await
}

async fn tcp_collector(listener: &TcpListener) -> Collector<TcpStream> {
    let (stream, _) = timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the Plugin did not dial")
        .unwrap();
    Collector::accept(stream).await
}

fn socket(dir: &Path) -> String {
    dir.join("dnstap.sock").display().to_string()
}

fn time(sec: Option<u64>, nsec: Option<u32>) -> SystemTime {
    UNIX_EPOCH + Duration::new(sec.unwrap(), nsec.unwrap())
}

// A port that is free now: bound and released, for a Corefile that must name it.
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

// CoreDNS v1.15.0 plugin/dnstap/handler_test.go TestDnstap, end to end: handshake, then the Query and its Response.
#[tokio::test]
async fn a_udp_query_is_tapped_before_its_response_with_the_configured_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = socket(dir.path());
    let listener = UnixListener::bind(&path).unwrap();
    let directive = format!(
        "dnstap {path} {{\n identity test-id\n version test-version\n extra test-extra\n }}"
    );
    let (server, registry, lifecycle) = up(&block(&directive)).await;
    let mut collector = unix_collector(&listener).await;

    let before = SystemTime::now();
    ask(&server, "192.0.2.7:5353", Protocol::Udp).await;
    let after = SystemTime::now();

    let query = collector.next().await;
    let response = collector.next().await;
    for tap in [&query, &response] {
        assert_eq!(tap.kind, Some(1));
        assert_eq!(tap.identity.as_deref(), Some(&b"test-id"[..]));
        assert_eq!(tap.version.as_deref(), Some(&b"test-version"[..]));
        assert_eq!(tap.extra.as_deref(), Some(&b"test-extra"[..]));
        let message = tap.message.as_ref().unwrap();
        assert_eq!(message.family, Some(INET));
        assert_eq!(message.protocol, Some(UDP));
        assert_eq!(message.query_address.as_deref(), Some(&[192, 0, 2, 7][..]));
        assert_eq!(message.query_port, Some(5353));
        assert_eq!(message.response_address, None);
        assert_eq!(message.response_port, None);
        // The short form carries no wire message.
        assert_eq!(message.query_message, None);
        assert_eq!(message.response_message, None);
    }
    let (query, response) = (query.message.unwrap(), response.message.unwrap());
    assert_eq!(query.kind, Some(CLIENT_QUERY));
    assert_eq!(response.kind, Some(CLIENT_RESPONSE));
    // Both messages share the Query's time; the Response follows it, inside the window of the call.
    let query_time = time(query.query_time_sec, query.query_time_nsec);
    assert_eq!(
        query_time,
        time(response.query_time_sec, response.query_time_nsec)
    );
    let response_time = time(response.response_time_sec, response.response_time_nsec);
    assert!(before <= query_time && query_time <= response_time && response_time <= after);
    assert_eq!(query.response_time_sec, None);

    assert_eq!(
        metric(&registry, "pharos_dnstap_messages_enqueued_total"),
        2
    );
    eventually(|| metric(&registry, "pharos_dnstap_messages_written_total") == 2).await;
    assert_eq!(metric(&registry, "pharos_dnstap_connected"), 1);

    // CoreDNS v1.15.0 plugin/dnstap/setup.go OnFinalShutdown: the stream ends with STOP and FINISH.
    // Close waits for FINISH, so the collector answers STOP while Shutdown runs.
    let (shutdown, stop) = tokio::join!(lifecycle.run(Phase::Shutdown), collector.frame());
    shutdown.unwrap();
    assert_eq!(stop, Frame::Stop);
    assert_eq!(metric(&registry, "pharos_dnstap_connected"), 0);
}

#[tokio::test]
async fn without_options_identity_is_the_hostname_and_version_names_pharos() {
    let dir = tempfile::tempdir().unwrap();
    let path = socket(dir.path());
    let listener = UnixListener::bind(&path).unwrap();
    let (server, _, _) = up(&block(&format!("dnstap {path}"))).await;
    let mut collector = unix_collector(&listener).await;
    ask(&server, "192.0.2.7:5353", Protocol::Udp).await;
    let tap = collector.next().await;
    let hostname = nix::unistd::gethostname().unwrap();
    assert_eq!(tap.identity.as_deref(), Some(hostname.as_encoded_bytes()));
    let version = String::from_utf8(tap.version.unwrap()).unwrap();
    assert!(version.starts_with("Pharos-"), "{version}");
    assert_eq!(tap.extra, None);
}

// CoreDNS v1.15.0 plugin/dnstap/msg/msg.go SetQueryAddress: a TCP Query over IPv6 reports family, protocol and a 16 octet address.
#[tokio::test]
async fn a_full_tcp_query_over_ipv6_carries_both_wire_messages() {
    let dir = tempfile::tempdir().unwrap();
    let path = socket(dir.path());
    let listener = UnixListener::bind(&path).unwrap();
    let (server, _, _) = up(&block(&format!("dnstap {path} full"))).await;
    let mut collector = unix_collector(&listener).await;

    let wire = ask(&server, "[2001:db8::1]:40000", Protocol::Tcp).await;

    let query = collector.next().await.message.unwrap();
    let response = collector.next().await.message.unwrap();
    for message in [&query, &response] {
        assert_eq!(message.family, Some(INET6));
        assert_eq!(message.protocol, Some(TCP));
        let address: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            message.query_address.as_deref(),
            Some(&address.octets()[..])
        );
        assert_eq!(message.query_port, Some(40000));
    }
    assert_eq!(query.query_message.as_deref(), Some(&QUERY[..]));
    assert_eq!(query.response_message, None);
    // CoreDNS v1.15.0 plugin/dnstap/writer.go tapResponse: the Response message only, not the Query.
    assert_eq!(response.query_message, None);
    assert_eq!(response.response_message.as_deref(), Some(&wire[..]));
    assert!(
        Message::parse(response.response_message.as_ref().unwrap())
            .unwrap()
            .additional_count()
            > 0
    );
}

// CoreDNS v1.15.0 plugin/dnstap/handler.go ServeDNS (#6532): a Query that ends in an error code is answered, so it is tapped.
#[tokio::test]
async fn a_query_nobody_answers_taps_a_synthesized_servfail_response() {
    let dir = tempfile::tempdir().unwrap();
    let path = socket(dir.path());
    let listener = UnixListener::bind(&path).unwrap();
    let corefile = format!(".:0 {{\n dnstap {path} full\n}}");
    let (server, _, _) = up(&corefile).await;
    let mut collector = unix_collector(&listener).await;

    let mut response = Vec::new();
    Box::pin(server.handle(
        &QUERY,
        "192.0.2.7:5353".parse().unwrap(),
        Protocol::Udp,
        &mut response,
    ))
    .await;
    assert_eq!(response[3] & 15, 2);

    assert_eq!(
        collector.next().await.message.unwrap().kind,
        Some(CLIENT_QUERY)
    );
    let tapped = collector.next().await.message.unwrap();
    assert_eq!(tapped.kind, Some(CLIENT_RESPONSE));
    assert_eq!(tapped.response_message.as_deref(), Some(&response[..]));
}

// CoreDNS v1.15.0 plugin/dnstap/io.go dio.serve: a write error redials; Pharos waits with a backoff while the collector is down.
#[tokio::test]
async fn a_collector_that_restarts_is_redialed_and_receives_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = socket(dir.path());
    let listener = UnixListener::bind(&path).unwrap();
    let (server, registry, _) = up(&block(&format!("dnstap {path}"))).await;
    let mut first = unix_collector(&listener).await;
    ask(&server, "192.0.2.7:1000", Protocol::Udp).await;
    first.until_query_port(1000).await;

    // The collector goes away: its connection and its socket.
    drop(first);
    drop(listener);
    std::fs::remove_file(&path).unwrap();
    let mut port = 2000;
    while metric(&registry, "pharos_dnstap_connect_failures_total") == 0 {
        port += 1;
        ask(&server, &format!("192.0.2.7:{port}"), Protocol::Udp).await;
        sleep(Duration::from_millis(50)).await;
        assert!(port < 2400, "the Plugin never noticed the outage");
    }

    // It comes back at the same path and is dialed again without a restart of the server.
    let listener = UnixListener::bind(&path).unwrap();
    let mut second = unix_collector(&listener).await;
    eventually(|| metric(&registry, "pharos_dnstap_reconnects_total") == 1).await;
    ask(&server, "192.0.2.7:9999", Protocol::Udp).await;
    second.until_query_port(9999).await;
    assert_eq!(metric(&registry, "pharos_dnstap_connected"), 1);
}

// CoreDNS v1.15.0 plugin/dnstap/io.go dio.Dnstap: a full queue drops rather than blocks the Query; Pharos counts the drops.
#[tokio::test]
async fn a_stalled_collector_makes_the_full_queue_drop_and_count() {
    let dir = tempfile::tempdir().unwrap();
    let path = socket(dir.path());
    // Bound but never accepted: the dial succeeds in the kernel and the handshake never completes.
    let _listener = UnixListener::bind(&path).unwrap();
    let (server, registry, _) = up(&block(&format!("dnstap {path}"))).await;

    // `queue` 1 holds 10,000 messages; 6,000 Queries send 12,000.
    for number in 0..6000 {
        ask(
            &server,
            &format!("192.0.2.7:{}", 1024 + number),
            Protocol::Udp,
        )
        .await;
    }

    assert_eq!(
        metric(&registry, "pharos_dnstap_messages_enqueued_total"),
        10_000
    );
    assert_eq!(
        metric(
            &registry,
            "pharos_dnstap_messages_dropped_total{reason=\"queue_full\"}"
        ),
        2000
    );
    assert_eq!(metric(&registry, "pharos_dnstap_messages_written_total"), 0);
}

#[tokio::test]
async fn a_tcp_collector_receives_messages() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (server, _, _) = up(&block(&format!("dnstap tcp://127.0.0.1:{port} full"))).await;
    let mut collector = tcp_collector(&listener).await;
    ask(&server, "192.0.2.7:5353", Protocol::Udp).await;
    let query = collector.next().await.message.unwrap();
    assert_eq!(query.kind, Some(CLIENT_QUERY));
    assert_eq!(query.query_message.as_deref(), Some(&QUERY[..]));
    assert_eq!(
        collector.next().await.message.unwrap().kind,
        Some(CLIENT_RESPONSE)
    );
}

// CoreDNS v1.15.0 plugin/dnstap/io.go dial: `tls://` dials TLS; `skipverify` accepts any server certificate.
#[tokio::test]
async fn a_tls_collector_receives_messages_with_skipverify() {
    let acceptor = ServerTls::load(&ServerOptions {
        cert: format!("{FIXTURES}/server.pem").into(),
        key: format!("{FIXTURES}/server.key.pem").into(),
        ca: None,
        client_auth: ClientAuth::NoCert,
        keylog: None,
    })
    .unwrap()
    .acceptor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let directive = format!("dnstap tls://127.0.0.1:{port} {{\n skipverify\n }}");
    let (server, _, _) = up(&block(&directive)).await;
    let (tcp, _) = timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the Plugin did not dial")
        .unwrap();
    // The certificate names `localhost`, not 127.0.0.1: only `skipverify` lets the handshake finish.
    let mut collector = Collector::accept(acceptor.accept(tcp).await.unwrap()).await;
    ask(&server, "192.0.2.7:5353", Protocol::Udp).await;
    assert_eq!(
        collector.next().await.message.unwrap().kind,
        Some(CLIENT_QUERY)
    );
}

// CoreDNS v1.15.0 plugin/dnstap/listener.go: `dnstap listen` accepts collectors and sends each of them every message.
#[tokio::test]
async fn a_listener_broadcasts_to_every_collector_that_connects() {
    let dir = tempfile::tempdir().unwrap();
    let path = socket(dir.path());
    let (server, registry, lifecycle) = up(&block(&format!("dnstap listen {path} full"))).await;
    let mut first = Collector::accept(UnixStream::connect(&path).await.unwrap()).await;
    let mut second = Collector::accept(UnixStream::connect(&path).await.unwrap()).await;
    eventually(|| metric(&registry, "pharos_dnstap_connected") == 2).await;

    ask(&server, "192.0.2.7:5353", Protocol::Udp).await;

    for collector in [&mut first, &mut second] {
        let query = collector.next().await.message.unwrap();
        assert_eq!(query.kind, Some(CLIENT_QUERY));
        assert_eq!(query.query_message.as_deref(), Some(&QUERY[..]));
        assert_eq!(
            collector.next().await.message.unwrap().kind,
            Some(CLIENT_RESPONSE)
        );
    }
    let (shutdown, first_stop, second_stop) = tokio::join!(
        lifecycle.run(Phase::Shutdown),
        first.frame(),
        second.frame()
    );
    shutdown.unwrap();
    assert_eq!((first_stop, second_stop), (Frame::Stop, Frame::Stop));
}

// CoreDNS v1.15.0 plugin/dnstap/listener.go listen: `tls://` with a `tls CERT KEY` block serves TLS to collectors.
#[tokio::test]
async fn a_tls_listener_serves_a_collector_that_verifies_it() {
    let port = free_port().await;
    let directive = format!(
        "dnstap listen tls://127.0.0.1:{port} {{\n tls {FIXTURES}/server.pem {FIXTURES}/server.key.pem\n }}"
    );
    let (server, registry, _) = up(&block(&directive)).await;
    let config = pharos_server::tls::client_config(&ClientOptions {
        ca: Some(format!("{FIXTURES}/ca.pem").into()),
        identity: None,
    })
    .unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let tls = TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let mut collector = Collector::accept(tls).await;
    eventually(|| metric(&registry, "pharos_dnstap_connected") == 1).await;
    ask(&server, "192.0.2.7:5353", Protocol::Udp).await;
    assert_eq!(
        collector.next().await.message.unwrap().kind,
        Some(CLIENT_QUERY)
    );
}

const FORWARDER_QUERY: u64 = 7;
const FORWARDER_RESPONSE: u64 = 8;

// An Upstream that answers every Query with QR set.
#[cfg(feature = "plugin-forward")]
async fn echo_upstream() -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut wire = [0; 512];
        while let Ok((length, peer)) = socket.recv_from(&mut wire).await {
            wire[2] |= 0x80;
            let _ = socket.send_to(&wire[..length], peer).await;
        }
    });
    port
}

// CoreDNS v1.15.0 plugin/forward/dnstap.go toDnstap: the exchange with the Upstream is tapped between the Query and its Response.
#[cfg(feature = "plugin-forward")]
#[tokio::test]
async fn forward_taps_its_exchange_with_the_upstream_from_the_servers_side() {
    let dir = tempfile::tempdir().unwrap();
    let path = socket(dir.path());
    let listener = UnixListener::bind(&path).unwrap();
    let upstream = echo_upstream().await;
    let corefile = format!(".:0 {{\n dnstap {path} full\n forward . 127.0.0.1:{upstream}\n}}");
    let (server, _, _) = up(&corefile).await;
    let mut collector = unix_collector(&listener).await;

    let wire = ask(&server, "192.0.2.7:5353", Protocol::Udp).await;

    let mut kinds = Vec::new();
    let mut messages = Vec::new();
    for _ in 0..4 {
        let message = collector.next().await.message.unwrap();
        kinds.push(message.kind.unwrap());
        messages.push(message);
    }
    assert_eq!(
        kinds,
        [
            CLIENT_QUERY,
            FORWARDER_QUERY,
            FORWARDER_RESPONSE,
            CLIENT_RESPONSE
        ]
    );
    let (query, response) = (&messages[1], &messages[2]);
    for message in [query, response] {
        assert_eq!(message.family, Some(INET));
        assert_eq!(message.protocol, Some(UDP));
        // The Query address is this server's socket toward the Upstream; the Response address is the Upstream.
        assert_eq!(message.query_address.as_deref(), Some(&[127, 0, 0, 1][..]));
        assert!(
            message
                .query_port
                .is_some_and(|port| port != 5353 && port != 0)
        );
        assert_eq!(
            message.response_address.as_deref(),
            Some(&[127, 0, 0, 1][..])
        );
        assert_eq!(message.response_port, Some(u64::from(upstream)));
    }
    let query_time = time(query.query_time_sec, query.query_time_nsec);
    assert_eq!(
        query_time,
        time(response.query_time_sec, response.query_time_nsec)
    );
    assert!(query_time <= time(response.response_time_sec, response.response_time_nsec));
    assert_eq!(query.response_time_sec, None);
    // `full`: the Query goes out as the client sent it, and the Response is the Upstream's.
    assert_eq!(query.query_message.as_deref(), Some(&QUERY[..]));
    assert_eq!(query.response_message, None);
    assert_eq!(response.query_message, None);
    assert_eq!(response.response_message.as_deref(), Some(&wire[..]));
}

// CoreDNS v1.15.0 plugin/forward/dnstap.go toDnstap: `state.Req` is the current, possibly rewritten, request.
#[cfg(all(feature = "plugin-forward", feature = "plugin-rewrite"))]
#[tokio::test]
async fn forward_taps_the_query_it_sent_after_a_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = socket(dir.path());
    let listener = UnixListener::bind(&path).unwrap();
    let upstream = echo_upstream().await;
    let corefile = format!(
        ".:0 {{\n dnstap {path} full\n rewrite name exact example.org example.net\n forward . 127.0.0.1:{upstream}\n}}"
    );
    let (server, _, _) = up(&corefile).await;
    let mut collector = unix_collector(&listener).await;

    ask(&server, "192.0.2.7:5353", Protocol::Udp).await;

    let mut sent = None;
    for _ in 0..4 {
        let message = collector.next().await.message.unwrap();
        match message.kind.unwrap() {
            // The client's Query is tapped before the Plugin Chain rewrites it.
            CLIENT_QUERY => assert_eq!(message.query_message.as_deref(), Some(&QUERY[..])),
            FORWARDER_QUERY => sent = message.query_message,
            _ => {}
        }
    }
    let mut rewritten = QUERY.to_vec();
    rewritten[13..20].copy_from_slice(b"example");
    rewritten[21..24].copy_from_slice(b"net");
    assert_eq!(sent.as_deref(), Some(&rewritten[..]));
}

// CoreDNS v1.15.0 plugin/forward/dnstap.go toDnstap: a failed exchange has no reply, so only the forwarder Query is tapped.
#[cfg(feature = "plugin-forward")]
#[tokio::test]
async fn forward_taps_no_response_when_the_upstream_does_not_answer() {
    let dir = tempfile::tempdir().unwrap();
    let path = socket(dir.path());
    let listener = UnixListener::bind(&path).unwrap();
    // Nothing listens here: the TCP connect is refused at once.
    let closed = free_port().await;
    let corefile =
        format!(".:0 {{\n dnstap {path}\n forward . 127.0.0.1:{closed} {{\n force_tcp\n }}\n}}");
    let (server, _, _) = up(&corefile).await;
    let mut collector = unix_collector(&listener).await;

    let mut response = Vec::new();
    Box::pin(server.handle(
        &QUERY,
        "192.0.2.7:5353".parse().unwrap(),
        Protocol::Udp,
        &mut response,
    ))
    .await;
    assert_eq!(response[3] & 15, 2);

    let mut forwarded = 0;
    loop {
        let message = collector.next().await.message.unwrap();
        match message.kind.unwrap() {
            CLIENT_QUERY => {}
            FORWARDER_QUERY => {
                forwarded += 1;
                assert_eq!(message.protocol, Some(TCP));
                assert_eq!(message.response_port, Some(u64::from(closed)));
            }
            CLIENT_RESPONSE => break,
            other => panic!("unexpected message type {other}"),
        }
    }
    assert!(forwarded > 0);
}
