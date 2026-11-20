#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Buf, Bytes};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{HeaderMap, Method, Request, StatusCode, client::conn::http2, http::request::Builder};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{
    Action, GrpcOptions, Handler, ListenerKey, ListenerRegistry, Protocol, TcpOptions, Transport,
    grpc::{self, Code, FramePrefix},
    tls::{ClientAuth, ClientOptions, ServerOptions, ServerTls, TlsConnector, client_config},
};
use rustls::pki_types::ServerName;
use tokio::{net::TcpStream, time::timeout};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/tls")
        .join(name)
}

fn query(id: u16) -> Vec<u8> {
    let mut wire = Vec::new();
    let name: Name = "example.org.".parse().unwrap();
    let mut builder = MessageBuilder::new(&mut wire, 512, id, 0x0100).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    wire
}

/// Answers every Query with one A record, after an optional delay.
struct Answering {
    tls: ServerTls,
    options: GrpcOptions,
    delay: Duration,
    tcp: TcpOptions,
    calls: Arc<AtomicUsize>,
    running: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    peers: Arc<Mutex<Vec<SocketAddr>>>,
}

impl Answering {
    fn new(options: GrpcOptions) -> Self {
        let tls = ServerTls::load(&ServerOptions {
            cert: fixture("server.pem"),
            key: fixture("server.key.pem"),
            ca: None,
            client_auth: ClientAuth::NoCert,
            keylog: None,
        })
        .unwrap()
        .with_alpn(grpc::ALPN);
        Self {
            tls,
            options,
            delay: Duration::ZERO,
            tcp: TcpOptions::default(),
            calls: Arc::default(),
            running: Arc::default(),
            peak: Arc::default(),
            peers: Arc::default(),
        }
    }
}

impl Handler for Answering {
    fn tls(&self) -> Option<ServerTls> {
        Some(self.tls.clone())
    }
    fn grpc(&self) -> GrpcOptions {
        self.options
    }
    fn tcp_options(&self) -> TcpOptions {
        self.tcp
    }
    async fn handle(
        &self,
        query: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        // CoreDNS v1.15.0 server_grpc.go: the Plugin Chain runs with the TCP rules.
        assert_eq!(protocol, Protocol::Tcp);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.peers.lock().unwrap().push(peer);
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        self.running.fetch_sub(1, Ordering::SeqCst);
        let name: Name = "example.org.".parse().unwrap();
        let owner = NameRef::parse(name.as_wire(), 0).unwrap();
        let id = u16::from_be_bytes([query[0], query[1]]);
        let mut builder = MessageBuilder::new(response, 512, id, 0x8180).unwrap();
        builder.question(owner, Type::A, Class::IN).unwrap();
        builder
            .record(
                Section::Answer,
                owner,
                Type::A,
                Class::IN,
                300,
                &[192, 0, 2, 1],
            )
            .unwrap();
        let _ = builder.finish();
        Action::Respond
    }
}

fn key() -> ListenerKey {
    ListenerKey {
        transport: Transport::Grpc,
        address: "127.0.0.1:0".parse().unwrap(),
    }
}

async fn listening(handler: Answering) -> (ListenerRegistry, SocketAddr) {
    let mut registry = ListenerRegistry::default();
    registry
        .apply(HashMap::from([(key(), handler)]))
        .await
        .unwrap();
    let address = registry.get(&key()).unwrap().local_addr();
    (registry, address)
}

async fn tls_connect(
    address: SocketAddr,
    alpn: &[&[u8]],
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, std::io::Error> {
    let mut config = (*client_config(&ClientOptions {
        ca: Some(fixture("ca.pem")),
        identity: None,
    })
    .unwrap())
    .clone();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    let tcp = TcpStream::connect(address).await.unwrap();
    TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
}

type Payload = BoxBody<Bytes, Infallible>;
type Sender = http2::SendRequest<Payload>;

async fn connect(address: SocketAddr) -> (Sender, SocketAddr) {
    let tls = tls_connect(address, grpc::ALPN).await.unwrap();
    let local = tls.get_ref().0.local_addr().unwrap();
    let (sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(connection);
    (sender, local)
}

/// One gRPC message carrying `message` as the `DnsPacket` field.
fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prefix = FramePrefix::new(message.len());
    while prefix.has_remaining() {
        let count = prefix.chunk().len();
        out.extend_from_slice(prefix.chunk());
        prefix.advance(count);
    }
    out.extend_from_slice(message);
    out
}

fn builder(path: &str) -> Builder {
    Request::builder()
        .method(Method::POST)
        .uri(format!("https://localhost{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
}

fn body(bytes: Vec<u8>) -> Payload {
    Full::new(Bytes::from(bytes)).boxed()
}

fn call(message: &[u8]) -> Request<Payload> {
    builder(grpc::PATH).body(body(frame(message))).unwrap()
}

fn raw(bytes: Vec<u8>) -> Request<Payload> {
    builder(grpc::PATH).body(body(bytes)).unwrap()
}

struct Reply {
    http: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    trailers: Option<HeaderMap>,
}

impl Reply {
    /// The gRPC status, from the trailers or, for Trailers-Only, from the headers.
    fn status(&self) -> (Code, String) {
        let map = self.trailers.as_ref().unwrap_or(&self.headers);
        let code = Code::from_header(map["grpc-status"].as_bytes());
        let message = map
            .get("grpc-message")
            .map(|value| grpc::unescape_message(value.to_str().unwrap()))
            .unwrap_or_default();
        (code, message)
    }

    /// The DNS Message in a successful Response.
    fn dns(&self) -> &[u8] {
        let header = grpc::parse_header(&self.body).unwrap().unwrap();
        assert!(!header.compressed);
        assert_eq!(self.body.len(), grpc::HEADER_LEN + header.len);
        grpc::decode_packet(&self.body[grpc::HEADER_LEN..]).unwrap()
    }
}

async fn send(sender: &mut Sender, request: Request<Payload>) -> Reply {
    sender.ready().await.unwrap();
    let response = timeout(TEST_TIMEOUT, sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    let (parts, body) = response.into_parts();
    let collected = timeout(TEST_TIMEOUT, body.collect())
        .await
        .unwrap()
        .unwrap();
    let trailers = collected.trailers().cloned();
    Reply {
        http: parts.status,
        headers: parts.headers,
        body: collected.to_bytes(),
        trailers,
    }
}

// CoreDNS v1.15.0 server_grpc.go Query: the DnsPacket Response carries the Plugin Chain's Message.
#[tokio::test]
async fn a_query_is_answered_with_a_dns_packet_and_status_ok() {
    let handler = Answering::new(GrpcOptions::default());
    let peers = Arc::clone(&handler.peers);
    let (registry, address) = listening(handler).await;
    let (mut sender, local) = connect(address).await;
    let reply = send(&mut sender, call(&query(7))).await;
    assert_eq!(reply.http, StatusCode::OK);
    assert_eq!(reply.headers["content-type"], "application/grpc");
    assert_eq!(reply.status(), (Code::Ok, String::new()));
    assert_eq!(&reply.dns()[..2], &7u16.to_be_bytes());
    assert_eq!(&reply.dns()[2..4], &[0x81, 0x80]);
    // The client address is the TCP peer.
    assert_eq!(*peers.lock().unwrap(), [local]);
    // The same connection serves further calls.
    let reply = send(&mut sender, call(&query(8))).await;
    assert_eq!(reply.status().0, Code::Ok);
    assert_eq!(&reply.dns()[..2], &8u16.to_be_bytes());
    registry.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 server_grpc_test.go TestServergRPC_Query_ErrorCases, TestServergRPC_QueryRejectsUpdate
// and grpc-go v1.84.0 http2_server.go operateHeaders and server.go handleStream statuses.
#[tokio::test]
async fn invalid_calls_get_the_grpc_go_statuses() {
    let handler = Answering::new(GrpcOptions::default());
    let calls = Arc::clone(&handler.calls);
    let (registry, address) = listening(handler).await;
    let (mut sender, _) = connect(address).await;
    let mut update = query(1);
    update[2] = 0x28;
    let valid = || body(frame(&query(1)));
    let with = |name: &str, value: &str| {
        builder(grpc::PATH)
            .header(name, value)
            .body(valid())
            .unwrap()
    };
    let path = |path: &str| builder(path).body(valid()).unwrap();
    let get = Request::builder()
        .method(Method::GET)
        .uri(format!("https://localhost{}", grpc::PATH))
        .header("content-type", "application/grpc")
        .body(body(Vec::new()))
        .unwrap();
    // `builder` already sets a content-type, so these cases start from a bare request.
    let typed = |value: &str| {
        Request::builder()
            .method(Method::POST)
            .uri(format!("https://localhost{}", grpc::PATH))
            .header("content-type", value)
            .body(valid())
            .unwrap()
    };
    let cases: Vec<(&str, Request<Payload>, u16, Code, &str)> = vec![
        ("UPDATE", call(&update), 200, Code::Unknown, "dns: invalid"),
        (
            "not DNS",
            call(b"invalid"),
            200,
            Code::Unknown,
            "dns: invalid",
        ),
        (
            "empty DnsPacket",
            raw(vec![0; 5]),
            200,
            Code::Unknown,
            "dns:",
        ),
        ("no message", raw(Vec::new()), 200, Code::Unknown, "EOF"),
        (
            "short header",
            raw(vec![0, 0, 0]),
            200,
            Code::Internal,
            "unexpected EOF",
        ),
        (
            "truncated message",
            raw(vec![0, 0, 0, 0, 9, 0x0a, 7]),
            200,
            Code::Internal,
            "unexpected EOF",
        ),
        (
            "two messages",
            raw([frame(&query(1)), frame(&query(2))].concat()),
            200,
            Code::Internal,
            "unexpected data",
        ),
        (
            "malformed protobuf",
            raw(vec![0, 0, 0, 0, 3, 0x0a, 9, 1]),
            200,
            Code::Internal,
            "grpc: error unmarshalling request",
        ),
        (
            "compressed",
            raw(vec![1, 0, 0, 0, 2, 0x0a, 0]),
            200,
            Code::Internal,
            "compressed flag",
        ),
        (
            "bad flag",
            raw(vec![2, 0, 0, 0, 0]),
            200,
            Code::Internal,
            "invalid compression flag",
        ),
        (
            "oversize",
            raw(vec![0, 0, 1, 0, 4]),
            200,
            Code::ResourceExhausted,
            "received message larger than max (65540 vs. 65539)",
        ),
        (
            "unknown service",
            path("/other.Service/Query"),
            200,
            Code::Unimplemented,
            "unknown service other.Service",
        ),
        (
            "unknown method",
            path("/coredns.dns.DnsService/Other"),
            200,
            Code::Unimplemented,
            "unknown method Other for service coredns.dns.DnsService",
        ),
        (
            "malformed path",
            path("/nope"),
            200,
            Code::Unimplemented,
            "malformed method name",
        ),
        (
            "encoding",
            with("grpc-encoding", "gzip"),
            200,
            Code::Unimplemented,
            "Decompressor is not installed",
        ),
        (
            "timeout",
            with("grpc-timeout", "soon"),
            400,
            Code::Internal,
            "malformed grpc-timeout",
        ),
        (
            "content type",
            typed("application/dns-message"),
            415,
            Code::InvalidArgument,
            "invalid gRPC request content-type",
        ),
        (
            "JSON subtype",
            typed("application/grpc+json"),
            415,
            Code::InvalidArgument,
            "invalid gRPC request content-type",
        ),
        (
            "method",
            get,
            405,
            Code::Internal,
            "invalid gRPC request method",
        ),
    ];
    for (name, request, http, code, message) in cases {
        let reply = send(&mut sender, request).await;
        assert_eq!(reply.http.as_u16(), http, "{name}");
        assert!(reply.body.is_empty(), "{name}");
        // PROTOCOL-HTTP2 "Trailers-Only": the status is in the headers and there are no trailers.
        assert!(reply.trailers.is_none(), "{name}");
        let (got, text) = reply.status();
        assert_eq!(got, code, "{name}: {text}");
        assert!(text.contains(message), "{name}: {text}");
    }
    // Every rejection happened before the Plugin Chain, and the connection still works.
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        send(&mut sender, call(&query(2))).await.status().0,
        Code::Ok
    );
    registry.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 server_grpc_test.go TestServergRPC_Query_MaxSizeMessage and _LargeMessage, and
// server_grpc.go Serve: grpc.MaxRecvMsgSize(maxProtobufPayloadBytes).
#[tokio::test]
async fn message_size_limits_follow_coredns() {
    let (registry, address) = listening(Answering::new(GrpcOptions::default())).await;
    let (mut sender, _) = connect(address).await;
    // A Query padded to exactly 65535 octets is the largest accepted DnsPacket.
    let mut padded = query(3);
    padded.resize(grpc::MAX_MESSAGE_LEN, 0);
    let reply = send(&mut sender, call(&padded)).await;
    assert_eq!(reply.status().0, Code::Ok, "{:?}", reply.status());
    // One octet more makes the payload 65540 octets, one over grpc.MaxRecvMsgSize.
    padded.push(0);
    let reply = send(&mut sender, call(&padded)).await;
    assert_eq!(
        reply.status(),
        (
            Code::ResourceExhausted,
            "grpc: received message larger than max (65540 vs. 65539)".to_owned()
        )
    );
    // The rejected stream leaves the connection usable.
    assert_eq!(
        send(&mut sender, call(&query(4))).await.status().0,
        Code::Ok
    );
    registry.shutdown().await.unwrap();
}

// PROTOCOL-HTTP2 "Timeout": a call that outlives grpc-timeout ends with DEADLINE_EXCEEDED.
#[tokio::test]
async fn grpc_timeout_ends_a_slow_call() {
    let mut handler = Answering::new(GrpcOptions::default());
    handler.delay = Duration::from_millis(600);
    let (registry, address) = listening(handler).await;
    let (mut sender, _) = connect(address).await;
    let slow = builder(grpc::PATH)
        .header("grpc-timeout", "100m")
        .body(body(frame(&query(1))))
        .unwrap();
    assert_eq!(
        send(&mut sender, slow).await.status().0,
        Code::DeadlineExceeded
    );
    let generous = builder(grpc::PATH)
        .header("grpc-timeout", "5S")
        .body(body(frame(&query(1))))
        .unwrap();
    assert_eq!(send(&mut sender, generous).await.status().0, Code::Ok);
    registry.shutdown().await.unwrap();
}

/// A request body that sends its first bytes and then never finishes.
struct Stalled(Option<Bytes>);

impl Body for Stalled {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.0.take() {
            Some(bytes) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            None => Poll::Pending,
        }
    }
}

// CoreDNS v1.15.0 plugin/timeouts: the TCP read timeout bounds a request that stops sending.
#[tokio::test]
async fn a_stalled_request_message_is_abandoned_after_the_read_timeout() {
    let mut handler = Answering::new(GrpcOptions::default());
    handler.tcp.read = Duration::from_millis(300);
    let (registry, address) = listening(handler).await;
    let (mut sender, _) = connect(address).await;
    let stalled = builder(grpc::PATH)
        .body(Stalled(Some(Bytes::from_static(&[0, 0, 0, 0, 40]))).boxed())
        .unwrap();
    assert_eq!(
        send(&mut sender, stalled).await.status().0,
        Code::DeadlineExceeded
    );
    assert_eq!(
        send(&mut sender, call(&query(1))).await.status().0,
        Code::Ok
    );
    registry.shutdown().await.unwrap();
}

/// Run `count` calls at once on one connection whose server has already announced its settings.
async fn burst(sender: &Sender, count: u16) {
    let mut tasks = Vec::new();
    for id in 0..count {
        let mut sender = sender.clone();
        tasks.push(tokio::spawn(async move {
            send(&mut sender, call(&query(id))).await.status().0
        }));
    }
    for task in tasks {
        assert_eq!(
            timeout(TEST_TIMEOUT, task).await.unwrap().unwrap(),
            Code::Ok
        );
    }
}

// RFC 9113 §6.5.2: SETTINGS_MAX_CONCURRENT_STREAMS bounds the calls one connection runs at once.
#[tokio::test]
async fn max_streams_bounds_concurrent_calls_per_connection() {
    let mut handler = Answering::new(GrpcOptions {
        max_streams: 2,
        ..GrpcOptions::default()
    });
    handler.delay = Duration::from_millis(150);
    let peak = Arc::clone(&handler.peak);
    let (registry, address) = listening(handler).await;
    let (mut sender, _) = connect(address).await;
    // The server's SETTINGS must reach the client before it opens streams in a burst.
    send(&mut sender, call(&query(99))).await;
    peak.store(0, Ordering::SeqCst);
    burst(&sender, 6).await;
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    registry.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 server_grpc.go Serve: MaxConcurrentStreams is set only when above zero.
#[tokio::test]
async fn zero_max_streams_does_not_limit_concurrent_calls() {
    let mut handler = Answering::new(GrpcOptions {
        max_streams: 0,
        ..GrpcOptions::default()
    });
    handler.delay = Duration::from_millis(300);
    let peak = Arc::clone(&handler.peak);
    let (registry, address) = listening(handler).await;
    let (mut sender, _) = connect(address).await;
    send(&mut sender, call(&query(99))).await;
    peak.store(0, Ordering::SeqCst);
    burst(&sender, 300).await;
    // hyper's own default would cap this at 200.
    let peak = peak.load(Ordering::SeqCst);
    assert!(peak > 200, "{peak}");
    registry.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 server_grpc.go Serve: netutil.LimitListener caps live connections.
#[tokio::test]
async fn max_connections_holds_back_further_connections() {
    let (registry, address) = listening(Answering::new(GrpcOptions {
        max_connections: 1,
        ..GrpcOptions::default()
    }))
    .await;
    let (mut first, _) = connect(address).await;
    assert_eq!(send(&mut first, call(&query(1))).await.status().0, Code::Ok);
    let blocked = timeout(Duration::from_millis(500), connect(address)).await;
    assert!(blocked.is_err(), "second connection was served");
    drop(first);
    let (mut second, _) = timeout(TEST_TIMEOUT, connect(address)).await.unwrap();
    assert_eq!(
        send(&mut second, call(&query(2))).await.status().0,
        Code::Ok
    );
    registry.shutdown().await.unwrap();
}

// RFC 7301 §3.2 and grpc-go v1.84.0: gRPC needs ALPN "h2"; other protocols are refused.
#[tokio::test]
async fn only_h2_is_negotiated() {
    let (registry, address) = listening(Answering::new(GrpcOptions::default())).await;
    // No overlap with the server's list is a handshake failure.
    assert!(tls_connect(address, &[b"http/1.1"]).await.is_err());
    // A client that offers no protocol is dropped after the handshake.
    let tls = tls_connect(address, &[]).await.unwrap();
    let outcome = timeout(TEST_TIMEOUT, async {
        let (mut sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(connection);
        sender.ready().await?;
        sender.send_request(call(&query(1))).await
    })
    .await
    .unwrap();
    assert!(outcome.is_err());
    registry.shutdown().await.unwrap();
}

// RFC 9113 §6.8: shutdown lets an in-flight call finish.
#[tokio::test]
async fn shutdown_finishes_a_running_call() {
    let mut handler = Answering::new(GrpcOptions::default());
    handler.delay = Duration::from_millis(500);
    let running = Arc::clone(&handler.running);
    let (registry, address) = listening(handler).await;
    let (mut sender, _) = connect(address).await;
    let reply = tokio::spawn(async move { send(&mut sender, call(&query(1))).await.status().0 });
    while running.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    registry.shutdown().await.unwrap();
    assert_eq!(reply.await.unwrap(), Code::Ok);
    assert!(TcpStream::connect(address).await.is_err());
}

// RFC 7766 §6.2.3: a connection with no call in flight is closed after the idle timeout.
#[tokio::test]
async fn idle_connections_are_closed() {
    let mut handler = Answering::new(GrpcOptions::default());
    handler.tcp.idle = Duration::from_millis(300);
    let (registry, address) = listening(handler).await;
    let (mut sender, _) = connect(address).await;
    assert_eq!(
        send(&mut sender, call(&query(1))).await.status().0,
        Code::Ok
    );
    timeout(TEST_TIMEOUT, async {
        while !sender.is_closed() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("idle connection stayed open");
    registry.shutdown().await.unwrap();
}

// RFC 7766 §6.2.3: idle time counts only while no call is running.
#[tokio::test]
async fn a_running_call_is_not_cut_by_the_idle_timeout() {
    let mut handler = Answering::new(GrpcOptions::default());
    handler.delay = Duration::from_millis(900);
    handler.tcp.idle = Duration::from_millis(300);
    let (registry, address) = listening(handler).await;
    let (mut sender, _) = connect(address).await;
    assert_eq!(
        send(&mut sender, call(&query(1))).await.status().0,
        Code::Ok
    );
    registry.shutdown().await.unwrap();
}
