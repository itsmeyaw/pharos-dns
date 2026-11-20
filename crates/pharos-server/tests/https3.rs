#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Buf, Bytes};
use hyper::{Method, Request, StatusCode};
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{
    Action, Handler, HttpsOptions, ListenerKey, ListenerRegistry, Protocol, TcpOptions, Transport,
    doh::{self, Status},
    metrics::Registry,
    tls::{ClientAuth, ClientOptions, ServerOptions, ServerTls, client_config},
};
use quinn::{
    ClientConfig, Connection, ConnectionError, Endpoint, crypto::rustls::QuicClientConfig,
};
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/tls")
        .join(name)
}

fn identity(prefix: &str) -> ServerTls {
    ServerTls::load(&ServerOptions {
        cert: fixture(&format!("{prefix}.pem")),
        key: fixture(&format!("{prefix}.key.pem")),
        ca: None,
        client_auth: ClientAuth::NoCert,
        keylog: None,
    })
    .unwrap()
    .with_quic_alpn(doh::H3_ALPN)
    .unwrap()
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

/// Answers every Query with one A record of TTL 300, after an optional delay.
struct Answering {
    tls: ServerTls,
    options: HttpsOptions,
    delay: Duration,
    drop: bool,
    tcp: TcpOptions,
    calls: Arc<AtomicUsize>,
    running: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl Answering {
    fn new(options: HttpsOptions) -> Self {
        Self {
            tls: identity("server"),
            options,
            delay: Duration::ZERO,
            drop: false,
            tcp: TcpOptions::default(),
            calls: Arc::default(),
            running: Arc::default(),
            peak: Arc::default(),
        }
    }
}

fn options() -> HttpsOptions {
    HttpsOptions {
        max_streams: doh::DEFAULT_H3_MAX_STREAMS,
        ..HttpsOptions::default()
    }
}

impl Handler for Answering {
    fn tls(&self) -> Option<ServerTls> {
        Some(self.tls.clone())
    }
    fn https(&self) -> HttpsOptions {
        self.options.clone()
    }
    fn tcp_options(&self) -> TcpOptions {
        self.tcp
    }
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        assert_eq!(protocol, Protocol::Tcp);
        self.calls.fetch_add(1, Ordering::SeqCst);
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        self.running.fetch_sub(1, Ordering::SeqCst);
        if self.drop {
            return Action::Drop;
        }
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
        transport: Transport::Https3,
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

fn client_endpoint(alpn: &[u8]) -> Endpoint {
    let tls = client_config(&ClientOptions {
        ca: Some(fixture("ca.pem")),
        identity: None,
    })
    .unwrap();
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).unwrap(),
    )));
    endpoint
}

type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// An HTTP/3 client; the QUIC connection stays open while it lives.
struct Client {
    _endpoint: Endpoint,
    connection: Connection,
    sender: Sender,
}

impl Client {
    async fn new(address: SocketAddr) -> Self {
        let endpoint = client_endpoint(b"h3");
        let connection = timeout(
            TEST_TIMEOUT,
            endpoint.connect(address, "localhost").unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
        tokio::spawn(async move {
            driver.wait_idle().await;
        });
        Self {
            _endpoint: endpoint,
            connection,
            sender,
        }
    }

    async fn send(&mut self, request: Request<Vec<u8>>) -> (StatusCode, hyper::HeaderMap, Bytes) {
        send(&mut self.sender, request).await
    }
}

async fn send(
    sender: &mut Sender,
    request: Request<Vec<u8>>,
) -> (StatusCode, hyper::HeaderMap, Bytes) {
    let (parts, body) = request.into_parts();
    let mut stream = sender
        .send_request(Request::from_parts(parts, ()))
        .await
        .unwrap();
    // A rejected request may be answered before its body is sent in full.
    if !body.is_empty() {
        let _ = stream.send_data(Bytes::from(body)).await;
    }
    let _ = stream.finish().await;
    let response = timeout(TEST_TIMEOUT, stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    let mut body = Vec::new();
    while let Some(mut chunk) = timeout(TEST_TIMEOUT, stream.recv_data())
        .await
        .unwrap()
        .unwrap()
    {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    (response.status(), response.headers().clone(), body.into())
}

fn post(path: &str, body: Vec<u8>) -> Request<Vec<u8>> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("https://localhost{path}"))
        .header("content-type", doh::MEDIA_TYPE)
        .body(body)
        .unwrap()
}

fn get(target: &str) -> Request<Vec<u8>> {
    Request::builder()
        .uri(format!("https://localhost{target}"))
        .header("accept", doh::MEDIA_TYPE)
        .body(Vec::new())
        .unwrap()
}

fn encoded(wire: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(wire)
}

// RFC 8484 §4.1: both methods carry the Query; §4.2.2: the Response is application/dns-message.
#[tokio::test]
async fn get_and_post_are_answered_over_http3() {
    let (registry, address) = listening(Answering::new(options())).await;
    let mut client = Client::new(address).await;
    let wire = query(7);
    for request in [
        post(doh::PATH, wire.clone()),
        get(&format!("{}?dns={}", doh::PATH, encoded(&wire))),
    ] {
        let (status, headers, body) = client.send(request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], doh::MEDIA_TYPE);
        // RFC 8484 §5.1: freshness follows the lowest TTL.
        assert_eq!(headers["cache-control"], "max-age=300");
        assert_eq!(&body[..2], &7u16.to_be_bytes());
        assert_eq!(&body[2..4], &[0x81, 0x80]);
    }
    registry.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 server_https3.go ServeHTTP: the same status codes as server_https.go.
#[tokio::test]
async fn invalid_requests_get_the_coredns_status_codes() {
    let (registry, address) = listening(Answering::new(options())).await;
    let mut client = Client::new(address).await;
    let wire = query(1);
    let put = Request::builder()
        .method(Method::PUT)
        .uri(format!("https://localhost{}", doh::PATH))
        .body(wire.clone())
        .unwrap();
    let cases = [
        ("unknown path", post("/b10cada", wire.clone()), 404),
        ("other method", put, 400),
        ("garbage body", post(doh::PATH, vec![1, 2, 3]), 400),
        ("empty body", post(doh::PATH, Vec::new()), 400),
        ("oversized body", post(doh::PATH, vec![0; 65537]), 400),
        ("GET without dns", get(doh::PATH), 400),
        (
            "GET with padding",
            get(&format!("{}?dns=AAAB=", doh::PATH)),
            400,
        ),
        ("GET garbage", get(&format!("{}?dns=AAAB", doh::PATH)), 400),
    ];
    for (case, request, expected) in cases {
        let (status, headers, _) = client.send(request).await;
        assert_eq!(status.as_u16(), expected, "{case}");
        assert_eq!(
            headers["content-type"], "text/plain; charset=utf-8",
            "{case}"
        );
        assert_eq!(headers["x-content-type-options"], "nosniff", "{case}");
    }
    // A rejected request leaves the connection usable.
    let (status, ..) = client.send(post(doh::PATH, wire)).await;
    assert_eq!(status, StatusCode::OK);
    registry.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 server_https3.go ServeHTTP: a Query the Chain leaves unanswered is a 500 "No response".
#[tokio::test]
async fn dropped_query_is_a_500() {
    let mut handler = Answering::new(options());
    handler.drop = true;
    let (registry, address) = listening(handler).await;
    let mut client = Client::new(address).await;
    let (status, headers, body) = client.send(post(doh::PATH, query(1))).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(headers["content-type"], "text/plain; charset=utf-8");
    assert_eq!(&body[..], b"No response\n");
    registry.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 TestServerHTTPS3RejectsUpdate: an UPDATE never reaches the Plugin Chain.
#[tokio::test]
async fn update_is_rejected_before_the_handler() {
    let handler = Answering::new(options());
    let calls = Arc::clone(&handler.calls);
    let (registry, address) = listening(handler).await;
    let mut client = Client::new(address).await;
    let mut update = query(1);
    // RFC 2136 §2.1: opcode 5 is UPDATE.
    update[2] = 0x28;
    let (status, ..) = client.send(post(doh::PATH, update)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    registry.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 plugin/pkg/doh requestToMsgPost never reads Content-Type; only the body decides.
#[tokio::test]
async fn request_media_type_is_not_checked() {
    let (registry, address) = listening(Answering::new(options())).await;
    let mut client = Client::new(address).await;
    let mut request = post(doh::PATH, query(5));
    request
        .headers_mut()
        .insert("content-type", "text/plain".parse().unwrap());
    assert_eq!(client.send(request).await.0, StatusCode::OK);
    registry.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 core/dnsserver DefaultHTTPS3MaxHeaderBytes: header sections over 16 KiB are refused.
#[tokio::test]
async fn oversized_header_section_is_refused() {
    let handler = Answering::new(options());
    let calls = Arc::clone(&handler.calls);
    let (registry, address) = listening(handler).await;
    let mut client = Client::new(address).await;
    let mut request = post(doh::PATH, query(1));
    request
        .headers_mut()
        .insert("x-padding", "a".repeat(20 * 1024).parse().unwrap());
    let (parts, body) = request.into_parts();
    let outcome = async {
        let mut stream = client
            .sender
            .send_request(Request::from_parts(parts, ()))
            .await?;
        let _ = stream.send_data(Bytes::from(body)).await;
        let _ = stream.finish().await;
        stream.recv_response().await
    };
    // RFC 9114 §4.2.2: the server answers 431 or abandons the stream; it never runs the request.
    if let Ok(response) = timeout(TEST_TIMEOUT, outcome).await.unwrap() {
        assert_eq!(
            response.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut healthy = Client::new(address).await;
    assert_eq!(
        healthy.send(post(doh::PATH, query(2))).await.0,
        StatusCode::OK
    );
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn responses_are_counted_by_status() {
    let metrics = Registry::new("v", "rev", "rustc");
    let options = HttpsOptions {
        status: Some(Arc::new(Status::new(
            metrics.clone(),
            "https3",
            "https3://:443".into(),
        ))),
        ..options()
    };
    let (registry, address) = listening(Answering::new(options)).await;
    let mut client = Client::new(address).await;
    client.send(post(doh::PATH, query(1))).await;
    client.send(post(doh::PATH, query(2))).await;
    client.send(post("/nope", query(3))).await;
    let mut text = String::new();
    metrics.encode(&mut text);
    for expected in [
        "pharos_dns_https3_responses_total{server=\"https3://:443\",status=\"200\"} 2",
        "pharos_dns_https3_responses_total{server=\"https3://:443\",status=\"404\"} 1",
    ] {
        assert!(text.contains(expected), "{expected}\n{text}");
    }
    registry.shutdown().await.unwrap();
}

// RFC 9114 §3.1: HTTP/3 is selected by the ALPN token "h3" only.
#[tokio::test]
async fn other_alpn_is_rejected() {
    let (registry, address) = listening(Answering::new(options())).await;
    let endpoint = client_endpoint(b"doq");
    let result = timeout(
        TEST_TIMEOUT,
        endpoint.connect(address, "localhost").unwrap(),
    )
    .await
    .unwrap();
    assert!(result.is_err());
    registry.shutdown().await.unwrap();
}

// RFC 9000 §4.6: the stream credit a server grants bounds the Queries one connection runs at once.
#[tokio::test]
async fn max_streams_bounds_concurrent_queries_per_connection() {
    let mut handler = Answering::new(HttpsOptions {
        max_streams: 2,
        ..options()
    });
    handler.delay = Duration::from_millis(150);
    let peak = Arc::clone(&handler.peak);
    let (registry, address) = listening(handler).await;
    let client = Client::new(address).await;
    let mut tasks = Vec::new();
    for id in 0..6 {
        let mut sender = client.sender.clone();
        tasks.push(tokio::spawn(async move {
            send(&mut sender, post(doh::PATH, query(id))).await.0
        }));
    }
    for task in tasks {
        assert_eq!(
            timeout(TEST_TIMEOUT, task).await.unwrap().unwrap(),
            StatusCode::OK
        );
    }
    assert_eq!(peak.load(Ordering::SeqCst), 2);
    registry.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 core/dnsserver `https3 { max_streams 0 }`: the QUIC default instead of a Pharos limit.
#[tokio::test]
async fn zero_max_streams_keeps_the_quic_default() {
    let mut handler = Answering::new(HttpsOptions {
        max_streams: 0,
        ..options()
    });
    handler.delay = Duration::from_millis(100);
    let peak = Arc::clone(&handler.peak);
    let (registry, address) = listening(handler).await;
    let client = Client::new(address).await;
    let mut tasks = Vec::new();
    for id in 0..8 {
        let mut sender = client.sender.clone();
        tasks.push(tokio::spawn(async move {
            send(&mut sender, post(doh::PATH, query(id))).await.0
        }));
    }
    for task in tasks {
        assert_eq!(
            timeout(TEST_TIMEOUT, task).await.unwrap().unwrap(),
            StatusCode::OK
        );
    }
    assert!(peak.load(Ordering::SeqCst) > 2);
    registry.shutdown().await.unwrap();
}

async fn close_code(connection: &Connection) -> (u32, Vec<u8>) {
    match timeout(TEST_TIMEOUT, connection.closed()).await.unwrap() {
        ConnectionError::ApplicationClosed(close) => (
            u32::try_from(close.error_code.into_inner()).unwrap(),
            close.reason.to_vec(),
        ),
        other => panic!("expected an application close, got {other:?}"),
    }
}

// CoreDNS v1.15.0 TestServerHTTPS3MaxConnections: a connection over the limit is closed with H3_EXCESSIVE_LOAD.
#[tokio::test]
async fn connection_limit_closes_extra_connections() {
    let (registry, address) = listening(Answering::new(HttpsOptions {
        max_connections: 1,
        ..options()
    }))
    .await;
    let mut first = Client::new(address).await;
    assert_eq!(
        first.send(post(doh::PATH, query(1))).await.0,
        StatusCode::OK
    );
    let endpoint = client_endpoint(b"h3");
    let second = timeout(
        TEST_TIMEOUT,
        endpoint.connect(address, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    // RFC 9114 §8.1: H3_EXCESSIVE_LOAD is 0x107.
    let (code, reason) = close_code(&second).await;
    assert_eq!(
        (code, reason.as_slice()),
        (0x107, &b"too many connections"[..])
    );
    // The connection under the limit is unaffected.
    assert_eq!(
        first.send(post(doh::PATH, query(2))).await.0,
        StatusCode::OK
    );
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn zero_max_connections_removes_the_limit() {
    let (registry, address) = listening(Answering::new(HttpsOptions {
        max_connections: 0,
        ..options()
    }))
    .await;
    let mut held = Vec::new();
    for id in 0..3 {
        let mut client = Client::new(address).await;
        assert_eq!(
            client.send(post(doh::PATH, query(id))).await.0,
            StatusCode::OK
        );
        held.push(client);
    }
    registry.shutdown().await.unwrap();
}

// RFC 9114 §5.2: shutdown sends GOAWAY, finishes accepted requests, then closes with H3_NO_ERROR.
#[tokio::test]
async fn shutdown_finishes_in_flight_queries() {
    let mut handler = Answering::new(options());
    handler.delay = Duration::from_millis(300);
    let calls = Arc::clone(&handler.calls);
    let (registry, address) = listening(handler).await;
    let client = Client::new(address).await;
    let pending = {
        let mut sender = client.sender.clone();
        tokio::spawn(async move { send(&mut sender, post(doh::PATH, query(1))).await.0 })
    };
    while calls.load(Ordering::SeqCst) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    registry.shutdown().await.unwrap();
    assert_eq!(pending.await.unwrap(), StatusCode::OK);
    // RFC 9114 §8.1: H3_NO_ERROR is 0x100.
    assert_eq!(close_code(&client.connection).await.0, 0x100);
}

// A stream that never delivers its headers is abandoned after the read timeout, not held open.
#[tokio::test]
async fn stalled_request_is_abandoned_after_the_read_timeout() {
    let mut handler = Answering::new(options());
    handler.tcp.read = Duration::from_millis(300);
    handler.tcp.idle = Duration::from_secs(30);
    let (registry, address) = listening(handler).await;
    let client = Client::new(address).await;
    // RFC 9114 §7.2.2: a request stream that starts a HEADERS frame (type 0x01) and never completes it.
    let (mut send, mut recv) = client.connection.open_bi().await.unwrap();
    send.write_all(&[0x01]).await.unwrap();
    let outcome = timeout(Duration::from_secs(3), recv.read_to_end(1024)).await;
    assert!(outcome.is_ok(), "stalled stream stayed open");
    let mut healthy = client;
    assert_eq!(
        healthy.send(post(doh::PATH, query(1))).await.0,
        StatusCode::OK
    );
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn https3_listener_has_no_tcp_workers() {
    let (registry, address) = listening(Answering::new(options())).await;
    assert!(
        tokio::net::TcpStream::connect(address).await.is_err(),
        "HTTP/3 Listener must not accept TCP"
    );
    registry.shutdown().await.unwrap();
}
