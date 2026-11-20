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

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, StatusCode,
    client::conn::{http1, http2},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{
    Action, Handler, HttpsOptions, ListenerKey, ListenerRegistry, Protocol, Transport,
    doh::{self, Status},
    metrics::Registry,
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

/// Answers every Query with one A record of TTL 300, after an optional delay.
struct Answering {
    tls: ServerTls,
    options: HttpsOptions,
    delay: Duration,
    running: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl Answering {
    fn new(options: HttpsOptions) -> Self {
        let tls = ServerTls::load(&ServerOptions {
            cert: fixture("server.pem"),
            key: fixture("server.key.pem"),
            ca: None,
            client_auth: ClientAuth::NoCert,
            keylog: None,
        })
        .unwrap()
        .with_alpn(doh::ALPN);
        Self {
            tls,
            options,
            delay: Duration::ZERO,
            running: Arc::default(),
            peak: Arc::default(),
        }
    }
}

impl Handler for Answering {
    fn tls(&self) -> Option<ServerTls> {
        Some(self.tls.clone())
    }
    fn https(&self) -> HttpsOptions {
        self.options.clone()
    }
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        assert_eq!(protocol, Protocol::Tcp);
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
        transport: Transport::Https,
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
) -> tokio_rustls::client::TlsStream<TcpStream> {
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
        .unwrap()
}

/// A client that speaks whichever HTTP version the handshake selected.
enum Client {
    H1(http1::SendRequest<Full<Bytes>>),
    H2(http2::SendRequest<Full<Bytes>>),
}

impl Client {
    async fn new(address: SocketAddr, alpn: &[&[u8]]) -> Self {
        let tls = tls_connect(address, alpn).await;
        let selected = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let io = TokioIo::new(tls);
        if selected.as_deref() == Some(b"h2") {
            let (sender, connection) = http2::handshake(TokioExecutor::new(), io).await.unwrap();
            tokio::spawn(connection);
            Self::H2(sender)
        } else {
            let (sender, connection) = http1::handshake(io).await.unwrap();
            tokio::spawn(connection);
            Self::H1(sender)
        }
    }

    async fn send(
        &mut self,
        request: Request<Full<Bytes>>,
    ) -> (StatusCode, hyper::HeaderMap, Bytes) {
        let response = match self {
            Self::H1(sender) => timeout(TEST_TIMEOUT, sender.send_request(request)).await,
            Self::H2(sender) => timeout(TEST_TIMEOUT, sender.send_request(request)).await,
        }
        .unwrap()
        .unwrap();
        let (parts, body) = response.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        (parts.status, parts.headers, body)
    }
}

fn post(path: &str, body: Vec<u8>) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("https://localhost{path}"))
        .header("content-type", doh::MEDIA_TYPE)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn get(target: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(format!("https://localhost{target}"))
        .header("accept", doh::MEDIA_TYPE)
        .body(Full::default())
        .unwrap()
}

fn encoded(wire: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(wire)
}

const VERSIONS: [(&str, &[&[u8]]); 2] =
    [("h2", &[b"h2", b"http/1.1"]), ("http/1.1", &[b"http/1.1"])];

// RFC 8484 §4.1: both methods carry the Query; §4.2.2: the Response is application/dns-message.
#[tokio::test]
async fn get_and_post_are_answered_over_http2_and_http1() {
    let (registry, address) = listening(Answering::new(HttpsOptions::default())).await;
    for (name, alpn) in VERSIONS {
        let mut client = Client::new(address, alpn).await;
        let wire = query(7);
        for request in [
            post(doh::PATH, wire.clone()),
            get(&format!("{}?dns={}", doh::PATH, encoded(&wire))),
        ] {
            let (status, headers, body) = client.send(request).await;
            assert_eq!(status, StatusCode::OK, "{name}");
            assert_eq!(headers["content-type"], doh::MEDIA_TYPE, "{name}");
            // RFC 8484 §5.1: freshness follows the lowest TTL.
            assert_eq!(headers["cache-control"], "max-age=300", "{name}");
            assert_eq!(&body[..2], &7u16.to_be_bytes(), "{name}");
            assert_eq!(&body[2..4], &[0x81, 0x80], "{name}");
        }
    }
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_requests_get_the_coredns_status_codes() {
    let (registry, address) = listening(Answering::new(HttpsOptions::default())).await;
    let wire = query(1);
    for (name, alpn) in VERSIONS {
        let mut client = Client::new(address, alpn).await;
        let put = Request::builder()
            .method(Method::PUT)
            .uri(format!("https://localhost{}", doh::PATH))
            .body(Full::new(Bytes::from(wire.clone())))
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
            assert_eq!(status.as_u16(), expected, "{name} {case}");
            assert_eq!(
                headers["content-type"], "text/plain; charset=utf-8",
                "{name} {case}"
            );
        }
        // A rejected request leaves the connection usable.
        let (status, ..) = client.send(post(doh::PATH, wire.clone())).await;
        assert_eq!(status, StatusCode::OK, "{name}");
    }
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn responses_are_counted_by_status() {
    let metrics = Registry::new("v", "rev", "rustc");
    let options = HttpsOptions {
        status: Some(Arc::new(Status::new(
            metrics.clone(),
            "https",
            "https://:443".into(),
        ))),
        ..HttpsOptions::default()
    };
    let (registry, address) = listening(Answering::new(options)).await;
    let mut client = Client::new(address, &[b"h2"]).await;
    client.send(post(doh::PATH, query(1))).await;
    client.send(post(doh::PATH, query(2))).await;
    client.send(post("/nope", query(3))).await;
    let mut text = String::new();
    metrics.encode(&mut text);
    for expected in [
        "pharos_dns_https_responses_total{server=\"https://:443\",status=\"200\"} 2",
        "pharos_dns_https_responses_total{server=\"https://:443\",status=\"404\"} 1",
    ] {
        assert!(text.contains(expected), "{expected}\n{text}");
    }
    registry.shutdown().await.unwrap();
}

// RFC 9113 §6.5.2: SETTINGS_MAX_CONCURRENT_STREAMS bounds the Queries one connection runs at once.
#[tokio::test]
async fn max_streams_bounds_concurrent_queries_per_connection() {
    let mut handler = Answering::new(HttpsOptions {
        max_streams: 2,
        ..HttpsOptions::default()
    });
    handler.delay = Duration::from_millis(150);
    let peak = Arc::clone(&handler.peak);
    let (registry, address) = listening(handler).await;
    let Client::H2(sender) = Client::new(address, &[b"h2"]).await else {
        panic!("h2 expected");
    };
    // The server's SETTINGS must reach the client before it opens streams in a burst.
    let mut warm = sender.clone();
    warm.ready().await.unwrap();
    warm.send_request(post(doh::PATH, query(99))).await.unwrap();
    peak.store(0, Ordering::SeqCst);
    let mut tasks = Vec::new();
    for id in 0..6 {
        let mut sender = sender.clone();
        tasks.push(tokio::spawn(async move {
            sender.ready().await.unwrap();
            let response = sender
                .send_request(post(doh::PATH, query(id)))
                .await
                .unwrap();
            response.status()
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

// CoreDNS v1.15.0 core/dnsserver/server_https.go Listen: netutil.LimitListener caps live connections.
#[tokio::test]
async fn max_connections_holds_back_further_connections() {
    let (registry, address) = listening(Answering::new(HttpsOptions {
        max_connections: 1,
        ..HttpsOptions::default()
    }))
    .await;
    let mut first = Client::new(address, &[b"h2"]).await;
    assert_eq!(
        first.send(post(doh::PATH, query(1))).await.0,
        StatusCode::OK
    );
    let blocked = timeout(Duration::from_millis(500), Client::new(address, &[b"h2"])).await;
    assert!(blocked.is_err(), "second connection was served");
    drop(first);
    let mut second = timeout(TEST_TIMEOUT, Client::new(address, &[b"h2"]))
        .await
        .unwrap();
    assert_eq!(
        second.send(post(doh::PATH, query(2))).await.0,
        StatusCode::OK
    );
    registry.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 plugin/pkg/doh requestToMsgPost never reads Content-Type; only the body decides.
#[tokio::test]
async fn request_media_type_is_not_checked() {
    let (registry, address) = listening(Answering::new(HttpsOptions::default())).await;
    let mut client = Client::new(address, &[b"h2"]).await;
    let mut request = post(doh::PATH, query(5));
    request
        .headers_mut()
        .insert("content-type", "text/plain".parse().unwrap());
    assert_eq!(client.send(request).await.0, StatusCode::OK);
    let mut request = post(doh::PATH, b"not dns".to_vec());
    request
        .headers_mut()
        .insert("content-type", doh::MEDIA_TYPE.parse().unwrap());
    assert_eq!(client.send(request).await.0, StatusCode::BAD_REQUEST);
    registry.shutdown().await.unwrap();
}
