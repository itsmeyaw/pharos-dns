#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{Method, Request, StatusCode, client::conn::http2};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::{
    Action, Handler, HttpsOptions, ListenerKey, ListenerRegistry, Protocol, Transport, doh, grpc,
    proxyproto::{Config, Policy},
    tls::{ClientAuth, ClientOptions, ServerOptions, ServerTls, TlsConnector, client_config},
};
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT: &str = "192.0.2.1:12345";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/tls")
        .join(name)
}

fn identity() -> ServerTls {
    ServerTls::load(&ServerOptions {
        cert: fixture("server.pem"),
        key: fixture("server.key.pem"),
        ca: None,
        client_auth: ClientAuth::NoCert,
        keylog: None,
    })
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

type Seen = Arc<Mutex<Vec<(SocketAddr, String)>>>;

/// Records the peer address and TLV hex the Listener reported for every Query, then answers it.
struct Probe {
    tls: ServerTls,
    config: Arc<Config>,
    https: HttpsOptions,
    seen: Seen,
}

impl Probe {
    fn new(tls: ServerTls, config: Config) -> (Self, Seen) {
        let seen = Seen::default();
        let probe = Self {
            tls,
            config: Arc::new(config),
            https: HttpsOptions::default(),
            seen: Arc::clone(&seen),
        };
        (probe, seen)
    }
}

impl Handler for Probe {
    fn tls(&self) -> Option<ServerTls> {
        Some(self.tls.clone())
    }
    fn https(&self) -> HttpsOptions {
        self.https.clone()
    }
    fn proxyproto(&self) -> Option<Arc<Config>> {
        Some(Arc::clone(&self.config))
    }
    async fn handle(
        &self,
        query: &[u8],
        peer: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        self.answer(query, peer, "", response)
    }
    async fn handle_proxied(
        self: &Arc<Self>,
        query: &[u8],
        peer: SocketAddr,
        _: Protocol,
        tlv: &str,
        response: &mut Vec<u8>,
    ) -> Action {
        self.answer(query, peer, tlv, response)
    }
}

impl Probe {
    fn answer(&self, query: &[u8], peer: SocketAddr, tlv: &str, response: &mut Vec<u8>) -> Action {
        self.seen.lock().unwrap().push((peer, tlv.to_owned()));
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

fn config(policy: Policy) -> Config {
    let mut config = Config::new(move |_| policy);
    config.header_timeout = Duration::from_millis(300);
    config.tlv_metadata = true;
    config
}

// PROXY protocol §2.2: a PROXY command header for IPv4; `family` 0x11 is STREAM, 0x12 DGRAM.
fn v2(family: u8, tlvs: &[u8]) -> Vec<u8> {
    let mut wire = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    wire.extend([0x21, family]);
    wire.extend(u16::try_from(12 + tlvs.len()).unwrap().to_be_bytes());
    wire.extend([192, 0, 2, 1, 192, 0, 2, 53]);
    wire.extend(12345u16.to_be_bytes());
    wire.extend(53u16.to_be_bytes());
    wire.extend(tlvs);
    wire
}

// PROXY protocol §2.2.7: one custom TLV (type 0xEA, one octet); its hex is `ea000107`.
const TLV: [u8; 4] = [0xEA, 0, 1, 7];

async fn listening(transport: Transport, handler: Probe) -> (ListenerRegistry, SocketAddr) {
    let key = ListenerKey {
        transport,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let mut registry = ListenerRegistry::default();
    registry
        .apply(HashMap::from([(key, handler)]))
        .await
        .unwrap();
    let address = registry.get(&key).unwrap().local_addr();
    (registry, address)
}

fn tls_client(alpn: &[&[u8]]) -> TlsConnector {
    let mut config = (*client_config(&ClientOptions {
        ca: Some(fixture("ca.pem")),
        identity: None,
    })
    .unwrap())
    .clone();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    TlsConnector::from(Arc::new(config))
}

/// Open a TCP connection that sends `prefix` before the TLS handshake.
async fn prefixed(address: SocketAddr, prefix: &[u8]) -> TcpStream {
    let mut tcp = TcpStream::connect(address).await.unwrap();
    tcp.write_all(prefix).await.unwrap();
    tcp
}

async fn http2_client<B>(tcp: TcpStream, alpn: &[&[u8]]) -> http2::SendRequest<B>
where
    B: hyper::body::Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let tls = tls_client(alpn)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let (sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(connection);
    sender
}

fn doh_post(wire: Vec<u8>) -> Request<Full<Bytes>> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("https://localhost{}", doh::PATH))
        .header("content-type", doh::MEDIA_TYPE)
        .body(Full::new(Bytes::from(wire)))
        .unwrap()
}

async fn doh_exchange(sender: &mut http2::SendRequest<Full<Bytes>>, id: u16) -> StatusCode {
    sender.ready().await.unwrap();
    let response = timeout(TEST_TIMEOUT, sender.send_request(doh_post(query(id))))
        .await
        .unwrap()
        .unwrap();
    let status = response.status();
    let _ = response.into_body().collect().await.unwrap();
    status
}

// PROXY protocol §2: the header precedes the TLS ClientHello of an `https://` connection.
#[tokio::test]
async fn https_header_before_the_handshake_sets_the_peer_and_tlv_of_every_request() {
    let (probe, seen) = Probe::new(identity().with_alpn(doh::ALPN), config(Policy::Use));
    let (registry, address) = listening(Transport::Https, probe).await;
    let tcp = prefixed(address, &v2(0x11, &TLV)).await;
    let mut sender = http2_client(tcp, doh::ALPN).await;
    assert_eq!(doh_exchange(&mut sender, 1).await, StatusCode::OK);
    assert_eq!(doh_exchange(&mut sender, 2).await, StatusCode::OK);
    let expected = (CLIENT.parse().unwrap(), "ea000107".to_owned());
    assert_eq!(*seen.lock().unwrap(), [expected.clone(), expected]);
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn https_v1_header_sets_the_peer() {
    let (probe, seen) = Probe::new(identity().with_alpn(doh::ALPN), config(Policy::Use));
    let (registry, address) = listening(Transport::Https, probe).await;
    let tcp = prefixed(address, b"PROXY TCP4 192.0.2.1 192.0.2.53 12345 53\r\n").await;
    let mut sender = http2_client(tcp, doh::ALPN).await;
    assert_eq!(doh_exchange(&mut sender, 1).await, StatusCode::OK);
    assert_eq!(
        *seen.lock().unwrap(),
        [(CLIENT.parse().unwrap(), String::new())]
    );
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn https_without_a_header_keeps_the_real_peer_under_use() {
    let (probe, seen) = Probe::new(identity().with_alpn(doh::ALPN), config(Policy::Use));
    let (registry, address) = listening(Transport::Https, probe).await;
    let tcp = TcpStream::connect(address).await.unwrap();
    let local = tcp.local_addr().unwrap();
    let mut sender = http2_client(tcp, doh::ALPN).await;
    assert_eq!(doh_exchange(&mut sender, 1).await, StatusCode::OK);
    assert_eq!(*seen.lock().unwrap(), [(local, String::new())]);
    registry.shutdown().await.unwrap();
}

// go-proxyproto REJECT: a connection that sends a header is closed before the handshake.
#[tokio::test]
async fn https_reject_policy_closes_a_connection_with_a_header() {
    let (probe, seen) = Probe::new(identity().with_alpn(doh::ALPN), config(Policy::Reject));
    let (registry, address) = listening(Transport::Https, probe).await;
    let tcp = prefixed(address, &v2(0x11, &[])).await;
    let tls = tls_client(doh::ALPN)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await;
    assert!(tls.is_err());
    assert!(seen.lock().unwrap().is_empty());
    registry.shutdown().await.unwrap();
}

// go-proxyproto ReadHeaderTimeout: a header that never completes closes the connection.
#[tokio::test]
async fn https_truncated_header_is_closed_after_the_header_timeout() {
    let (probe, seen) = Probe::new(identity().with_alpn(doh::ALPN), config(Policy::Use));
    let (registry, address) = listening(Transport::Https, probe).await;
    let mut tcp = prefixed(address, &v2(0x11, &TLV)[..10]).await;
    let closed = timeout(TEST_TIMEOUT, tcp.read(&mut [0; 1])).await.unwrap();
    assert!(matches!(closed, Ok(0) | Err(_)));
    assert!(seen.lock().unwrap().is_empty());
    registry.shutdown().await.unwrap();
}

type Payload = BoxBody<Bytes, Infallible>;

fn grpc_call(message: &[u8]) -> Request<Payload> {
    let mut body = Vec::new();
    let mut prefix = grpc::FramePrefix::new(message.len());
    while prefix.has_remaining() {
        let count = prefix.chunk().len();
        body.extend_from_slice(prefix.chunk());
        prefix.advance(count);
    }
    body.extend_from_slice(message);
    Request::builder()
        .method(Method::POST)
        .uri(format!("https://localhost{}", grpc::PATH))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Full::new(Bytes::from(body)).boxed())
        .unwrap()
}

async fn grpc_exchange(sender: &mut http2::SendRequest<Payload>, id: u16) -> hyper::HeaderMap {
    sender.ready().await.unwrap();
    let response = timeout(TEST_TIMEOUT, sender.send_request(grpc_call(&query(id))))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let collected = response.into_body().collect().await.unwrap();
    collected.trailers().cloned().unwrap_or_default()
}

// PROXY protocol §2: the header precedes the TLS ClientHello of a `grpc://` connection.
#[tokio::test]
async fn grpc_header_before_the_handshake_sets_the_peer_and_tlv_of_every_call() {
    let (probe, seen) = Probe::new(identity().with_alpn(grpc::ALPN), config(Policy::Use));
    let (registry, address) = listening(Transport::Grpc, probe).await;
    let tcp = prefixed(address, &v2(0x11, &TLV)).await;
    let mut sender = http2_client(tcp, grpc::ALPN).await;
    for id in [1, 2] {
        let trailers = grpc_exchange(&mut sender, id).await;
        assert_eq!(trailers["grpc-status"], "0");
    }
    let expected = (CLIENT.parse().unwrap(), "ea000107".to_owned());
    assert_eq!(*seen.lock().unwrap(), [expected.clone(), expected]);
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn grpc_without_a_header_keeps_the_real_peer_under_use() {
    let (probe, seen) = Probe::new(identity().with_alpn(grpc::ALPN), config(Policy::Use));
    let (registry, address) = listening(Transport::Grpc, probe).await;
    let tcp = TcpStream::connect(address).await.unwrap();
    let local = tcp.local_addr().unwrap();
    let mut sender = http2_client(tcp, grpc::ALPN).await;
    let trailers = grpc_exchange(&mut sender, 1).await;
    assert_eq!(trailers["grpc-status"], "0");
    assert_eq!(*seen.lock().unwrap(), [(local, String::new())]);
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn grpc_reject_policy_closes_a_connection_with_a_header() {
    let (probe, seen) = Probe::new(identity().with_alpn(grpc::ALPN), config(Policy::Reject));
    let (registry, address) = listening(Transport::Grpc, probe).await;
    let tcp = prefixed(address, &v2(0x11, &[])).await;
    let tls = tls_client(grpc::ALPN)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await;
    assert!(tls.is_err());
    assert!(seen.lock().unwrap().is_empty());
    registry.shutdown().await.unwrap();
}
