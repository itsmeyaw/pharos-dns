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
    proxyproto::{Config, Policy, UdpTracking},
    tls::{ClientAuth, ClientOptions, ServerOptions, ServerTls, TlsConnector, client_config},
};
use quinn::{ClientConfig, Connection, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
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

fn tracking() -> Config {
    let mut config = config(Policy::Use);
    config.udp_tracking = Some(UdpTracking {
        ttl: Duration::from_secs(30),
        max_sessions: 100,
    });
    config
}

/// How the relay presents the client's datagrams to the Listener.
#[derive(Clone, Copy)]
enum Relay {
    /// Every datagram carries its own PROXY v2 header.
    Every,
    /// One header-only datagram opens the flow, as Cloudflare Spectrum does.
    Spectrum,
}

/// A UDP relay in front of `server`: returns the address clients send to and the address the Listener sees.
async fn relay(server: SocketAddr, mode: Relay) -> (SocketAddr, SocketAddr) {
    let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let back = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    back.connect(server).await.unwrap();
    let addresses = (front.local_addr().unwrap(), back.local_addr().unwrap());
    let header = v2(0x12, &TLV);
    tokio::spawn(async move {
        let (mut inbound, mut outbound) = (vec![0; 65535], vec![0; 65535]);
        let (mut client, mut opened) = (None, false);
        loop {
            tokio::select! {
                received = front.recv_from(&mut inbound) => {
                    let (length, from) = received.unwrap();
                    client = Some(from);
                    let mut wire = Vec::new();
                    match mode {
                        Relay::Every => wire.extend(&header),
                        Relay::Spectrum if !opened => {
                            opened = true;
                            back.send(&header).await.unwrap();
                        }
                        Relay::Spectrum => {}
                    }
                    wire.extend(&inbound[..length]);
                    back.send(&wire).await.unwrap();
                }
                received = back.recv(&mut outbound) => {
                    let length = received.unwrap();
                    if let Some(client) = client {
                        front.send_to(&outbound[..length], client).await.unwrap();
                    }
                }
            }
        }
    });
    addresses
}

fn quic_client(alpn: &[u8]) -> Endpoint {
    let mut tls = (*client_config(&ClientOptions {
        ca: Some(fixture("ca.pem")),
        identity: None,
    })
    .unwrap())
    .clone();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).unwrap(),
    )));
    endpoint
}

async fn quic_connect(alpn: &[u8], address: SocketAddr) -> (Endpoint, Connection) {
    let endpoint = quic_client(alpn);
    let connection = timeout(
        TEST_TIMEOUT,
        endpoint.connect(address, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    (endpoint, connection)
}

// RFC 9250 §4.2: the Query is length-prefixed and the stream ends with FIN.
async fn doq_exchange(connection: &Connection) {
    let message = query(0);
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let mut wire = u16::try_from(message.len()).unwrap().to_be_bytes().to_vec();
    wire.extend(&message);
    send.write_all(&wire).await.unwrap();
    send.finish().unwrap();
    let response = timeout(TEST_TIMEOUT, recv.read_to_end(70_000))
        .await
        .unwrap()
        .unwrap();
    assert!(response.len() > 2);
}

fn doq_probe(config: Config) -> (Probe, Seen) {
    Probe::new(identity(), config)
}

fn expected() -> Vec<(SocketAddr, String)> {
    vec![(CLIENT.parse().unwrap(), "ea000107".to_owned()); 2]
}

// CoreDNS v1.15.0 plugin/proxyproto README: with udp_session_tracking the header-only first datagram
// ahead of the QUIC handshake links the later headerless datagrams to the client and its TLVs.
#[tokio::test]
async fn quic_session_tracking_links_the_handshake_to_the_header_only_datagram() {
    let (probe, seen) = doq_probe(tracking());
    let (registry, address) = listening(Transport::Quic, probe).await;
    let (front, _) = relay(address, Relay::Spectrum).await;
    let (_endpoint, connection) = quic_connect(b"doq", front).await;
    doq_exchange(&connection).await;
    doq_exchange(&connection).await;
    assert_eq!(*seen.lock().unwrap(), expected());
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn quic_header_on_every_datagram_sets_the_peer_and_tlv() {
    let (probe, seen) = doq_probe(config(Policy::Use));
    let (registry, address) = listening(Transport::Quic, probe).await;
    let (front, _) = relay(address, Relay::Every).await;
    let (_endpoint, connection) = quic_connect(b"doq", front).await;
    doq_exchange(&connection).await;
    doq_exchange(&connection).await;
    assert_eq!(*seen.lock().unwrap(), expected());
    registry.shutdown().await.unwrap();
}

// A header-only datagram is dropped without session tracking, so the flow keeps the relay's address.
#[tokio::test]
async fn quic_without_session_tracking_keeps_the_proxy_address() {
    let (probe, seen) = doq_probe(config(Policy::Use));
    let (registry, address) = listening(Transport::Quic, probe).await;
    let (front, back) = relay(address, Relay::Spectrum).await;
    let (_endpoint, connection) = quic_connect(b"doq", front).await;
    doq_exchange(&connection).await;
    assert_eq!(*seen.lock().unwrap(), [(back, String::new())]);
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn quic_client_without_a_header_keeps_its_address_under_use() {
    let (probe, seen) = doq_probe(tracking());
    let (registry, address) = listening(Transport::Quic, probe).await;
    let (endpoint, connection) = quic_connect(b"doq", address).await;
    doq_exchange(&connection).await;
    assert_eq!(
        *seen.lock().unwrap(),
        [(endpoint.local_addr().unwrap(), String::new())]
    );
    registry.shutdown().await.unwrap();
}

// go-proxyproto REJECT: a datagram with a header is dropped, so the handshake never completes.
#[tokio::test]
async fn quic_reject_policy_drops_datagrams_with_a_header() {
    let (probe, seen) = doq_probe(config(Policy::Reject));
    let (registry, address) = listening(Transport::Quic, probe).await;
    let (front, _) = relay(address, Relay::Every).await;
    let endpoint = quic_client(b"doq");
    let connecting = endpoint.connect(front, "localhost").unwrap();
    assert!(timeout(Duration::from_secs(1), connecting).await.is_err());
    assert!(seen.lock().unwrap().is_empty());
    registry.shutdown().await.unwrap();
}

fn h3_probe(config: Config) -> (Probe, Seen) {
    let tls = identity().with_quic_alpn(doh::H3_ALPN).unwrap();
    let (mut probe, seen) = Probe::new(tls, config);
    probe.https.max_streams = doh::DEFAULT_H3_MAX_STREAMS;
    (probe, seen)
}

async fn h3_exchange(address: SocketAddr) -> (Endpoint, Connection) {
    let (endpoint, connection) = quic_connect(b"h3", address).await;
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
        .await
        .unwrap();
    tokio::spawn(async move {
        driver.wait_idle().await;
    });
    for id in [1, 2] {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("https://localhost{}", doh::PATH))
            .header("content-type", doh::MEDIA_TYPE)
            .body(())
            .unwrap();
        let mut stream = sender.send_request(request).await.unwrap();
        stream.send_data(Bytes::from(query(id))).await.unwrap();
        stream.finish().await.unwrap();
        let response = timeout(TEST_TIMEOUT, stream.recv_response())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        while timeout(TEST_TIMEOUT, stream.recv_data())
            .await
            .unwrap()
            .unwrap()
            .is_some()
        {}
    }
    (endpoint, connection)
}

#[tokio::test]
async fn https3_session_tracking_links_the_handshake_to_the_header_only_datagram() {
    let (probe, seen) = h3_probe(tracking());
    let (registry, address) = listening(Transport::Https3, probe).await;
    let (front, _) = relay(address, Relay::Spectrum).await;
    let _client = h3_exchange(front).await;
    assert_eq!(*seen.lock().unwrap(), expected());
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn https3_header_on_every_datagram_sets_the_peer_and_tlv() {
    let (probe, seen) = h3_probe(config(Policy::Use));
    let (registry, address) = listening(Transport::Https3, probe).await;
    let (front, _) = relay(address, Relay::Every).await;
    let _client = h3_exchange(front).await;
    assert_eq!(*seen.lock().unwrap(), expected());
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn https3_client_without_a_header_keeps_its_address_under_use() {
    let (probe, seen) = h3_probe(tracking());
    let (registry, address) = listening(Transport::Https3, probe).await;
    let (endpoint, _connection) = h3_exchange(address).await;
    let local = endpoint.local_addr().unwrap();
    assert_eq!(
        *seen.lock().unwrap(),
        [(local, String::new()), (local, String::new())]
    );
    registry.shutdown().await.unwrap();
}
