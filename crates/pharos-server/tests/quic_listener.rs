#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use pharos_server::{
    Action, Handler, ListenerKey, ListenerRegistry, Protocol, QuicMetrics, QuicOptions, TcpOptions,
    Transport,
    metrics::Registry,
    tls::{ClientAuth, ClientOptions, ServerOptions, ServerTls, client_config},
};
use quinn::{
    ClientConfig, Connection, ConnectionError, Endpoint, VarInt, crypto::rustls::QuicClientConfig,
};
use tokio::{sync::Notify, time::timeout};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const SERVER: &str = "quic://127.0.0.1:0";

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
}

/// Echoes every Query, optionally holding it until `gate` opens.
struct Doq {
    tls: ServerTls,
    tcp: TcpOptions,
    quic: QuicOptions,
    metrics: Option<QuicMetrics>,
    gate: Option<Arc<Notify>>,
    delay: Duration,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl Doq {
    fn new(registry: &Registry) -> Self {
        Self {
            tls: identity("server"),
            tcp: TcpOptions::default(),
            quic: QuicOptions::default(),
            metrics: Some(QuicMetrics::new(registry, SERVER)),
            gate: None,
            delay: Duration::ZERO,
            calls: Arc::default(),
        }
    }
}

impl Handler for Doq {
    fn tls(&self) -> Option<ServerTls> {
        Some(self.tls.clone())
    }
    fn tcp_options(&self) -> TcpOptions {
        self.tcp
    }
    fn quic_options(&self) -> QuicOptions {
        self.quic
    }
    fn quic_metrics(&self) -> Option<QuicMetrics> {
        self.metrics.clone()
    }
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        assert_eq!(protocol, Protocol::Tcp);
        self.calls.fetch_add(1, Ordering::Relaxed);
        if let Some(gate) = &self.gate {
            gate.notified().await;
        }
        tokio::time::sleep(self.delay).await;
        response.extend_from_slice(query);
        Action::Respond
    }
}

fn key() -> ListenerKey {
    ListenerKey {
        transport: Transport::Quic,
        address: "127.0.0.1:0".parse().unwrap(),
    }
}

async fn listening(handler: Doq) -> (ListenerRegistry, SocketAddr) {
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

async fn connect(address: SocketAddr) -> (Endpoint, Connection) {
    let endpoint = client_endpoint(b"doq");
    let connection = timeout(
        TEST_TIMEOUT,
        endpoint.connect(address, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    (endpoint, connection)
}

/// A QUERY for `example.com. A` with the given Message ID and EDNS option bytes.
fn query(id: u16, option: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    wire.extend_from_slice(&id.to_be_bytes());
    wire.extend_from_slice(&[
        0x01,
        0x00,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        u8::from(!option.is_empty()),
    ]);
    wire.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
    if !option.is_empty() {
        // RFC 6891 §6.1.2: root-owned OPT with a 1232-octet payload size and one option.
        wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0]);
        wire.extend_from_slice(&u16::try_from(option.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(option);
    }
    wire
}

// RFC 9250 §4.2: the Query is length-prefixed and the stream ends with FIN.
fn frame(message: &[u8]) -> Vec<u8> {
    let mut wire = u16::try_from(message.len()).unwrap().to_be_bytes().to_vec();
    wire.extend_from_slice(message);
    wire
}

async fn exchange(connection: &Connection, message: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    send.write_all(&frame(message)).await.unwrap();
    send.finish().unwrap();
    let response = timeout(TEST_TIMEOUT, recv.read_to_end(70_000))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        usize::from(u16::from_be_bytes([response[0], response[1]])),
        response.len() - 2
    );
    response[2..].to_vec()
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

fn counter(registry: &Registry, status: &str) -> String {
    let mut out = String::new();
    registry.encode(&mut out);
    let prefix =
        format!("pharos_dns_quic_responses_total{{server=\"{SERVER}\",status=\"{status}\"}} ");
    out.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or("0")
        .to_owned()
}

// RFC 9250 §4.2: one Query per stream; several streams share a connection.
#[tokio::test]
async fn answers_queries_on_separate_streams() {
    let registry = Registry::default();
    let (listeners, address) = listening(Doq::new(&registry)).await;
    let (_endpoint, connection) = connect(address).await;
    let first = query(0, &[]);
    assert_eq!(exchange(&connection, &first).await, first);
    assert_eq!(exchange(&connection, &first).await, first);
    assert_eq!(counter(&registry, "0x0"), "2");
    listeners.shutdown().await.unwrap();
}

// RFC 9250 §4.1.1: the ALPN token is "doq".
#[tokio::test]
async fn other_alpn_is_rejected() {
    let (listeners, address) = listening(Doq::new(&Registry::default())).await;
    let endpoint = client_endpoint(b"h3");
    let result = timeout(
        TEST_TIMEOUT,
        endpoint.connect(address, "localhost").unwrap(),
    )
    .await
    .unwrap();
    assert!(result.is_err());
    listeners.shutdown().await.unwrap();
}

// RFC 9250 §4.3.3: these Messages are protocol errors that abort the connection with code 2.
#[tokio::test]
async fn protocol_errors_close_the_connection_with_code_two() {
    // RFC 7828 §3.2.1 edns-tcp-keepalive is option code 11.
    let keepalive = query(0, &[0, 11, 0, 0]);
    for (name, wire) in [
        ("non-zero ID", frame(&query(7, &[]))),
        ("edns-tcp-keepalive", frame(&keepalive)),
        ("malformed Message", frame(b"not dns at all")),
        ("zero length (DoQ draft)", vec![0, 0]),
        ("Message without length prefix", query(0, &[])),
        ("data after the Message", {
            let mut wire = frame(&query(0, &[]));
            wire.push(0);
            wire
        }),
    ] {
        let registry = Registry::default();
        let handler = Doq::new(&registry);
        let calls = Arc::clone(&handler.calls);
        let (listeners, address) = listening(handler).await;
        let (_endpoint, connection) = connect(address).await;
        let (mut send, _recv) = connection.open_bi().await.unwrap();
        send.write_all(&wire).await.unwrap();
        send.finish().unwrap();
        assert_eq!(close_code(&connection).await.0, 2, "{name}");
        assert_eq!(calls.load(Ordering::Relaxed), 0, "{name}");
        assert_eq!(counter(&registry, "0x2"), "1", "{name}");
        listeners.shutdown().await.unwrap();
    }
}

// RFC 9250 §4.3.3: STREAM FIN before the length is satisfied is a protocol error.
#[tokio::test]
async fn truncated_message_closes_the_connection() {
    let (listeners, address) = listening(Doq::new(&Registry::default())).await;
    let (_endpoint, connection) = connect(address).await;
    let (mut send, _recv) = connection.open_bi().await.unwrap();
    let wire = frame(&query(0, &[]));
    send.write_all(&wire[..wire.len() - 3]).await.unwrap();
    send.finish().unwrap();
    assert_eq!(close_code(&connection).await.0, 2);
    listeners.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 TestServerQUIC_ServeQUIC_StalledStreamDoesNotKillOtherStreamsOnSameConnection.
#[tokio::test]
async fn stalled_stream_is_reset_without_closing_the_connection() {
    let registry = Registry::default();
    let mut handler = Doq::new(&registry);
    handler.tcp.read = Duration::from_millis(200);
    let (listeners, address) = listening(handler).await;
    let (_endpoint, connection) = connect(address).await;
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    // One byte of the length prefix, then silence.
    send.write_all(&[0]).await.unwrap();
    let error = timeout(TEST_TIMEOUT, recv.read_to_end(1024))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(error, quinn::ReadToEndError::Read(quinn::ReadError::Reset(code)) if code == VarInt::from_u32(1)),
        "{error:?}"
    );
    let ok = query(0, &[]);
    assert_eq!(exchange(&connection, &ok).await, ok);
    assert_eq!(counter(&registry, "0x1"), "1");
    listeners.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 TestServerQUIC_ServeQUIC_PeerResetStreamDoesNotKillOtherStreamsOnSameConnection.
#[tokio::test]
async fn peer_reset_stream_does_not_close_the_connection() {
    let (listeners, address) = listening(Doq::new(&Registry::default())).await;
    let (_endpoint, connection) = connect(address).await;
    let (mut send, _recv) = connection.open_bi().await.unwrap();
    send.write_all(&[0]).await.unwrap();
    send.reset(VarInt::from_u32(0)).unwrap();
    let ok = query(0, &[]);
    assert_eq!(exchange(&connection, &ok).await, ok);
    listeners.shutdown().await.unwrap();
}

// quic { max_streams N }: the peer may not open more concurrent streams than the limit.
#[tokio::test]
async fn stream_limit_blocks_extra_streams() {
    let mut handler = Doq::new(&Registry::default());
    handler.quic.max_streams = 1;
    let (listeners, address) = listening(handler).await;
    let (_endpoint, connection) = connect(address).await;
    let (_held, _recv) = connection.open_bi().await.unwrap();
    // QUIC stream credit: the second stream cannot open until the first ends.
    assert!(
        timeout(Duration::from_millis(300), connection.open_bi())
            .await
            .is_err()
    );
    listeners.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 TestServerQUICServeQUICDefaultMaxConnections.
#[tokio::test]
async fn connection_limit_closes_extra_connections() {
    let mut handler = Doq::new(&Registry::default());
    handler.quic.max_connections = 1;
    let (listeners, address) = listening(handler).await;
    let (_first_endpoint, first) = connect(address).await;
    let ok = query(0, &[]);
    assert_eq!(exchange(&first, &ok).await, ok);
    let (_second_endpoint, second) = connect(address).await;
    let (code, reason) = close_code(&second).await;
    assert_eq!((code, reason.as_slice()), (0, &b"too many connections"[..]));
    // The connection under the limit is unaffected.
    assert_eq!(exchange(&first, &ok).await, ok);
    listeners.shutdown().await.unwrap();
}

#[tokio::test]
async fn zero_max_connections_removes_the_limit() {
    let mut handler = Doq::new(&Registry::default());
    handler.quic.max_connections = 0;
    let (listeners, address) = listening(handler).await;
    let mut held = Vec::new();
    let ok = query(0, &[]);
    for _ in 0..3 {
        let (endpoint, connection) = connect(address).await;
        assert_eq!(exchange(&connection, &ok).await, ok);
        held.push((endpoint, connection));
    }
    listeners.shutdown().await.unwrap();
}

#[tokio::test]
async fn oversized_worker_pool_is_clamped_instead_of_panicking() {
    let mut handler = Doq::new(&Registry::default());
    handler.quic.worker_pool_size = usize::MAX;
    let (listeners, address) = listening(handler).await;
    let (_endpoint, connection) = connect(address).await;
    let ok = query(0, &[]);
    assert_eq!(exchange(&connection, &ok).await, ok);
    listeners.shutdown().await.unwrap();
}

// CoreDNS v1.15.0 TestServerQUIC_ServeQUIC_StalledStreamDoesNotStarveWorkerPool.
#[tokio::test]
async fn worker_pool_exhaustion_delays_later_streams_until_a_worker_frees() {
    let mut handler = Doq::new(&Registry::default());
    handler.quic.worker_pool_size = 1;
    let gate = Arc::new(Notify::new());
    handler.gate = Some(Arc::clone(&gate));
    let calls = Arc::clone(&handler.calls);
    let (listeners, address) = listening(handler).await;
    let (_endpoint, connection) = connect(address).await;
    let ok = query(0, &[]);
    let first = {
        let connection = connection.clone();
        let ok = ok.clone();
        tokio::spawn(async move { exchange(&connection, &ok).await })
    };
    while calls.load(Ordering::Relaxed) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let second = {
        let connection = connection.clone();
        let ok = ok.clone();
        tokio::spawn(async move { exchange(&connection, &ok).await })
    };
    // The only worker is held, so the second Query is not handled yet.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    gate.notify_one();
    assert_eq!(first.await.unwrap(), ok);
    while calls.load(Ordering::Relaxed) < 2 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    gate.notify_one();
    assert_eq!(second.await.unwrap(), ok);
    listeners.shutdown().await.unwrap();
}

// RFC 8446 §4.6.1 via Reload: new connections use the renewed identity on the same Listener.
#[tokio::test]
async fn reload_serves_a_renewed_certificate() {
    let registry = Registry::default();
    let (mut listeners, address) = listening(Doq::new(&registry)).await;
    let (_old_endpoint, old) = connect(address).await;
    let certificate = |connection: &Connection| {
        let chain = connection
            .peer_identity()
            .unwrap()
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .unwrap();
        chain[0].clone()
    };
    let original = certificate(&old);
    let mut renewed = Doq::new(&registry);
    renewed.tls = identity("server-renewed");
    listeners
        .apply(HashMap::from([(key(), renewed)]))
        .await
        .unwrap();
    assert_eq!(listeners.get(&key()).unwrap().local_addr(), address);
    let (_new_endpoint, new) = connect(address).await;
    assert_ne!(certificate(&new), original);
    let ok = query(0, &[]);
    assert_eq!(exchange(&new, &ok).await, ok);
    assert_eq!(exchange(&old, &ok).await, ok);
    listeners.shutdown().await.unwrap();
}

// Graceful shutdown: accepted streams finish before the connection closes.
#[tokio::test]
async fn shutdown_finishes_in_flight_queries() {
    let mut handler = Doq::new(&Registry::default());
    handler.delay = Duration::from_millis(300);
    let calls = Arc::clone(&handler.calls);
    let (listeners, address) = listening(handler).await;
    let (_endpoint, connection) = connect(address).await;
    let ok = query(0, &[]);
    let pending = {
        let connection = connection.clone();
        let ok = ok.clone();
        tokio::spawn(async move { exchange(&connection, &ok).await })
    };
    while calls.load(Ordering::Relaxed) == 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    listeners.shutdown().await.unwrap();
    assert_eq!(pending.await.unwrap(), ok);
    assert_eq!(close_code(&connection).await.0, 0);
}

#[tokio::test]
async fn quic_listener_has_no_tcp_or_plain_udp_workers() {
    let (listeners, address) = listening(Doq::new(&Registry::default())).await;
    assert!(
        tokio::net::TcpStream::connect(address).await.is_err(),
        "QUIC Listener must not accept TCP"
    );
    listeners.shutdown().await.unwrap();
}
