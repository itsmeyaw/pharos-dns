#![forbid(unsafe_code)]

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use pharos_server::{
    Action, Handler, ListenerKey, ListenerRegistry, Protocol, Transport,
    proxyproto::{Config, Policy, UdpTracking},
    tls::{ClientAuth, ClientOptions, ServerOptions, ServerTls, TlsConnector, client_config},
};
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Answers every Query with the peer address and TLV hex the Listener reported.
struct Probe {
    config: Arc<Config>,
    tls: Option<ServerTls>,
}

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/tls")
        .join(name)
}

impl Handler for Probe {
    fn tls(&self) -> Option<ServerTls> {
        self.tls.clone()
    }
    fn proxyproto(&self) -> Option<Arc<Config>> {
        Some(Arc::clone(&self.config))
    }
    async fn handle(
        &self,
        _: &[u8],
        peer: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        response.extend_from_slice(format!("{peer}|").as_bytes());
        Action::Respond
    }
    async fn handle_shared(
        self: &Arc<Self>,
        query: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        self.handle(query, peer, protocol, response).await
    }
    async fn handle_proxied(
        self: &Arc<Self>,
        _: &[u8],
        peer: SocketAddr,
        _: Protocol,
        tlv: &str,
        response: &mut Vec<u8>,
    ) -> Action {
        response.extend_from_slice(format!("{peer}|{tlv}").as_bytes());
        Action::Respond
    }
}

fn config(policy: Policy) -> Config {
    let mut config = Config::new(move |_| policy);
    config.header_timeout = Duration::from_millis(300);
    config.tlv_metadata = true;
    config
}

fn key() -> ListenerKey {
    ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:0".parse().unwrap(),
    }
}

async fn listening(config: Config) -> (ListenerRegistry, SocketAddr) {
    listening_on(key(), config, None).await
}

async fn listening_on(
    key: ListenerKey,
    config: Config,
    tls: Option<ServerTls>,
) -> (ListenerRegistry, SocketAddr) {
    let mut registry = ListenerRegistry::default();
    let handler = Probe {
        config: Arc::new(config),
        tls,
    };
    registry
        .apply(HashMap::from([(key, handler)]))
        .await
        .unwrap();
    let address = registry.get(&key).unwrap().local_addr();
    (registry, address)
}

fn v1() -> Vec<u8> {
    b"PROXY TCP4 192.0.2.1 192.0.2.53 12345 53\r\n".to_vec()
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

fn framed(query: &[u8]) -> Vec<u8> {
    let mut wire = u16::try_from(query.len()).unwrap().to_be_bytes().to_vec();
    wire.extend(query);
    wire
}

async fn read_response(stream: &mut TcpStream) -> Option<String> {
    let length = timeout(TEST_TIMEOUT, stream.read_u16()).await.ok()?.ok()?;
    let mut response = vec![0; length.into()];
    stream.read_exact(&mut response).await.ok()?;
    Some(String::from_utf8(response).unwrap())
}

async fn tcp_exchange(address: SocketAddr, wire: &[u8]) -> Option<String> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(wire).await.unwrap();
    read_response(&mut stream).await
}

// PROXY protocol §2.1: a v1 header precedes the first DNS frame of the connection.
#[tokio::test]
async fn tcp_v1_header_sets_the_peer_seen_by_the_handler() {
    let (registry, address) = listening(config(Policy::Use)).await;
    let wire = [v1(), framed(b"query")].concat();
    assert_eq!(
        tcp_exchange(address, &wire).await.as_deref(),
        Some("192.0.2.1:12345|")
    );
    registry.shutdown().await.unwrap();
}

// PROXY protocol §2.2: a v2 header carries the TLV vector that `tlv_metadata` publishes.
#[tokio::test]
async fn tcp_v2_header_sets_the_peer_and_the_tlv() {
    let (registry, address) = listening(config(Policy::Use)).await;
    let wire = [v2(0x11, &[0xEA, 0, 2, 0xCA, 0xFE]), framed(b"query")].concat();
    assert_eq!(
        tcp_exchange(address, &wire).await.as_deref(),
        Some("192.0.2.1:12345|ea0002cafe")
    );
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_header_applies_to_every_query_of_the_connection() {
    let (registry, address) = listening(config(Policy::Use)).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(&[v1(), framed(b"one"), framed(b"two")].concat())
        .await
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            read_response(&mut stream).await.as_deref(),
            Some("192.0.2.1:12345|")
        );
    }
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_without_a_header_keeps_the_real_peer_under_use() {
    let (registry, address) = listening(config(Policy::Use)).await;
    let response = tcp_exchange(address, &framed(b"query")).await.unwrap();
    assert!(response.starts_with("127.0.0.1:"), "{response}");
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_ignore_policy_consumes_the_header_but_keeps_the_real_peer() {
    let (registry, address) = listening(config(Policy::Ignore)).await;
    let wire = [v1(), framed(b"query")].concat();
    let response = tcp_exchange(address, &wire).await.unwrap();
    assert!(response.starts_with("127.0.0.1:"), "{response}");
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_reject_policy_closes_a_connection_with_a_header() {
    let (registry, address) = listening(config(Policy::Reject)).await;
    let wire = [v1(), framed(b"query")].concat();
    assert_eq!(tcp_exchange(address, &wire).await, None);
    assert!(tcp_exchange(address, &framed(b"query")).await.is_some());
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_skip_policy_leaves_the_header_to_the_application() {
    let (registry, address) = listening(config(Policy::Skip)).await;
    let wire = [v1(), framed(b"query")].concat();
    // The header's bytes read as a DNS length prefix; no Response carries the client address.
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&wire).await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(read_response(&mut stream).await, None);
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_header_that_never_completes_is_closed_after_the_header_timeout() {
    let (registry, address) = listening(config(Policy::Use)).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(b"PROXY TCP4 192.0.2.1 ").await.unwrap();
    let mut byte = [0];
    let read = timeout(TEST_TIMEOUT, stream.read(&mut byte)).await.unwrap();
    assert!(matches!(read, Ok(0) | Err(_)));
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_truncated_and_malicious_headers_close_the_connection() {
    let (registry, address) = listening(config(Policy::Use)).await;
    let mut oversized = v2(0x11, &[]);
    oversized[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    let long_line = [b"PROXY UNKNOWN ".as_slice(), &[b'x'; 4096]].concat();
    for wire in [
        v1()[..20].to_vec(),
        v2(0x11, &[])[..20].to_vec(),
        oversized,
        long_line,
        b"PROXY TCP4 999.0.0.1 192.0.2.53 1 2\r\n".to_vec(),
    ] {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(&wire).await.unwrap();
        stream.shutdown().await.unwrap();
        assert_eq!(read_response(&mut stream).await, None);
    }
    // The Listener still serves after the abuse.
    assert!(tcp_exchange(address, &framed(b"query")).await.is_some());
    registry.shutdown().await.unwrap();
}

// RFC 7858 §3.2: DoT is TLS over TCP; PROXY protocol §2 puts the header ahead of the ClientHello.
#[tokio::test]
async fn tls_listener_reads_the_header_before_the_handshake() {
    let tls = ServerTls::load(&ServerOptions {
        cert: fixture("server.pem"),
        key: fixture("server.key.pem"),
        ca: None,
        client_auth: ClientAuth::NoCert,
        keylog: None,
    })
    .unwrap();
    let key = ListenerKey {
        transport: Transport::Tls,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let (registry, address) = listening_on(key, config(Policy::Use), Some(tls)).await;
    let mut tcp = TcpStream::connect(address).await.unwrap();
    tcp.write_all(&v2(0x11, &[0xEA, 0, 1, 7])).await.unwrap();
    let client = client_config(&ClientOptions {
        ca: Some(fixture("ca.pem")),
        identity: None,
    })
    .unwrap();
    let mut stream = TlsConnector::from(client)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    stream.write_all(&framed(b"query")).await.unwrap();
    let length = timeout(TEST_TIMEOUT, stream.read_u16())
        .await
        .unwrap()
        .unwrap();
    let mut response = vec![0; length.into()];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, b"192.0.2.1:12345|ea000107");
    registry.shutdown().await.unwrap();
}

// RFC 7858 §3.2: a TLS ClientHello without a PROXY header is served under `use`.
#[tokio::test]
async fn tls_listener_serves_clients_that_send_no_header_under_use() {
    let tls = ServerTls::load(&ServerOptions {
        cert: fixture("server.pem"),
        key: fixture("server.key.pem"),
        ca: None,
        client_auth: ClientAuth::NoCert,
        keylog: None,
    })
    .unwrap();
    let key = ListenerKey {
        transport: Transport::Tls,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let (registry, address) = listening_on(key, config(Policy::Use), Some(tls)).await;
    let tcp = TcpStream::connect(address).await.unwrap();
    let client = client_config(&ClientOptions {
        ca: Some(fixture("ca.pem")),
        identity: None,
    })
    .unwrap();
    let mut stream = TlsConnector::from(client)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    stream.write_all(&framed(b"query")).await.unwrap();
    let length = timeout(TEST_TIMEOUT, stream.read_u16())
        .await
        .unwrap()
        .unwrap();
    let mut response = vec![0; length.into()];
    stream.read_exact(&mut response).await.unwrap();
    assert!(
        String::from_utf8(response)
            .unwrap()
            .starts_with("127.0.0.1:")
    );
    registry.shutdown().await.unwrap();
}

async fn udp_client(address: SocketAddr) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(address).await.unwrap();
    socket
}

async fn udp_response(socket: &UdpSocket) -> Option<String> {
    let mut buffer = [0; 512];
    let length = timeout(Duration::from_millis(500), socket.recv(&mut buffer))
        .await
        .ok()?
        .ok()?;
    Some(String::from_utf8(buffer[..length].to_vec()).unwrap())
}

fn tracking(policy: Policy) -> Config {
    let mut config = config(policy);
    config.udp_tracking = Some(UdpTracking {
        ttl: Duration::from_secs(30),
        max_sessions: 100,
    });
    config
}

// PROXY protocol §2.2: a v2 DGRAM header precedes the payload of its datagram.
#[tokio::test]
async fn udp_header_sets_the_peer_and_the_tlv_for_its_datagram() {
    let (registry, address) = listening(config(Policy::Use)).await;
    let client = udp_client(address).await;
    let wire = [v2(0x12, &[0xEA, 0, 2, 0xCA, 0xFE]), b"dns".to_vec()].concat();
    client.send(&wire).await.unwrap();
    assert_eq!(
        udp_response(&client).await.as_deref(),
        Some("192.0.2.1:12345|ea0002cafe")
    );
    client.send(b"dns").await.unwrap();
    let response = udp_response(&client).await.unwrap();
    assert!(response.starts_with("127.0.0.1:"), "{response}");
    registry.shutdown().await.unwrap();
}

// Cloudflare Spectrum: the header-only first datagram opens a session for headerless ones.
#[tokio::test]
async fn udp_header_only_datagram_opens_a_session() {
    let (registry, address) = listening(tracking(Policy::Use)).await;
    let client = udp_client(address).await;
    client.send(&v2(0x12, &[0xEA, 0, 1, 7])).await.unwrap();
    assert_eq!(udp_response(&client).await, None);
    for _ in 0..3 {
        client.send(b"dns").await.unwrap();
        assert_eq!(
            udp_response(&client).await.as_deref(),
            Some("192.0.2.1:12345|ea000107")
        );
    }
    let other = udp_client(address).await;
    other.send(b"dns").await.unwrap();
    assert!(
        udp_response(&other)
            .await
            .unwrap()
            .starts_with("127.0.0.1:")
    );
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_policies_decide_what_happens_to_a_header() {
    let wire = [v2(0x12, &[]), b"dns".to_vec()].concat();
    let (registry, address) = listening(config(Policy::Ignore)).await;
    let client = udp_client(address).await;
    client.send(&wire).await.unwrap();
    assert!(
        udp_response(&client)
            .await
            .unwrap()
            .starts_with("127.0.0.1:")
    );
    registry.shutdown().await.unwrap();

    let (registry, address) = listening(config(Policy::Reject)).await;
    let client = udp_client(address).await;
    client.send(&wire).await.unwrap();
    assert_eq!(udp_response(&client).await, None);
    client.send(b"dns").await.unwrap();
    assert!(udp_response(&client).await.is_some());
    registry.shutdown().await.unwrap();

    let (registry, address) = listening(config(Policy::Skip)).await;
    let client = udp_client(address).await;
    client.send(&wire).await.unwrap();
    assert!(
        udp_response(&client)
            .await
            .unwrap()
            .starts_with("127.0.0.1:")
    );
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_malformed_headers_are_dropped_and_the_listener_keeps_serving() {
    let (registry, address) = listening(config(Policy::Use)).await;
    let client = udp_client(address).await;
    let mut oversized = v2(0x12, &[]);
    oversized[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    for wire in [
        [v1(), b"dns".to_vec()].concat(),
        v2(0x12, &[])[..20].to_vec(),
        [v2(0x11, &[]), b"dns".to_vec()].concat(),
        oversized,
    ] {
        client.send(&wire).await.unwrap();
        assert_eq!(udp_response(&client).await, None);
    }
    client.send(b"dns").await.unwrap();
    assert!(udp_response(&client).await.is_some());
    registry.shutdown().await.unwrap();
}
