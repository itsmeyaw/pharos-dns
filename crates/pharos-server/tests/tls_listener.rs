#![forbid(unsafe_code)]

use std::{collections::HashMap, net::SocketAddr, path::PathBuf, time::Duration};

use pharos_server::{
    Action, Handler, ListenerKey, ListenerRegistry, Protocol, TcpOptions, Transport,
    tls::{ClientAuth, ClientOptions, ServerOptions, ServerTls, TlsConnector, client_config},
};
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use tokio_rustls::client::TlsStream;

const TEST_TIMEOUT: Duration = Duration::from_secs(3);

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

/// Answers every Query with its own bytes, like a Plugin Chain that echoes.
struct Echo {
    tls: ServerTls,
    options: TcpOptions,
}

impl Echo {
    fn new(prefix: &str) -> Self {
        Self {
            tls: identity(prefix),
            options: TcpOptions::default(),
        }
    }
}

impl Handler for Echo {
    fn tls(&self) -> Option<ServerTls> {
        Some(self.tls.clone())
    }
    fn tcp_options(&self) -> TcpOptions {
        self.options
    }
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        assert_eq!(protocol, Protocol::Tcp);
        response.extend_from_slice(query);
        Action::Respond
    }
}

fn key() -> ListenerKey {
    ListenerKey {
        transport: Transport::Tls,
        address: "127.0.0.1:0".parse().unwrap(),
    }
}

async fn connect(address: SocketAddr) -> TlsStream<TcpStream> {
    let config = client_config(&ClientOptions {
        ca: Some(fixture("ca.pem")),
        identity: None,
    })
    .unwrap();
    let tcp = TcpStream::connect(address).await.unwrap();
    TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap()
}

// RFC 7858 §3.3: DNS Messages over TLS use the two-octet length framing of RFC 1035 §4.2.2.
async fn exchange(stream: &mut TlsStream<TcpStream>, query: &[u8]) -> Vec<u8> {
    stream.write_u16(query.len() as u16).await.unwrap();
    stream.write_all(query).await.unwrap();
    stream.flush().await.unwrap();
    let length = timeout(TEST_TIMEOUT, stream.read_u16())
        .await
        .unwrap()
        .unwrap();
    let mut response = vec![0; length.into()];
    stream.read_exact(&mut response).await.unwrap();
    response
}

fn served_certificate(stream: &TlsStream<TcpStream>) -> CertificateDer<'static> {
    stream.get_ref().1.peer_certificates().unwrap()[0]
        .clone()
        .into_owned()
}

async fn listening(handler: Echo) -> (ListenerRegistry, SocketAddr) {
    let mut registry = ListenerRegistry::default();
    registry
        .apply(HashMap::from([(key(), handler)]))
        .await
        .unwrap();
    let address = registry.get(&key()).unwrap().local_addr();
    (registry, address)
}

#[tokio::test]
async fn tls_listener_answers_framed_queries_on_one_connection() {
    let (registry, address) = listening(Echo::new("server")).await;
    let mut stream = connect(address).await;
    assert_eq!(exchange(&mut stream, b"first").await, b"first");
    assert_eq!(exchange(&mut stream, b"second").await, b"second");
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn tls_listener_does_not_serve_udp() {
    let (registry, address) = listening(Echo::new("server")).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(b"query", address).await.unwrap();
    let mut reply = [0; 16];
    assert!(
        timeout(Duration::from_millis(300), socket.recv_from(&mut reply))
            .await
            .is_err()
    );
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn plaintext_client_is_disconnected_without_a_response() {
    let (registry, address) = listening(Echo::new("server")).await;
    let mut tcp = TcpStream::connect(address).await.unwrap();
    tcp.write_u16(5).await.unwrap();
    tcp.write_all(b"query").await.unwrap();
    let mut reply = [0; 64];
    let read = timeout(TEST_TIMEOUT, tcp.read(&mut reply)).await.unwrap();
    // A TLS alert may precede the close; plaintext Response bytes never appear.
    assert!(!matches!(read, Ok(n) if n > 0 && &reply[..n] == b"\0\x05query"));
    registry.shutdown().await.unwrap();
}

// RFC 7766 §6.2.4: the query limit and timeouts of TCP apply to DNS over TLS as well.
#[tokio::test]
async fn max_queries_closes_the_tls_connection() {
    let mut handler = Echo::new("server");
    handler.options.max_queries = Some(1);
    let (registry, address) = listening(handler).await;
    let mut stream = connect(address).await;
    assert_eq!(exchange(&mut stream, b"only").await, b"only");
    let mut rest = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut rest))
        .await
        .unwrap()
        .ok();
    assert!(rest.is_empty());
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn stalled_handshake_is_closed_after_the_read_timeout() {
    let mut handler = Echo::new("server");
    handler.options.read = Duration::from_millis(300);
    let (registry, address) = listening(handler).await;
    let mut tcp = TcpStream::connect(address).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        timeout(TEST_TIMEOUT, tcp.read(&mut byte))
            .await
            .unwrap()
            .unwrap_or(0),
        0
    );
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn reload_serves_a_renewed_certificate_on_the_same_listener() {
    let (mut registry, address) = listening(Echo::new("server")).await;
    let mut before = connect(address).await;
    let original = served_certificate(&before);
    registry
        .apply(HashMap::from([(key(), Echo::new("server-renewed"))]))
        .await
        .unwrap();
    assert_eq!(registry.get(&key()).unwrap().local_addr(), address);
    let mut after = connect(address).await;
    assert_ne!(served_certificate(&after), original);
    assert_eq!(exchange(&mut after, b"new").await, b"new");
    // An established connection keeps working through the swap.
    assert_eq!(exchange(&mut before, b"old").await, b"old");
    registry.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_sends_close_notify() {
    let (registry, address) = listening(Echo::new("server")).await;
    let mut stream = connect(address).await;
    assert_eq!(exchange(&mut stream, b"query").await, b"query");
    registry.shutdown().await.unwrap();
    // A clean TLS close ends the stream with EOF; a bare TCP reset would be an error.
    let mut rest = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert!(rest.is_empty());
}

#[tokio::test]
async fn tls_listener_without_an_identity_closes_connections() {
    struct Plain;
    impl Handler for Plain {
        async fn handle(&self, _: &[u8], _: SocketAddr, _: Protocol, _: &mut Vec<u8>) -> Action {
            Action::Drop
        }
    }
    let mut registry = ListenerRegistry::default();
    registry
        .apply(HashMap::from([(key(), Plain)]))
        .await
        .unwrap();
    let address = registry.get(&key()).unwrap().local_addr();
    let mut tcp = TcpStream::connect(address).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        timeout(TEST_TIMEOUT, tcp.read(&mut byte))
            .await
            .unwrap()
            .unwrap_or(0),
        0
    );
    registry.shutdown().await.unwrap();
}
