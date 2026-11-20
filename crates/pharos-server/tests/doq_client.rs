#![forbid(unsafe_code)]

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use pharos_server::{
    Action, Handler, ListenerKey, ListenerRegistry, Protocol, Transport,
    doq_client::{DoqClient, DoqConnection, DoqError},
    tls::{ClientAuth, ClientOptions, ServerOptions, ServerTls, client_config},
};
use quinn::{
    Connection, ConnectionError, Endpoint, RecvStream, SendStream, ServerConfig, VarInt,
    crypto::rustls::HandshakeData,
};
use tokio::{
    sync::{Barrier, mpsc},
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

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

/// A QUERY for `example.com. A` with Message ID zero, as DoQ requires.
const QUERY: &[u8] = b"\0\0\x01\0\0\x01\0\0\0\0\0\0\x07example\x03com\0\0\x01\0\x01";

fn frame(message: &[u8]) -> Vec<u8> {
    let mut wire = u16::try_from(message.len()).unwrap().to_be_bytes().to_vec();
    wire.extend_from_slice(message);
    wire
}

fn answer(query: &[u8], id: u16) -> Vec<u8> {
    let mut response = query.to_vec();
    response[..2].copy_from_slice(&id.to_be_bytes());
    response[2] |= 0x80;
    response
}

fn client(address: SocketAddr, source: Option<IpAddr>) -> DoqClient {
    let tls = client_config(&ClientOptions {
        ca: Some(fixture("ca.pem")),
        identity: None,
    })
    .unwrap();
    DoqClient::new(&tls, source, address, Duration::from_secs(30)).unwrap()
}

async fn connect(client: &DoqClient) -> DoqConnection {
    timeout(TEST_TIMEOUT, client.connect("localhost"))
        .await
        .unwrap()
        .unwrap()
}

async fn exchange(connection: &DoqConnection, query: &[u8]) -> Result<Vec<u8>, DoqError> {
    let mut wire = vec![0; 65535];
    wire[..query.len()].copy_from_slice(query);
    let len = timeout(TEST_TIMEOUT, connection.exchange(&mut wire, query.len()))
        .await
        .unwrap()?;
    wire.truncate(len);
    Ok(wire)
}

/// A DoQ server whose per-stream behaviour the test scripts.
struct Server {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    connections: Arc<Mutex<Vec<Connection>>>,
}

type Stream = (usize, Connection, SendStream, RecvStream);

fn server(streams: mpsc::UnboundedSender<Stream>) -> Server {
    let config = ServerConfig::with_crypto(identity().quic());
    let endpoint = Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    let connections = Arc::new(Mutex::new(Vec::new()));
    let known = Arc::clone(&connections);
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let number = count.fetch_add(1, Ordering::SeqCst) + 1;
            let streams = streams.clone();
            let known = Arc::clone(&known);
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                known.lock().unwrap().push(connection.clone());
                while let Ok((send, recv)) = connection.accept_bi().await {
                    if streams
                        .send((number, connection.clone(), send, recv))
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    Server {
        address,
        accepted,
        connections,
    }
}

async fn read_query(recv: &mut RecvStream) -> Vec<u8> {
    let mut prefix = [0; 2];
    recv.read_exact(&mut prefix).await.unwrap();
    let mut query = vec![0; usize::from(u16::from_be_bytes(prefix))];
    recv.read_exact(&mut query).await.unwrap();
    query
}

/// Replies to every Query like a conforming server, calling `reply` for the bytes it sends.
fn scripted(reply: impl Fn(usize, &[u8]) -> Vec<u8> + Send + Sync + 'static) -> Server {
    let (sender, mut receiver) = mpsc::unbounded_channel::<Stream>();
    let reply = Arc::new(reply);
    let server = server(sender);
    tokio::spawn(async move {
        while let Some((number, _connection, mut send, mut recv)) = receiver.recv().await {
            let reply = Arc::clone(&reply);
            tokio::spawn(async move {
                let query = read_query(&mut recv).await;
                let _ = send.write_all(&reply(number, &query)).await;
                let _ = send.finish();
            });
        }
    });
    server
}

// RFC 9250 §4.2: a Query goes out with ID zero on its own stream, and the Response comes back the same way.
#[tokio::test]
async fn exchanges_a_query_over_a_doq_stream() {
    let server = scripted(|_, query| frame(&answer(query, 0)));
    let client = client(server.address, None);
    let connection = connect(&client).await;
    let response = exchange(&connection, QUERY).await.unwrap();
    assert_eq!(response, answer(QUERY, 0));
    assert_ne!(connection.local_addr().port(), 0);
}

// RFC 9250 §4.1.1: the connection negotiates the ALPN token "doq".
#[tokio::test]
async fn negotiates_the_doq_alpn_on_tls_13() {
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let server = server(sender);
    let client = client(server.address, None);
    let connection = connect(&client).await;
    let exchanged = tokio::spawn(async move { exchange(&connection, QUERY).await });
    let (_, connection, mut send, mut recv) = receiver.recv().await.unwrap();
    let data = connection
        .handshake_data()
        .unwrap()
        .downcast::<HandshakeData>()
        .unwrap();
    assert_eq!(data.protocol.as_deref(), Some(&b"doq"[..]));
    let query = read_query(&mut recv).await;
    send.write_all(&frame(&answer(&query, 0))).await.unwrap();
    send.finish().unwrap();
    exchanged.await.unwrap().unwrap();
}

// RFC 6125 §6.4.1: a certificate for another name is refused.
#[tokio::test]
async fn rejects_a_certificate_for_another_name() {
    let server = scripted(|_, query| frame(&answer(query, 0)));
    let client = client(server.address, None);
    let result = timeout(TEST_TIMEOUT, client.connect("wrong.example"))
        .await
        .unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn binds_the_configured_source_address() {
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let server = server(sender);
    let source: IpAddr = "127.0.0.2".parse().unwrap();
    let client = client(server.address, Some(source));
    let connection = connect(&client).await;
    assert_eq!(connection.local_addr().ip(), source);
    let exchanged = tokio::spawn(async move { exchange(&connection, QUERY).await });
    let (_, connection, mut send, mut recv) = receiver.recv().await.unwrap();
    assert_eq!(connection.remote_address().ip(), source);
    let query = read_query(&mut recv).await;
    send.write_all(&frame(&answer(&query, 0))).await.unwrap();
    send.finish().unwrap();
    exchanged.await.unwrap().unwrap();
}

// RFC 9250 §4.2: concurrent Queries share one connection on separate streams.
#[tokio::test]
async fn concurrent_queries_share_one_connection() {
    const QUERIES: usize = 16;
    let barrier = Arc::new(Barrier::new(QUERIES));
    let gate = Arc::clone(&barrier);
    let (sender, mut receiver) = mpsc::unbounded_channel::<Stream>();
    let server = server(sender);
    tokio::spawn(async move {
        while let Some((_, _connection, mut send, mut recv)) = receiver.recv().await {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                let query = read_query(&mut recv).await;
                // Every Query must be in flight at once before any is answered.
                gate.wait().await;
                send.write_all(&frame(&answer(&query, 0))).await.unwrap();
                send.finish().unwrap();
            });
        }
    });
    let client = client(server.address, None);
    let connection = Arc::new(connect(&client).await);
    let mut tasks = Vec::new();
    for _ in 0..QUERIES {
        let connection = Arc::clone(&connection);
        tasks.push(tokio::spawn(
            async move { exchange(&connection, QUERY).await },
        ));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

async fn close_code(connection: &Connection) -> u32 {
    match timeout(TEST_TIMEOUT, connection.closed()).await.unwrap() {
        ConnectionError::ApplicationClosed(close) => {
            u32::try_from(close.error_code.into_inner()).unwrap()
        }
        other => panic!("expected an application close, got {other:?}"),
    }
}

// RFC 9250 §4.3.3 and CoreDNS v1.15.0 plugin/pkg/proxy/doq.go: these Responses are protocol errors.
#[tokio::test]
async fn protocol_errors_close_the_connection_with_code_two() {
    let cases: [(&str, Vec<u8>); 6] = [
        ("non-zero ID", frame(&answer(QUERY, 1))),
        ("zero length", vec![0, 0]),
        ("FIN inside the length", vec![0]),
        ("FIN inside the Message", vec![0, 20, 0, 0, 0x80]),
        ("malformed Message", frame(b"not dns at all")),
        ("data after the Message", {
            let mut wire = frame(&answer(QUERY, 0));
            wire.push(0);
            wire
        }),
    ];
    for (name, reply) in cases {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let server = server(sender);
        let client = client(server.address, None);
        let connection = connect(&client).await;
        let exchanged = tokio::spawn(async move {
            let result = exchange(&connection, QUERY).await;
            (result, connection)
        });
        let (_, peer, mut send, mut recv) = receiver.recv().await.unwrap();
        read_query(&mut recv).await;
        send.write_all(&reply).await.unwrap();
        send.finish().unwrap();
        let (result, connection) = exchanged.await.unwrap();
        assert!(
            matches!(result, Err(DoqError::Protocol(_))),
            "{name}: {result:?}"
        );
        assert_eq!(close_code(&peer).await, 2, "{name}");
        assert!(connection.is_closed(), "{name}");
    }
}

// RFC 9250 §4.3.2: a stream the server resets fails that Query only.
#[tokio::test]
async fn a_reset_stream_leaves_the_connection_usable() {
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let server = server(sender);
    let client = client(server.address, None);
    let connection = Arc::new(connect(&client).await);
    let first = {
        let connection = Arc::clone(&connection);
        tokio::spawn(async move { exchange(&connection, QUERY).await })
    };
    let (_, _peer, mut send, mut recv) = receiver.recv().await.unwrap();
    read_query(&mut recv).await;
    send.reset(VarInt::from_u32(1)).unwrap();
    assert!(matches!(first.await.unwrap(), Err(DoqError::Stream(_))));
    assert!(!connection.is_closed());
    let second = {
        let connection = Arc::clone(&connection);
        tokio::spawn(async move { exchange(&connection, QUERY).await })
    };
    let (_, _peer, mut send, mut recv) = receiver.recv().await.unwrap();
    let query = read_query(&mut recv).await;
    send.write_all(&frame(&answer(&query, 0))).await.unwrap();
    send.finish().unwrap();
    second.await.unwrap().unwrap();
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

// RFC 9250 §4.3.2: abandoning a Query resets the stream with DOQ_REQUEST_CANCELLED, not the connection.
#[tokio::test]
async fn dropping_an_exchange_cancels_only_its_stream() {
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let server = server(sender);
    let client = client(server.address, None);
    let connection = connect(&client).await;
    let abandoned = timeout(Duration::from_millis(100), exchange(&connection, QUERY)).await;
    assert!(abandoned.is_err());
    let (_, peer, send, _recv) = receiver.recv().await.unwrap();
    // The server never answered; the client's STOP_SENDING carries the cancellation code.
    assert_eq!(
        timeout(TEST_TIMEOUT, send.stopped())
            .await
            .unwrap()
            .unwrap(),
        Some(VarInt::from_u32(3))
    );
    assert!(peer.close_reason().is_none());
    assert!(!connection.is_closed());
}

// CoreDNS v1.15.0 plugin/pkg/proxy/doq.go: a connection the peer closed cannot open a stream.
#[tokio::test]
async fn a_closed_connection_fails_to_open_a_stream() {
    let (sender, _receiver) = mpsc::unbounded_channel();
    let server = server(sender);
    let client = client(server.address, None);
    let connection = connect(&client).await;
    let peer = timeout(TEST_TIMEOUT, async {
        loop {
            if let Some(peer) = server.connections.lock().unwrap().first().cloned() {
                break peer;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    peer.close(VarInt::from_u32(0), b"rotate");
    timeout(TEST_TIMEOUT, async {
        while !connection.is_closed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let result = exchange(&connection, QUERY).await;
    assert!(matches!(result, Err(DoqError::Open(_))), "{result:?}");
}

// RFC 9250 §5.3: a Listener of Pharos itself answers a DoQ client.
struct Echo(ServerTls);

impl Handler for Echo {
    fn tls(&self) -> Option<ServerTls> {
        Some(self.0.clone())
    }
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        response.extend_from_slice(query);
        Action::Respond
    }
}

#[tokio::test]
async fn exchanges_with_the_pharos_quic_listener() {
    let key = || ListenerKey {
        transport: Transport::Quic,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let mut listeners = ListenerRegistry::default();
    listeners
        .apply(std::collections::HashMap::from([(key(), Echo(identity()))]))
        .await
        .unwrap();
    let address = listeners.get(&key()).unwrap().local_addr();
    let client = client(address, None);
    let connection = connect(&client).await;
    for _ in 0..2 {
        assert_eq!(exchange(&connection, QUERY).await.unwrap(), QUERY);
    }
    listeners.shutdown().await.unwrap();
}
