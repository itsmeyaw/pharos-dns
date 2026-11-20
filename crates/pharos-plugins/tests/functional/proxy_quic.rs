use pharos_plugins::proxy::{Doq, Error, Health, HealthConfig, Options, Proxy, Tls, Transport};
use pharos_proto::{Message, Type};
use pharos_server::{
    metrics::Registry,
    tls::{ClientOptions, ServerName, ServerOptions, ServerTls, client_config},
};
use quinn::{Connection, Endpoint, ReadExactError, RecvStream, SendStream, ServerConfig, VarInt};
use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{Barrier, mpsc},
    time::timeout,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

// RFC 6891 §6.1.2 OPT with the options bytes, RFC 7828 §3.2.1 edns-tcp-keepalive being option 11.
const KEEPALIVE: &[u8] = &[0, 11, 0, 2, 0, 10];

// RFC 1035 §4.1: a Query for `example.org. A` with the given ID and EDNS option bytes.
fn query(id: u16, name: &[u8], options: &[u8]) -> Vec<u8> {
    let mut wire = id.to_be_bytes().to_vec();
    wire.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, u8::from(!options.is_empty())]);
    wire.extend_from_slice(name);
    wire.extend_from_slice(&[0, 1, 0, 1]);
    if !options.is_empty() {
        wire.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0]);
        wire.extend_from_slice(&u16::try_from(options.len()).unwrap().to_be_bytes());
        wire.extend_from_slice(options);
    }
    wire
}

const EXAMPLE: &[u8] = b"\x07example\x03org\0";

fn reply(query: &[u8], id: u16) -> Vec<u8> {
    let mut response = query.to_vec();
    response[..2].copy_from_slice(&id.to_be_bytes());
    response[2] |= 0x80;
    response
}

// RFC 9250 §4.2: each message is preceded by its two-octet length.
fn frame(message: &[u8]) -> Vec<u8> {
    let mut wire = u16::try_from(message.len()).unwrap().to_be_bytes().to_vec();
    wire.extend_from_slice(message);
    wire
}

fn tls(name: &str) -> Tls {
    let config = client_config(&ClientOptions {
        ca: Some(format!("{FIXTURES}/ca.pem").into()),
        identity: None,
    })
    .unwrap();
    Tls {
        config,
        server_name: ServerName::try_from(name.to_owned()).unwrap(),
    }
}

struct Server {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    streams: Arc<AtomicUsize>,
    connections: Arc<Mutex<Vec<Connection>>>,
}

/// A DoQ server that hands each stream's Query to `handler`.
fn serve<F, Fut>(handler: F) -> Server
where
    F: Fn(usize, Connection, Vec<u8>, SendStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let identity = ServerTls::load(&ServerOptions {
        cert: format!("{FIXTURES}/server.pem").into(),
        key: format!("{FIXTURES}/server.key.pem").into(),
        ca: None,
        client_auth: pharos_server::tls::ClientAuth::NoCert,
        keylog: None,
    })
    .unwrap();
    let endpoint = Endpoint::server(
        ServerConfig::with_crypto(identity.quic()),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = endpoint.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let streams = Arc::new(AtomicUsize::new(0));
    let connections = Arc::new(Mutex::new(Vec::new()));
    let handler = Arc::new(handler);
    let (count, served, known) = (
        Arc::clone(&accepted),
        Arc::clone(&streams),
        Arc::clone(&connections),
    );
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let number = count.fetch_add(1, Ordering::SeqCst) + 1;
            let (handler, served, known) = (
                Arc::clone(&handler),
                Arc::clone(&served),
                Arc::clone(&known),
            );
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                known.lock().unwrap().push(connection.clone());
                while let Ok((send, mut recv)) = connection.accept_bi().await {
                    served.fetch_add(1, Ordering::SeqCst);
                    let (handler, connection) = (Arc::clone(&handler), connection.clone());
                    tokio::spawn(async move {
                        if let Some(query) = read_query(&mut recv).await {
                            handler(number, connection, query, send).await;
                        }
                    });
                }
            });
        }
    });
    Server {
        address,
        accepted,
        streams,
        connections,
    }
}

async fn read_query(recv: &mut RecvStream) -> Option<Vec<u8>> {
    let mut prefix = [0; 2];
    recv.read_exact(&mut prefix).await.ok()?;
    let mut query = vec![0; usize::from(u16::from_be_bytes(prefix))];
    match recv.read_exact(&mut query).await {
        Ok(()) => Some(query),
        Err(ReadExactError::FinishedEarly(_) | ReadExactError::ReadError(_)) => None,
    }
}

async fn answer(mut send: SendStream, bytes: &[u8]) {
    let _ = send.write_all(bytes).await;
    let _ = send.finish();
}

/// A server that answers every Query with `reply` (ID zero).
fn echo() -> Server {
    serve(|_, _, query, send| async move { answer(send, &frame(&reply(&query, 0))).await })
}

fn proxy(server: &Server, name: &str) -> Proxy {
    let mut proxy = Proxy::new(server.address);
    proxy.set_quic(tls(name));
    proxy
}

async fn exchange(proxy: &Proxy, query: &[u8]) -> Result<(Vec<u8>, Transport), Error> {
    let mut response = vec![0; 65535];
    let exchange = proxy
        .exchange(query, &mut response, Transport::Udp, Options::default())
        .await?;
    response.truncate(exchange.len);
    Ok((response, exchange.transport))
}

// RFC 9250 §4.2.1 and CoreDNS v1.15.0 plugin/pkg/proxy/doq.go exchange: ID zero upstream, the client's ID back.
#[tokio::test]
async fn exchanges_a_query_with_a_doq_upstream() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let server = serve(move |_, connection, query, send| {
        let log = Arc::clone(&log);
        async move {
            let alpn = connection
                .handshake_data()
                .unwrap()
                .downcast::<quinn::crypto::rustls::HandshakeData>()
                .unwrap()
                .protocol;
            log.lock().unwrap().push((query.clone(), alpn));
            answer(send, &frame(&reply(&query, 0))).await;
        }
    });
    let proxy = proxy(&server, "localhost");
    let request = query(0x1234, EXAMPLE, KEEPALIVE);
    let (response, transport) = exchange(&proxy, &request).await.unwrap();
    assert_eq!(transport, Transport::Quic);
    assert_eq!(&response[..2], &[0x12, 0x34]);
    assert_ne!(response[2] & 0x80, 0);
    let seen = seen.lock().unwrap();
    let (upstream, alpn) = &seen[0];
    assert_eq!(&upstream[..2], &[0, 0]);
    assert_eq!(alpn.as_deref(), Some(&b"doq"[..]));
    // RFC 9250 §4.2.1: the edns-tcp-keepalive option never goes to a DoQ server.
    let upstream = Message::parse(upstream).unwrap();
    assert_eq!(upstream.opt().unwrap().options().iter().count(), 0);
}

#[tokio::test]
async fn doq_upstream_ignores_force_tcp_and_prefer_udp() {
    let server = echo();
    let proxy = proxy(&server, "localhost");
    let request = query(7, EXAMPLE, &[]);
    for options in [
        Options {
            force_tcp: true,
            ..Options::default()
        },
        Options {
            prefer_udp: true,
            ..Options::default()
        },
    ] {
        let mut response = vec![0; 65535];
        let exchange = proxy
            .exchange(&request, &mut response, Transport::Tcp, options)
            .await
            .unwrap();
        assert_eq!(exchange.transport, Transport::Quic);
    }
}

// RFC 6125 §6.4.1: CoreDNS v1.15.0 TestProxyDoQVerifiesServerName.
#[tokio::test]
async fn wrong_server_name_fails_the_handshake() {
    let server = echo();
    let proxy = proxy(&server, "wrong.example");
    let result = exchange(&proxy, &query(1, EXAMPLE, &[])).await;
    assert!(matches!(result, Err(Error::Io(_))), "{result:?}");
}

// CoreDNS v1.15.0 TestProxyDoQSourceAddress.
#[tokio::test]
async fn binds_the_source_address() {
    let remote = Arc::new(Mutex::new(None));
    let seen = Arc::clone(&remote);
    let server = serve(move |_, connection, query, send| {
        *seen.lock().unwrap() = Some(connection.remote_address());
        async move { answer(send, &frame(&reply(&query, 0))).await }
    });
    let mut proxy = proxy(&server, "localhost");
    proxy.set_source_address(Some("127.0.0.2".parse().unwrap()));
    let mut response = vec![0; 65535];
    let exchange = proxy
        .exchange(
            &query(1, EXAMPLE, &[]),
            &mut response,
            Transport::Udp,
            Options::default(),
        )
        .await
        .unwrap();
    assert_eq!(exchange.local_addr.ip().to_string(), "127.0.0.2");
    assert_eq!(
        remote.lock().unwrap().unwrap().ip().to_string(),
        "127.0.0.2"
    );
}

// CoreDNS v1.15.0 TestProxyDoQReusesOneConnectionForConcurrentQueries.
#[tokio::test]
async fn concurrent_queries_share_one_connection() {
    const QUERIES: usize = 16;
    let barrier = Arc::new(Barrier::new(QUERIES));
    let server = serve(move |_, _, query, send| {
        let barrier = Arc::clone(&barrier);
        async move {
            // Every Query must be in flight at once before any is answered.
            barrier.wait().await;
            answer(send, &frame(&reply(&query, 0))).await;
        }
    });
    let proxy = Arc::new(proxy(&server, "localhost"));
    let tasks = (0..QUERIES)
        .map(|i| {
            let proxy = Arc::clone(&proxy);
            tokio::spawn(async move {
                let id = u16::try_from(i + 1).unwrap();
                let (response, _) = exchange(&proxy, &query(id, EXAMPLE, &[])).await.unwrap();
                assert_eq!(u16::from_be_bytes([response[0], response[1]]), id);
            })
        })
        .collect::<Vec<_>>();
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
    assert_eq!(server.streams.load(Ordering::SeqCst), QUERIES);
}

// CoreDNS v1.15.0 TestProxyDoQCancellationDoesNotCloseConnection.
#[tokio::test]
async fn abandoning_a_query_keeps_the_connection() {
    let server = serve(|_, _, query, send| async move {
        if query.windows(4).any(|window| window == b"slow") {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        answer(send, &frame(&reply(&query, 0))).await;
    });
    let proxy = proxy(&server, "localhost");
    let slow = query(1, b"\x04slow\x07example\0", &[]);
    let abandoned = timeout(Duration::from_millis(75), exchange(&proxy, &slow)).await;
    assert!(abandoned.is_err());
    exchange(&proxy, &query(2, EXAMPLE, &[])).await.unwrap();
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

async fn wait_closed(server: &Server, number: usize) {
    timeout(TEST_TIMEOUT, async {
        loop {
            let closed = server
                .connections
                .lock()
                .unwrap()
                .get(number)
                .is_some_and(|connection| connection.close_reason().is_some());
            if closed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

// CoreDNS v1.15.0 TestProxyDoQReplacesClosedConnection.
#[tokio::test]
async fn replaces_a_connection_the_server_closed() {
    let server = serve(|number, connection, query, send| async move {
        answer(send, &frame(&reply(&query, 0))).await;
        if number == 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            connection.close(VarInt::from_u32(0), b"rotate test connection");
        }
    });
    let proxy = proxy(&server, "localhost");
    exchange(&proxy, &query(1, EXAMPLE, &[])).await.unwrap();
    wait_closed(&server, 0).await;
    exchange(&proxy, &query(2, EXAMPLE, &[])).await.unwrap();
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
}

// RFC 9250 §4.3.3 and CoreDNS v1.15.0 TestProxyDoQProtocolErrorRetiresConnection.
#[tokio::test]
async fn protocol_error_retires_the_connection() {
    let server = serve(|number, _, query, send| async move {
        let id = u16::from(number == 1);
        answer(send, &frame(&reply(&query, id))).await;
    });
    let proxy = proxy(&server, "localhost");
    let first = exchange(&proxy, &query(10, EXAMPLE, &[])).await;
    assert!(matches!(first, Err(Error::Io(_))), "{first:?}");
    let (response, _) = exchange(&proxy, &query(11, EXAMPLE, &[])).await.unwrap();
    assert_eq!(&response[..2], &[0, 11]);
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
    wait_closed(&server, 0).await;
}

// CoreDNS v1.15.0 TestProxyDoQRejectsZoneTransferBeforeDial.
#[tokio::test]
async fn zone_transfers_are_rejected_before_dialing() {
    let server = echo();
    let proxy = proxy(&server, "localhost");
    for qtype in [Type::AXFR, Type::IXFR] {
        let mut request = query(1, EXAMPLE, &[]);
        let end = request.len();
        request[end - 4..end - 2].copy_from_slice(&qtype.0.to_be_bytes());
        let result = exchange(&proxy, &request).await;
        assert!(
            matches!(result, Err(Error::UnsupportedRequest)),
            "{result:?}"
        );
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 0);
}

// CoreDNS v1.15.0 TestDoQConnectionExpiryAndMaxAge.
#[tokio::test]
async fn expired_and_old_connections_are_replaced() {
    for (expire, max_age) in [
        (Duration::from_millis(20), Duration::ZERO),
        (Duration::from_secs(3600), Duration::from_millis(20)),
    ] {
        let server = echo();
        let mut proxy = proxy(&server, "localhost");
        proxy.set_expire(expire);
        proxy.set_max_age(max_age);
        exchange(&proxy, &query(1, EXAMPLE, &[])).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        exchange(&proxy, &query(2, EXAMPLE, &[])).await.unwrap();
        assert_eq!(server.accepted.load(Ordering::SeqCst), 2, "{expire:?}");
    }
}

// CoreDNS v1.15.0 TestDoQStopCancelsDial.
#[tokio::test]
async fn stop_cancels_an_unfinished_handshake() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut proxy = Proxy::new(silent.local_addr().unwrap());
    proxy.set_quic(tls("localhost"));
    let proxy = Arc::new(proxy);
    let pending = {
        let proxy = Arc::clone(&proxy);
        tokio::spawn(async move { exchange(&proxy, &query(1, EXAMPLE, &[])).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    proxy.stop();
    let result = timeout(Duration::from_secs(1), pending)
        .await
        .expect("stop must end the dial")
        .unwrap();
    assert!(result.is_err());
    let after = exchange(&proxy, &query(2, EXAMPLE, &[])).await;
    assert!(matches!(after, Err(Error::Stopped)), "{after:?}");
}

// CoreDNS v1.15.0 TestDoQHealthCheck: the probe asks `NS` for the health domain with ID zero.
#[tokio::test]
async fn health_probe_reaches_a_doq_upstream() {
    let (sender, mut receiver) = mpsc::unbounded_channel();
    let server = serve(move |_, _, query, send| {
        sender.send(query.clone()).unwrap();
        async move { answer(send, &frame(&reply(&query, 0))).await }
    });
    let mut config = HealthConfig::new(server.address, 1);
    config.domain = "health.example.".parse().unwrap();
    config.recursive = false;
    config.doq = Some(Doq::new(server.address, tls("localhost")));
    let health = Health::with_config(config);
    health.start();
    let probe = timeout(TEST_TIMEOUT, receiver.recv())
        .await
        .unwrap()
        .unwrap();
    let message = Message::parse(&probe).unwrap();
    let question = message.questions().next().unwrap();
    assert_eq!(question.name.to_string(), "health.example.");
    assert_eq!(question.qtype, Type::NS);
    assert!(!message.rd());
    assert_eq!(message.id(), 0);
    assert_eq!(health.fails(), 0);
}

#[tokio::test]
async fn health_probe_fails_when_the_server_name_does_not_match() {
    let server = echo();
    let mut config = HealthConfig::new(server.address, 1);
    config.interval = Duration::from_millis(10);
    config.doq = Some(Doq::new(server.address, tls("wrong.example")));
    let health = Health::with_config(config);
    health.start();
    let deadline = Instant::now() + TEST_TIMEOUT;
    while health.fails() < 2 {
        assert!(Instant::now() < deadline, "probe never failed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.streams.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn failed_exchange_marks_the_upstream_unhealthy() {
    let server = echo();
    let mut proxy = proxy(&server, "wrong.example");
    let mut health = HealthConfig::new(server.address, 1);
    health.interval = Duration::from_millis(10);
    proxy.set_health_config(health);
    assert!(exchange(&proxy, &query(1, EXAMPLE, &[])).await.is_err());
    let deadline = Instant::now() + TEST_TIMEOUT;
    while !proxy.down() {
        assert!(Instant::now() < deadline, "upstream never marked down");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// CoreDNS v1.15.0 plugin/pkg/proxy/doq.go acquire: cache hits and misses count under proto "quic".
#[tokio::test]
async fn connection_cache_metrics_use_the_quic_label() {
    let server = echo();
    let registry = Registry::new("v", "r", "rust");
    let mut proxy = proxy(&server, "localhost");
    proxy.set_metrics(&registry, "forward");
    for id in 1..=2 {
        exchange(&proxy, &query(id, EXAMPLE, &[])).await.unwrap();
    }
    let mut metrics = String::new();
    registry.encode(&mut metrics);
    for family in ["misses", "hits"] {
        assert!(
            metrics.lines().any(|line| {
                line.starts_with(&format!("pharos_proxy_conn_cache_{family}_total{{"))
                    && line.contains("proto=\"quic\"")
                    && line.ends_with(" 1")
            }),
            "{family}: {metrics}"
        );
    }
    assert!(!metrics.contains("proto=\"udp\""), "{metrics}");
    assert!(!metrics.contains("proto=\"tcp"), "{metrics}");
}
