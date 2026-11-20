use pharos_plugins::proxy::{Error, Health, HealthConfig, Options, Proxy, Tls, Transport};
use pharos_server::{
    metrics::Registry,
    tls::{
        ClientAuth, ClientOptions, ServerName, ServerOptions, ServerTls, TlsAcceptor, client_config,
    },
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const QUERY: &[u8] = &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

struct DotServer {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    queries: Arc<AtomicUsize>,
}

fn acceptor() -> TlsAcceptor {
    ServerTls::load(&ServerOptions {
        cert: format!("{FIXTURES}/server.pem").into(),
        key: format!("{FIXTURES}/server.key.pem").into(),
        ca: None,
        client_auth: ClientAuth::NoCert,
        keylog: None,
    })
    .unwrap()
    .acceptor()
}

// RFC 7858 §3.3: DNS Messages over TLS use the two-octet length framing of RFC 1035 §4.2.2.
async fn dot_server() -> DotServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    let queries = Arc::new(AtomicUsize::new(0));
    let served = Arc::clone(&queries);
    let acceptor = acceptor();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let served = Arc::clone(&served);
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut wire = [0; 512];
                while let Ok(len) = stream.read_u16().await {
                    let len = usize::from(len);
                    stream.read_exact(&mut wire[..len]).await.unwrap();
                    served.fetch_add(1, Ordering::SeqCst);
                    wire[2] |= 0x80;
                    stream.write_u16(len as u16).await.unwrap();
                    stream.write_all(&wire[..len]).await.unwrap();
                    stream.flush().await.unwrap();
                }
            });
        }
    });
    DotServer {
        address,
        accepted,
        queries,
    }
}

fn tls(name: &str, ca: &str) -> Tls {
    let config = client_config(&ClientOptions {
        ca: Some(format!("{FIXTURES}/{ca}").into()),
        identity: None,
    })
    .unwrap();
    Tls {
        config,
        server_name: ServerName::try_from(name.to_owned()).unwrap(),
    }
}

fn proxy(server: &DotServer, name: &str) -> Proxy {
    let mut proxy = Proxy::new(server.address);
    proxy.set_tls(tls(name, "ca.pem"));
    proxy
}

#[tokio::test]
async fn exchanges_a_query_with_a_dot_upstream() {
    let server = dot_server().await;
    let proxy = proxy(&server, "localhost");
    let mut response = [0; 512];
    let result = proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await
        .unwrap();
    assert_eq!(result.transport, Transport::Tls);
    assert_eq!(result.len, QUERY.len());
    assert_eq!(&response[..2], &QUERY[..2]);
    assert_ne!(response[2] & 0x80, 0);
}

#[tokio::test]
async fn reuses_one_tls_connection_for_later_queries() {
    let server = dot_server().await;
    let proxy = proxy(&server, "localhost");
    let mut response = [0; 512];
    for _ in 0..3 {
        proxy
            .exchange(QUERY, &mut response, Transport::Tcp, Options::default())
            .await
            .unwrap();
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn expired_tls_connection_is_replaced() {
    let server = dot_server().await;
    let mut proxy = proxy(&server, "localhost");
    proxy.set_expire(Duration::from_millis(50));
    let mut response = [0; 512];
    proxy
        .exchange(QUERY, &mut response, Transport::Tcp, Options::default())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    proxy
        .exchange(QUERY, &mut response, Transport::Tcp, Options::default())
        .await
        .unwrap();
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
}

// CoreDNS v1.15.0 plugin/forward README: force_tcp and prefer_udp do not change a DoT upstream.
#[tokio::test]
async fn force_tcp_and_prefer_udp_do_not_change_a_dot_upstream() {
    let server = dot_server().await;
    let proxy = proxy(&server, "localhost");
    let mut response = [0; 512];
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
        let result = proxy
            .exchange(QUERY, &mut response, Transport::Udp, options)
            .await
            .unwrap();
        assert_eq!(result.transport, Transport::Tls);
    }
}

#[tokio::test]
async fn wrong_server_name_fails_the_handshake() {
    let server = dot_server().await;
    let proxy = proxy(&server, "wrong.example");
    let mut response = [0; 512];
    let result = proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await;
    assert!(matches!(result, Err(Error::Io(_))), "{result:?}");
}

#[tokio::test]
async fn certificate_from_an_untrusted_ca_fails_the_handshake() {
    let server = dot_server().await;
    let mut proxy = Proxy::new(server.address);
    proxy.set_tls(tls("localhost", "other-ca.pem"));
    let mut response = [0; 512];
    let result = proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await;
    assert!(matches!(result, Err(Error::Io(_))), "{result:?}");
}

#[tokio::test]
async fn handshake_failure_marks_the_upstream_unhealthy() {
    let server = dot_server().await;
    let mut proxy = proxy(&server, "wrong.example");
    let mut health = HealthConfig::new(server.address, 1);
    health.interval = Duration::from_millis(10);
    proxy.set_health_config(health);
    let mut response = [0; 512];
    assert!(
        proxy
            .exchange(QUERY, &mut response, Transport::Udp, Options::default())
            .await
            .is_err()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !proxy.down() {
        assert!(Instant::now() < deadline, "upstream never marked down");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// CoreDNS v1.15.0 plugin/pkg/proxy/health.go: a DoT Upstream is probed over DoT.
#[tokio::test]
async fn health_probe_reaches_a_dot_upstream_over_tls() {
    let server = dot_server().await;
    let mut config = HealthConfig::new(server.address, 1);
    config.tls = Some(tls("localhost", "ca.pem"));
    let health = Health::with_config(config);
    health.start();
    let deadline = Instant::now() + Duration::from_secs(5);
    while server.queries.load(Ordering::SeqCst) == 0 {
        assert!(Instant::now() < deadline, "no probe reached the server");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(health.fails(), 0);
}

#[tokio::test]
async fn health_probe_fails_when_the_server_name_does_not_match() {
    let server = dot_server().await;
    let mut config = HealthConfig::new(server.address, 1);
    config.tls = Some(tls("wrong.example", "ca.pem"));
    config.interval = Duration::from_millis(10);
    let health = Health::with_config(config);
    health.start();
    let deadline = Instant::now() + Duration::from_secs(5);
    while health.fails() < 2 {
        assert!(Instant::now() < deadline, "probe never failed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.queries.load(Ordering::SeqCst), 0);
}

// CoreDNS v1.15.0 plugin/forward README: the dial timeout bounds the TCP dial plus the TLS handshake.
#[tokio::test]
async fn connect_deadline_bounds_a_stalled_handshake() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let _stalled = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let mut proxy = Proxy::new(address);
    proxy.set_tls(tls("localhost", "ca.pem"));
    let mut response = [0; 512];
    let started = Instant::now();
    let result = proxy
        .exchange(
            QUERY,
            &mut response,
            Transport::Udp,
            Options {
                tls_connect_deadline: Some(
                    tokio::time::Instant::now() + Duration::from_millis(100),
                ),
                ..Options::default()
            },
        )
        .await;
    assert!(
        matches!(&result, Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut),
        "{result:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn connection_cache_metrics_use_the_tcp_tls_label() {
    let server = dot_server().await;
    let registry = Registry::new("v", "r", "rust");
    let mut proxy = proxy(&server, "localhost");
    proxy.set_metrics(&registry, "forward");
    let mut response = [0; 512];
    for _ in 0..2 {
        proxy
            .exchange(QUERY, &mut response, Transport::Udp, Options::default())
            .await
            .unwrap();
    }
    let mut metrics = String::new();
    registry.encode(&mut metrics);
    assert!(
        metrics.lines().any(|line| {
            line.starts_with("pharos_proxy_conn_cache_misses_total{")
                && line.contains("proto=\"tcp-tls\"")
                && line.ends_with(" 1")
        }),
        "{metrics}"
    );
    assert!(
        metrics.lines().any(|line| {
            line.starts_with("pharos_proxy_conn_cache_hits_total{")
                && line.contains("proto=\"tcp-tls\"")
                && line.ends_with(" 1")
        }),
        "{metrics}"
    );
    assert!(!metrics.contains("proto=\"udp\""), "{metrics}");
}
