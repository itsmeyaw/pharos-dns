use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode, Version, body::Incoming, server::conn::http1,
    server::conn::http2, service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pharos_plugins::proxy::{Error, Health, HealthConfig, Https, Options, Proxy, Tls, Transport};
use pharos_server::{
    doh,
    metrics::Registry,
    tls::{ClientAuth, ClientOptions, ServerName, ServerOptions, ServerTls, client_config},
};
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::net::TcpListener;

const QUERY: &[u8] = &[
    0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
];
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

/// What the DoH server saw of one request.
#[derive(Clone, Debug)]
struct Seen {
    method: Method,
    uri: String,
    host: Option<String>,
    version: Version,
    content_type: Option<String>,
    accept: Option<String>,
    wire: Vec<u8>,
}

struct DohServer {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl DohServer {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

// RFC 8484 §4.2: the Response is the Query's Message with QR set, in `application/dns-message`.
async fn doh_server(alpn: &'static [&'static [u8]], status: StatusCode) -> DohServer {
    let acceptor = ServerTls::load(&ServerOptions {
        cert: format!("{FIXTURES}/server.pem").into(),
        key: format!("{FIXTURES}/server.key.pem").into(),
        ca: None,
        client_auth: ClientAuth::NoCert,
        keylog: None,
    })
    .unwrap()
    .with_alpn(alpn)
    .acceptor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (count, record) = (Arc::clone(&accepted), Arc::clone(&seen));
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let (acceptor, record) = (acceptor.clone(), Arc::clone(&record));
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
                let io = TokioIo::new(tls);
                let service = service_fn(move |request: Request<Incoming>| {
                    let record = Arc::clone(&record);
                    async move {
                        let (parts, body) = request.into_parts();
                        let header = |name: &str| {
                            parts
                                .headers
                                .get(name)
                                .map(|value| value.to_str().unwrap().to_owned())
                        };
                        let wire = match doh::locate(&parts.method, &parts.uri) {
                            Ok(doh::Source::Get(value)) => {
                                let mut wire = Vec::new();
                                doh::decode_get(value, &mut wire).unwrap();
                                wire
                            }
                            _ => body.collect().await.unwrap().to_bytes().to_vec(),
                        };
                        record.lock().unwrap().push(Seen {
                            method: parts.method.clone(),
                            uri: parts.uri.to_string(),
                            host: header("host")
                                .or_else(|| parts.uri.authority().map(|a| a.to_string())),
                            version: parts.version,
                            content_type: header("content-type"),
                            accept: header("accept"),
                            wire: wire.clone(),
                        });
                        let mut answer = wire;
                        answer[2] |= 0x80;
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(status)
                                .header("content-type", doh::MEDIA_TYPE)
                                .body(Full::new(Bytes::from(answer)))
                                .unwrap(),
                        )
                    }
                });
                if h2 {
                    let _ = http2::Builder::new(TokioExecutor::new())
                        .serve_connection(io, service)
                        .await;
                } else {
                    let _ = http1::Builder::new().serve_connection(io, service).await;
                }
            });
        }
    });
    DohServer {
        address,
        accepted,
        seen,
    }
}

const H2: &[&[u8]] = &[b"h2", b"http/1.1"];
const H1: &[&[u8]] = &[b"http/1.1"];

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

fn proxy(server: &DohServer, name: &str, method: Method) -> Proxy {
    let mut proxy = Proxy::new(server.address);
    proxy.set_https(Https::new(server.address, tls(name, "ca.pem"), method));
    proxy
}

async fn exchange(proxy: &Proxy) -> Result<(usize, [u8; 512]), Error> {
    let mut response = [0; 512];
    let result = proxy
        .exchange(QUERY, &mut response, Transport::Udp, Options::default())
        .await?;
    assert_eq!(result.transport, Transport::Https);
    Ok((result.len, response))
}

// CoreDNS v1.15.0 plugin/forward/proxy_test.go TestProxyHTTPS: the Response of a DoH Upstream is relayed.
#[tokio::test]
async fn exchanges_a_query_with_a_doh_upstream_over_post() {
    let server = doh_server(H2, StatusCode::OK).await;
    let proxy = proxy(&server, "localhost", Method::POST);
    let (len, response) = exchange(&proxy).await.unwrap();
    assert_eq!(len, QUERY.len());
    // RFC 1035 §4.1.1: the Response carries the Query's ID again.
    assert_eq!(&response[..2], &QUERY[..2]);
    assert_ne!(response[2] & 0x80, 0);
    let seen = server.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, Method::POST);
    assert_eq!(seen[0].uri, "https://localhost/dns-query");
    assert_eq!(seen[0].content_type.as_deref(), Some(doh::MEDIA_TYPE));
    assert_eq!(seen[0].accept.as_deref(), Some(doh::MEDIA_TYPE));
    // RFC 8484 §4.1: the Message ID is 0 on the wire.
    assert_eq!(&seen[0].wire[..2], &[0, 0]);
    assert_eq!(&seen[0].wire[2..], &QUERY[2..]);
}

#[tokio::test]
async fn doh_method_get_carries_the_query_in_the_dns_variable() {
    let server = doh_server(H2, StatusCode::OK).await;
    let proxy = proxy(&server, "localhost", Method::GET);
    let (_, response) = exchange(&proxy).await.unwrap();
    assert_eq!(&response[..2], &QUERY[..2]);
    let seen = server.seen();
    assert_eq!(seen[0].method, Method::GET);
    assert!(
        seen[0].uri.starts_with("https://localhost/dns-query?dns="),
        "{}",
        seen[0].uri
    );
    assert_eq!(&seen[0].wire[..2], &[0, 0]);
}

// CoreDNS v1.15.0 plugin/pkg/doh NewRequestWithContext: without a configured name the Host is the Upstream's IP address.
#[tokio::test]
async fn host_is_the_upstream_address_without_a_server_name() {
    let server = doh_server(H2, StatusCode::OK).await;
    let mut proxy = Proxy::new(server.address);
    let mut tls = tls("localhost", "ca.pem");
    tls.server_name = ServerName::from(server.address.ip());
    proxy.set_https(Https::new(server.address, tls, Method::POST));
    exchange(&proxy).await.unwrap();
    assert_eq!(
        server.seen()[0].host.as_deref(),
        Some(server.address.to_string().as_str())
    );
}

// RFC 9113 §5.1.2: concurrent Queries are streams of one HTTP/2 connection.
#[tokio::test]
async fn concurrent_queries_share_one_http2_connection() {
    let server = doh_server(H2, StatusCode::OK).await;
    let proxy = proxy(&server, "localhost", Method::POST);
    exchange(&proxy).await.unwrap();
    let results = futures_join(&proxy).await;
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
    assert!(
        server
            .seen()
            .iter()
            .all(|seen| seen.version == Version::HTTP_2)
    );
    assert_eq!(server.seen().len(), 6);
}

async fn futures_join(proxy: &Proxy) -> Vec<Result<(usize, [u8; 512]), Error>> {
    let (a, b, c, d, e) = tokio::join!(
        exchange(proxy),
        exchange(proxy),
        exchange(proxy),
        exchange(proxy),
        exchange(proxy)
    );
    vec![a, b, c, d, e]
}

// RFC 9112 §9.3: a server without `h2` is reached over persistent HTTP/1.1 connections.
#[tokio::test]
async fn falls_back_to_http1_and_reuses_the_connection() {
    let server = doh_server(H1, StatusCode::OK).await;
    let proxy = proxy(&server, "localhost", Method::POST);
    for _ in 0..3 {
        exchange(&proxy).await.unwrap();
    }
    assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
    let seen = server.seen();
    assert!(seen.iter().all(|seen| seen.version == Version::HTTP_11));
    assert_eq!(seen[0].uri, "/dns-query");
    assert_eq!(seen[0].host.as_deref(), Some("localhost"));
}

#[tokio::test]
async fn expired_connection_is_replaced() {
    let server = doh_server(H2, StatusCode::OK).await;
    let mut proxy = proxy(&server, "localhost", Method::POST);
    proxy.set_expire(Duration::from_millis(50));
    exchange(&proxy).await.unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;
    exchange(&proxy).await.unwrap();
    assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
}

// RFC 8484 §4.2.1: a non-2xx status is not a Response, whatever its body holds. CoreDNS accepts it.
#[tokio::test]
async fn a_non_success_status_is_an_upstream_failure() {
    let server = doh_server(H2, StatusCode::SERVICE_UNAVAILABLE).await;
    let proxy = proxy(&server, "localhost", Method::POST);
    let result = exchange(&proxy).await;
    assert!(matches!(result, Err(Error::Io(_))), "{result:?}");
}

#[tokio::test]
async fn wrong_server_name_fails_the_handshake() {
    let server = doh_server(H2, StatusCode::OK).await;
    let proxy = proxy(&server, "wrong.example", Method::POST);
    let result = exchange(&proxy).await;
    assert!(matches!(result, Err(Error::Io(_))), "{result:?}");
    assert!(server.seen().is_empty());
}

#[tokio::test]
async fn certificate_from_an_untrusted_ca_fails_the_handshake() {
    let server = doh_server(H2, StatusCode::OK).await;
    let mut proxy = Proxy::new(server.address);
    proxy.set_https(Https::new(
        server.address,
        tls("localhost", "other-ca.pem"),
        Method::POST,
    ));
    let result = exchange(&proxy).await;
    assert!(matches!(result, Err(Error::Io(_))), "{result:?}");
}

// RFC 8484 §4.1: ID 0 keeps identical Queries cacheable; RFC 8945 §5.5: a signed Query is sent unchanged.
#[tokio::test]
async fn a_signed_query_keeps_its_id() {
    let server = doh_server(H2, StatusCode::OK).await;
    let proxy = proxy(&server, "localhost", Method::POST);
    // ARCOUNT 1: a TSIG record named `k` with the root as algorithm, no MAC and no error.
    let mut signed = QUERY.to_vec();
    signed[11] = 1;
    signed.extend_from_slice(&[
        1, b'k', 0, 0, 250, 0, 255, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 1, 0x2c, 0, 0, 0x12,
        0x34, 0, 0, 0, 0,
    ]);
    let mut response = [0; 512];
    // The hand-built record need not verify; the Upstream is only asked to see it unchanged.
    let _ = proxy
        .exchange(&signed, &mut response, Transport::Udp, Options::default())
        .await;
    let seen = server.seen();
    assert_eq!(seen[0].wire, signed);
}

#[tokio::test]
async fn connection_cache_metrics_use_the_https_label() {
    let server = doh_server(H2, StatusCode::OK).await;
    let registry = Registry::new("v", "r", "rust");
    let mut proxy = proxy(&server, "localhost", Method::POST);
    proxy.set_metrics(&registry, "forward");
    for _ in 0..2 {
        exchange(&proxy).await.unwrap();
    }
    let mut metrics = String::new();
    registry.encode(&mut metrics);
    for (name, count) in [("misses", 1), ("hits", 1)] {
        assert!(
            metrics.lines().any(|line| {
                line.starts_with(&format!("pharos_proxy_conn_cache_{name}_total{{"))
                    && line.contains("proto=\"https\"")
                    && line.ends_with(&format!(" {count}"))
            }),
            "{metrics}"
        );
    }
    assert!(!metrics.contains("proto=\"udp\""), "{metrics}");
    assert!(!metrics.contains("proto=\"tcp-tls\""), "{metrics}");
}

// CoreDNS v1.15.0 plugin/pkg/proxy/health_test.go TestHealthHTTPS: the probe is a POST for `. NS` with RD.
#[tokio::test]
async fn health_probe_reaches_a_doh_upstream_over_https() {
    let server = doh_server(H2, StatusCode::OK).await;
    let mut config = HealthConfig::new(server.address, 1);
    config.https = Some(Https::new(
        server.address,
        tls("localhost", "ca.pem"),
        Method::GET,
    ));
    let health = Health::with_config(config);
    health.start();
    let deadline = Instant::now() + Duration::from_secs(5);
    while server.seen().is_empty() {
        assert!(Instant::now() < deadline, "no probe reached the server");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let seen = server.seen();
    assert_eq!(seen[0].method, Method::POST);
    // `. IN NS` with the RD bit set.
    assert_eq!(&seen[0].wire[2..4], &[1, 0]);
    assert_eq!(&seen[0].wire[12..], &[0, 0, 2, 0, 1]);
    assert_eq!(health.fails(), 0);
}

#[tokio::test]
async fn health_probe_fails_when_the_server_name_does_not_match() {
    let server = doh_server(H2, StatusCode::OK).await;
    let mut config = HealthConfig::new(server.address, 1);
    config.https = Some(Https::new(
        server.address,
        tls("wrong.example", "ca.pem"),
        Method::POST,
    ));
    config.interval = Duration::from_millis(10);
    let health = Health::with_config(config);
    health.start();
    let deadline = Instant::now() + Duration::from_secs(5);
    while health.fails() < 2 {
        assert!(Instant::now() < deadline, "probe never failed");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(server.seen().is_empty());
}

#[tokio::test]
async fn handshake_failure_marks_the_upstream_unhealthy() {
    let server = doh_server(H2, StatusCode::OK).await;
    let mut proxy = proxy(&server, "wrong.example", Method::POST);
    let mut health = HealthConfig::new(server.address, 1);
    health.interval = Duration::from_millis(10);
    proxy.set_health_config(health);
    assert!(exchange(&proxy).await.is_err());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !proxy.down() {
        assert!(Instant::now() < deadline, "upstream never marked down");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
