#![forbid(unsafe_code)]

use std::{
    alloc::System,
    io::{BufRead, BufReader, Read},
    net::SocketAddr,
    process::{Child, Command, Stdio},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, Uri,
    body::Incoming,
    client::conn::http2,
    header::{ACCEPT, CONTENT_TYPE, HeaderValue},
    server::conn::http2 as server_http2,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pharos_plugins::proxy::{Https, Options, Proxy, Tls, Transport};
use pharos_server::{
    doh,
    tls::{
        ClientAuth, ClientOptions, ServerName, ServerOptions, ServerTls, TlsConnector,
        client_config,
    },
};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
const WARM: usize = 10;
const MEASURED: usize = 40;
const QUERY: &[u8] = &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");
// RFC 8484 §4.1: `QUERY` with Message ID zero, as an unpadded base64url `dns` variable.
const GET_TARGET: &[u8] = b"https://localhost/dns-query?dns=AAABAAABAAAAAAAAAAACAAE";
const SERVER: &str = "PHAROS_DOH_SERVER";

// The DoH server runs in a child process, so its allocations stay out of the process-wide counter.
#[test]
fn doh_server() {
    if std::env::var_os(SERVER).is_none() {
        return;
    }
    let acceptor = ServerTls::load(&ServerOptions {
        cert: format!("{FIXTURES}/server.pem").into(),
        key: format!("{FIXTURES}/server.key.pem").into(),
        ca: None,
        client_auth: ClientAuth::NoCert,
        keylog: None,
    })
    .unwrap()
    .with_alpn(doh::ALPN)
    .acceptor();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    println!("ADDRESS {}", listener.local_addr().unwrap());
    runtime.spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let service = service_fn(|request: Request<Incoming>| async move {
                    let (parts, body) = request.into_parts();
                    let mut wire = match doh::locate(&parts.method, &parts.uri) {
                        Ok(doh::Source::Get(value)) => {
                            let mut wire = Vec::new();
                            doh::decode_get(value, &mut wire).unwrap();
                            wire
                        }
                        _ => body.collect().await.unwrap().to_bytes().to_vec(),
                    };
                    wire[2] |= 0x80;
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .header(CONTENT_TYPE, doh::MEDIA_TYPE)
                            .body(Full::new(Bytes::from(wire)))
                            .unwrap(),
                    )
                });
                let _ = server_http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    // The client closes our stdin when it is done.
    std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
}

fn spawn_server() -> (Child, SocketAddr) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "proxy::proxy_https_allocations::doh_server",
            "--nocapture",
        ])
        .env(SERVER, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let address = loop {
        let line = lines.next().expect("server exited").unwrap();
        if let Some(address) = line.strip_prefix("ADDRESS ") {
            break address.parse().unwrap();
        }
    };
    // The server prints nothing more; keep the pipe from filling or closing under it.
    std::mem::forget(lines);
    (child, address)
}

struct Counts {
    allocations: usize,
    reallocations: usize,
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn tls() -> Tls {
    Tls {
        config: client_config(&ClientOptions {
            ca: Some(format!("{FIXTURES}/ca.pem").into()),
            identity: None,
        })
        .unwrap(),
        server_name: ServerName::try_from("localhost".to_owned()).unwrap(),
    }
}

// What one DoH request costs in hyper, http and h2 alone: the same request and reply without Pharos.
fn bare_hyper(address: SocketAddr, method: &Method) -> Counts {
    let mut config = (*tls().config).clone();
    config.alpn_protocols = vec![b"h2".to_vec()];
    runtime().block_on(async {
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        tcp.set_nodelay(true).unwrap();
        let tls = TlsConnector::from(std::sync::Arc::new(config))
            .connect(tls().server_name, tcp)
            .await
            .unwrap();
        let (mut sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(connection);
        let post: Uri = "https://localhost/dns-query".parse().unwrap();
        let mut wire = QUERY.to_vec();
        wire[..2].fill(0);
        let body = Bytes::from(wire.clone());
        let mut out = Vec::with_capacity(512);
        let mut run = async |count: usize| {
            let before = GLOBAL.stats();
            for _ in 0..count {
                sender.ready().await.unwrap();
                let (uri, body) = if method == Method::POST {
                    (post.clone(), body.clone())
                } else {
                    (Uri::try_from(GET_TARGET).unwrap(), Bytes::new())
                };
                let request = Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(CONTENT_TYPE, HeaderValue::from_static(doh::MEDIA_TYPE))
                    .header(ACCEPT, HeaderValue::from_static(doh::MEDIA_TYPE))
                    .body(Full::new(body))
                    .unwrap();
                let (_, mut body) = sender.send_request(request).await.unwrap().into_parts();
                out.clear();
                while let Some(frame) = body.frame().await {
                    if let Ok(data) = frame.unwrap().into_data() {
                        out.extend_from_slice(&data);
                    }
                }
            }
            let after = GLOBAL.stats();
            Counts {
                allocations: after.allocations - before.allocations,
                reallocations: after.reallocations - before.reallocations,
            }
        };
        run(WARM).await;
        run(MEASURED).await
    })
}

fn plugin(address: SocketAddr, method: Method) -> Counts {
    let mut proxy = Proxy::new(address);
    proxy.set_https(Https::new(address, tls(), method));
    let registry = pharos_server::metrics::Registry::new("v", "r", "rust");
    proxy.set_metrics(&registry, "forward");
    runtime().block_on(async {
        let mut response = [0; 512];
        let mut query = async || {
            let result = proxy
                .exchange(QUERY, &mut response, Transport::Udp, Options::default())
                .await
                .unwrap();
            assert_eq!(result.transport, Transport::Https);
            assert_eq!(&response[..2], &QUERY[..2]);
        };
        for _ in 0..WARM {
            query().await;
        }
        let before = GLOBAL.stats();
        for _ in 0..MEASURED {
            query().await;
        }
        let after = GLOBAL.stats();
        Counts {
            allocations: after.allocations - before.allocations,
            reallocations: after.reallocations - before.reallocations,
        }
    })
}

fn check(name: &str, method: Method) {
    if crate::run_isolated(name) {
        return;
    }
    let (mut server, address) = spawn_server();
    let baseline = bare_hyper(address, &method);
    let measured = plugin(address, method);
    drop(server.stdin.take());
    server.wait().unwrap();
    println!(
        "bare hyper: {} allocations, {} reallocations; doh: {}, {}",
        baseline.allocations, baseline.reallocations, measured.allocations, measured.reallocations
    );
    // Whatever hyper, http and h2 allocate per request is theirs; Pharos adds none on top.
    assert!(measured.allocations <= baseline.allocations);
    assert!(measured.reallocations <= baseline.reallocations);
}

#[test]
fn warmed_doh_post_allocates_only_inside_hyper() {
    check(
        "proxy::proxy_https_allocations::warmed_doh_post_allocates_only_inside_hyper",
        Method::POST,
    );
}

#[test]
fn warmed_doh_get_allocates_only_inside_hyper() {
    check(
        "proxy::proxy_https_allocations::warmed_doh_get_allocates_only_inside_hyper",
        Method::GET,
    );
}
