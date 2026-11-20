#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-grpc", feature = "plugin-whoami"))]

use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{HeaderMap, Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers_with_registry};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{
    Action, Handler, Lifecycle, ListenerKey, ListenerRegistry, Phase, Protocol, Transport,
    grpc::{self, FramePrefix},
    metrics::Registry,
    tls::{ClientAuth, ServerOptions, ServerTls},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, UnixListener},
    task::AbortHandle,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

/// What the stub answers a call with.
#[derive(Clone)]
enum Reply {
    /// A DNS Message in one framed `DnsPacket`, status OK.
    Message(Vec<u8>),
    /// A Trailers-Only response with this `grpc-status`.
    Status(u8),
    /// This exact response body, status OK.
    Body(Vec<u8>),
    /// A reply with the wrong `content-type`.
    WrongContentType(Vec<u8>),
    /// `grpc-status: 0` in the initial headers, then a body and no trailers.
    HeaderStatusWithBody(Vec<u8>),
    Hang,
}

type Script = Arc<dyn Fn(&[u8]) -> Reply + Send + Sync>;
type Seen = Arc<Mutex<Vec<(String, HeaderMap)>>>;

struct Stub {
    address: SocketAddr,
    calls: Arc<AtomicUsize>,
    accepted: Arc<AtomicUsize>,
    seen: Seen,
    connections: Arc<Mutex<Vec<AbortHandle>>>,
}

impl Stub {
    fn kill_connections(&self) {
        for connection in self.connections.lock().unwrap().drain(..) {
            connection.abort();
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

// A Response to `query`: QR, RA and AD set, so a test can tell what the plugin kept.
fn echo(query: &[u8]) -> Reply {
    let mut wire = query.to_vec();
    wire[2] |= 0x80;
    wire[3] |= 0x80 | 0x20;
    Reply::Message(wire)
}

fn frame(message: &[u8]) -> Vec<u8> {
    let mut wire = FramePrefix::new(message.len()).chunk().to_vec();
    wire.extend_from_slice(message);
    wire
}

fn respond(reply: Reply) -> Response<BoxBody<Bytes, Infallible>> {
    let builder = Response::builder().header("content-type", "application/grpc");
    let body = match reply {
        Reply::Status(code) => {
            return builder
                .header("grpc-status", code.to_string())
                .body(Full::new(Bytes::new()).boxed())
                .unwrap();
        }
        Reply::Message(message) => frame(&message),
        Reply::Body(body) => body,
        Reply::WrongContentType(message) => {
            return Response::builder()
                .header("content-type", "text/plain")
                .body(Full::new(Bytes::from(frame(&message))).boxed())
                .unwrap();
        }
        Reply::HeaderStatusWithBody(message) => {
            return builder
                .header("grpc-status", "0")
                .body(Full::new(Bytes::from(frame(&message))).boxed())
                .unwrap();
        }
        Reply::Hang => unreachable!("handled before"),
    };
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().unwrap());
    builder
        .body(
            Full::new(Bytes::from(body))
                .with_trailers(std::future::ready(Some(Ok(trailers))))
                .boxed(),
        )
        .unwrap()
}

async fn serve_connection<T>(stream: T, script: Script, calls: Arc<AtomicUsize>, seen: Seen)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request: Request<Incoming>| {
        let (script, calls, seen) = (script.clone(), calls.clone(), seen.clone());
        async move {
            let (parts, body) = request.into_parts();
            seen.lock()
                .unwrap()
                .push((parts.uri.path().to_owned(), parts.headers));
            let body = body.collect().await.unwrap().to_bytes();
            calls.fetch_add(1, Ordering::SeqCst);
            let header = grpc::parse_header(&body).unwrap().unwrap();
            let end = grpc::HEADER_LEN + header.len;
            let query = grpc::decode_packet(&body[grpc::HEADER_LEN..end]).unwrap();
            match script(query) {
                Reply::Hang => std::future::pending().await,
                reply => Ok::<_, Infallible>(respond(reply)),
            }
        }
    });
    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await;
}

async fn start(script: impl Fn(&[u8]) -> Reply + Send + Sync + 'static, tls: bool) -> Stub {
    let script: Script = Arc::new(script);
    let acceptor = tls.then(|| {
        ServerTls::load(&ServerOptions {
            cert: format!("{FIXTURES}/server.pem").into(),
            key: format!("{FIXTURES}/server.key.pem").into(),
            ca: None,
            client_auth: ClientAuth::NoCert,
            keylog: None,
        })
        .unwrap()
        .with_alpn(grpc::ALPN)
        .acceptor()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stub = Stub {
        address: listener.local_addr().unwrap(),
        calls: Arc::default(),
        accepted: Arc::default(),
        seen: Arc::default(),
        connections: Arc::default(),
    };
    let (calls, accepted, seen, connections) = (
        stub.calls.clone(),
        stub.accepted.clone(),
        stub.seen.clone(),
        stub.connections.clone(),
    );
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            accepted.fetch_add(1, Ordering::SeqCst);
            let (script, calls, seen, acceptor) = (
                script.clone(),
                calls.clone(),
                seen.clone(),
                acceptor.clone(),
            );
            let task = tokio::spawn(async move {
                match acceptor {
                    Some(acceptor) => {
                        if let Ok(stream) = acceptor.accept(tcp).await {
                            serve_connection(stream, script, calls, seen).await;
                        }
                    }
                    None => serve_connection(tcp, script, calls, seen).await,
                }
            });
            connections.lock().unwrap().push(task.abort_handle());
        }
    });
    stub
}

async fn stub(script: impl Fn(&[u8]) -> Reply + Send + Sync + 'static) -> Stub {
    start(script, false).await
}

fn query(name: &str, qtype: Type) -> Vec<u8> {
    let name: Name = name.parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 0x1234, 0x0100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
        .unwrap();
    let _ = builder.finish();
    wire
}

fn front(corefile: &str) -> (impl Handler, Registry, Lifecycle) {
    let blocks = parse("Corefile", corefile).unwrap();
    let registry = Registry::new("test", "test", "test");
    let (mut servers, lifecycle) = servers_with_registry(
        configure::<Chain>(&blocks, directives()).unwrap(),
        registry.clone(),
    )
    .unwrap();
    (servers.drain().next().unwrap().1, registry, lifecycle)
}

async fn ask_type(server: &impl Handler, name: &str, qtype: Type) -> Vec<u8> {
    let mut response = Vec::with_capacity(65535);
    assert_eq!(
        Box::pin(server.handle(
            &query(name, qtype),
            "127.0.0.1:1234".parse().unwrap(),
            Protocol::Udp,
            &mut response
        ))
        .await,
        Action::Respond
    );
    response
}

async fn ask(server: &impl Handler, name: &str) -> Vec<u8> {
    ask_type(server, name, Type::A).await
}

fn rcode(response: &[u8]) -> u8 {
    response[3] & 15
}

// whoami answers with the client address in the Additional section.
fn from_whoami(response: &[u8]) -> bool {
    Message::parse(response).unwrap().additional_count() > 0
}

fn grpc_block(to: &str, options: &str) -> String {
    format!(".:0 {{\n grpc . {to} {{\n{options}\n }}\n whoami\n}}")
}

// CoreDNS v1.15.0 plugin/grpc/grpc_test.go TestGRPC: "single_proxy_ok".
#[tokio::test]
async fn a_reply_is_the_answer() {
    let upstream = stub(echo).await;
    let (server, _, _) = front(&grpc_block(&upstream.address.to_string(), ""));
    let response = ask(&server, "www.example.org.").await;
    assert_eq!(&response[..2], &[0x12, 0x34]);
    assert_eq!(rcode(&response), 0);
    assert!(response[2] & 0x80 != 0);
    // RA is kept; AD is not trusted (RFC 4035 §4.6).
    assert!(response[3] & 0x80 != 0);
    assert_eq!(response[3] & 0x20, 0);
    assert!(!from_whoami(&response));
    assert_eq!(upstream.calls(), 1);
}

// CoreDNS v1.15.0 pb/dns.proto: `coredns.dns.DnsService/Query` carries the Query as `application/grpc`.
#[tokio::test]
async fn the_call_names_the_service_method_and_a_deadline() {
    let upstream = stub(echo).await;
    let (server, _, _) = front(&grpc_block(&upstream.address.to_string(), ""));
    ask(&server, "www.example.org.").await;
    let seen = upstream.seen.lock().unwrap();
    let (path, headers) = &seen[0];
    assert_eq!(path, "/coredns.dns.DnsService/Query");
    assert_eq!(headers["content-type"], "application/grpc");
    assert_eq!(headers["te"], "trailers");
    // CoreDNS v1.15.0 plugin/grpc/grpc.go ServeDNS: the call carries the 5 second deadline.
    let timeout = headers["grpc-timeout"].to_str().unwrap();
    let millis: u64 = timeout.strip_suffix('m').unwrap().parse().unwrap();
    assert!((4000..=5000).contains(&millis), "{timeout}");
}

// CoreDNS v1.15.0 plugin/grpc/grpc_test.go TestGRPC: "multiple_proxies_one_ko".
#[tokio::test]
async fn an_upstream_error_moves_on_to_the_next_upstream() {
    let failing = stub(|_| Reply::Status(14)).await;
    let healthy = stub(echo).await;
    let (server, _, _) = front(&grpc_block(
        &format!("{} {}", failing.address, healthy.address),
        " policy sequential",
    ));
    let response = ask(&server, "www.example.org.").await;
    assert_eq!(rcode(&response), 0);
    assert!(!from_whoami(&response));
    assert_eq!((failing.calls(), healthy.calls()), (1, 1));
}

// CoreDNS v1.15.0 plugin/grpc/grpc_test.go TestGRPC: "single_proxy_ko" and "multiple_proxies_ko".
#[tokio::test]
async fn every_failing_upstream_is_servfail() {
    let (first, second) = (
        stub(|_| Reply::Status(14)).await,
        stub(|_| Reply::Status(2)).await,
    );
    let (server, _, _) = front(&grpc_block(
        &format!("{} {}", first.address, second.address),
        "",
    ));
    let response = ask(&server, "www.example.org.").await;
    assert_eq!(rcode(&response), 2);
    assert_eq!((first.calls(), second.calls()), (1, 1));
}

// CoreDNS v1.15.0 plugin/grpc/grpc.go ServeDNS: `fallthrough` when every Upstream failed.
#[tokio::test]
async fn fallthrough_after_failures_runs_the_next_plugin() {
    let upstream = stub(|_| Reply::Status(14)).await;
    let (server, _, _) = front(&grpc_block(&upstream.address.to_string(), " fallthrough"));
    assert!(from_whoami(&ask(&server, "www.example.org.").await));
}

// CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: a scheme grpc-go cannot dial passes setup and fails at the first Query.
#[tokio::test]
async fn an_undialable_target_fails_the_query_not_setup() {
    let upstream = stub(|query| echo(query)).await;
    let port = upstream.address.port();
    for bad in [
        format!("grpc://127.0.0.1:{port}"),
        format!("tls://127.0.0.1:{port}"),
        "127.0.0.1:99999".to_owned(),
    ] {
        let (server, _, _) = front(&grpc_block(&bad, ""));
        assert_eq!(rcode(&ask(&server, "www.example.org.").await), 2, "{bad}");
    }
    assert_eq!(upstream.calls(), 0);
    let to = format!("grpc://127.0.0.1:{port} {}", upstream.address);
    let (server, _, _) = front(&grpc_block(&to, " policy sequential"));
    assert_eq!(rcode(&ask(&server, "www.example.org.").await), 0);
}

// Replies that are not one acceptable DNS Message count as an error of the Upstream.
#[tokio::test]
async fn malformed_replies_are_upstream_errors() {
    let message = echo(&query("www.example.org.", Type::A));
    let Reply::Message(message) = message else {
        unreachable!()
    };
    let mut twice = frame(&message);
    twice.extend(frame(&message));
    let valid = message.clone();
    for (what, reply) in [
        ("compressed", Reply::Body(vec![1, 0, 0, 0, 0])),
        ("oversized", Reply::Body(vec![0, 0, 1, 0, 4])),
        ("empty", Reply::Body(Vec::new())),
        ("two messages", Reply::Body(twice)),
        (
            "truncated protobuf",
            Reply::Body(vec![0, 0, 0, 0, 2, 0x0a, 0xff]),
        ),
        ("not DNS", Reply::Message(vec![1, 2, 3])),
        ("message too large", Reply::Message(vec![0; 65536])),
        ("unknown status", Reply::Status(99)),
        // PROTOCOL-HTTP2 "Responses": the content-type must be application/grpc.
        ("wrong content-type", Reply::WrongContentType(valid.clone())),
        // PROTOCOL-HTTP2 "Responses": only the Trailers-Only form has grpc-status in the headers.
        (
            "header status with body",
            Reply::HeaderStatusWithBody(valid),
        ),
    ] {
        let upstream = stub(move |_| reply.clone()).await;
        let (server, _, _) = front(&grpc_block(&upstream.address.to_string(), ""));
        let response = ask(&server, "www.example.org.").await;
        assert_eq!(rcode(&response), 2, "{what}");
        assert_eq!(upstream.calls(), 1, "{what}");
    }
}

// CoreDNS v1.15.0 plugin/grpc/proxy.go query: NotFound is an NXDOMAIN reply.
#[tokio::test]
async fn not_found_is_nxdomain() {
    let upstream = stub(|_| Reply::Status(5)).await;
    let (server, registry, _) = front(&grpc_block(&upstream.address.to_string(), ""));
    let response = ask(&server, "www.example.org.").await;
    assert_eq!(&response[..2], &[0x12, 0x34]);
    assert_eq!(rcode(&response), 3);
    let message = Message::parse(&response).unwrap();
    assert!(message.qr());
    assert!(message.rd());
    assert_eq!(message.question_count(), 1);
    assert_eq!(message.answer_count(), 0);
    // CoreDNS v1.15.0 plugin/grpc/proxy.go query: the NotFound shortcut records no metrics.
    let mut text = String::new();
    registry.encode(&mut text);
    assert!(!text.contains("pharos_grpc_"), "{text}");
}

// CoreDNS v1.15.0 plugin/grpc/grpc.go ServeDNS: NXDOMAIN falls through when asked to.
#[tokio::test]
async fn fallthrough_on_nxdomain_runs_the_next_plugin() {
    let upstream = stub(|_| Reply::Status(5)).await;
    let (server, _, _) = front(&grpc_block(&upstream.address.to_string(), " fallthrough"));
    assert!(from_whoami(&ask(&server, "www.example.org.").await));
    let reply = stub(|query| {
        let mut wire = query.to_vec();
        wire[2] |= 0x80;
        wire[3] |= 3;
        Reply::Message(wire)
    })
    .await;
    let (server, _, _) = front(&grpc_block(&reply.address.to_string(), " fallthrough"));
    assert!(from_whoami(&ask(&server, "www.example.org.").await));
}

#[tokio::test]
async fn fallthrough_is_limited_to_its_zones() {
    let upstream = stub(|_| Reply::Status(5)).await;
    let (server, _, _) = front(&grpc_block(
        &upstream.address.to_string(),
        " fallthrough example.org",
    ));
    assert!(from_whoami(&ask(&server, "www.example.org.").await));
    let response = ask(&server, "www.example.com.").await;
    assert_eq!(rcode(&response), 3);
    assert!(!from_whoami(&response));
}

// CoreDNS v1.15.0 plugin/grpc/grpc.go ServeDNS: without a next Plugin the NXDOMAIN reply is the answer.
#[tokio::test]
async fn nxdomain_without_a_next_plugin_is_returned() {
    let upstream = stub(|_| Reply::Status(5)).await;
    let (server, _, _) = front(&format!(
        ".:0 {{\n grpc . {} {{\n fallthrough\n }}\n}}",
        upstream.address
    ));
    assert_eq!(rcode(&ask(&server, "www.example.org.").await), 3);
}

// CoreDNS v1.15.0 plugin/grpc/grpc.go match: `except` names and names outside FROM go to the next Plugin.
#[tokio::test]
async fn except_and_from_select_the_queries() {
    let upstream = stub(echo).await;
    let (server, _, _) = front(&format!(
        ".:0 {{\n grpc example.org {} {{\n except skip.example.org\n }}\n whoami\n}}",
        upstream.address
    ));
    assert!(!from_whoami(&ask(&server, "www.example.org.").await));
    assert!(!from_whoami(&ask(&server, "example.org.").await));
    assert_eq!(upstream.calls(), 2);
    assert!(from_whoami(&ask(&server, "a.skip.example.org.").await));
    assert!(from_whoami(&ask(&server, "www.example.com.").await));
    assert_eq!(upstream.calls(), 2);
    // The `except` name itself is excepted too, unless it is FROM.
    assert!(from_whoami(&ask(&server, "skip.example.org.").await));
}

// CoreDNS v1.15.0 plugin/grpc/grpc.go ServeDNS: a reply for another Question is FORMERR.
#[tokio::test]
async fn a_reply_for_another_question_is_formerr() {
    for change in [
        |wire: &mut Vec<u8>| {
            let end = wire.len();
            wire[end - 4..end - 2].copy_from_slice(&28_u16.to_be_bytes());
        },
        |wire: &mut Vec<u8>| wire[2] &= !0x80,
        |wire: &mut Vec<u8>| wire[5] = 0,
    ] {
        let upstream = stub(move |query| {
            let mut wire = query.to_vec();
            wire[2] |= 0x80;
            change(&mut wire);
            Reply::Message(wire)
        })
        .await;
        let (server, _, _) = front(&grpc_block(&upstream.address.to_string(), ""));
        assert_eq!(rcode(&ask(&server, "www.example.org.").await), 1);
    }
}

// RFC 4343 §3: DNS names compare ASCII letters case-insensitively, so a 0x20 reply matches.
#[tokio::test]
async fn the_question_matches_case_insensitively() {
    let upstream = stub(|query| {
        let mut wire = query.to_vec();
        wire[2] |= 0x80;
        wire[13..16].make_ascii_uppercase();
        Reply::Message(wire)
    })
    .await;
    let (server, _, _) = front(&grpc_block(&upstream.address.to_string(), ""));
    assert_eq!(rcode(&ask(&server, "www.example.org.").await), 0);
}

// CoreDNS v1.15.0 plugin/grpc/policy_test.go TestPoliciesOrdering.
#[tokio::test]
async fn round_robin_starts_with_the_next_upstream_each_time() {
    let upstreams = [stub(echo).await, stub(echo).await, stub(echo).await];
    let to = upstreams
        .iter()
        .map(|upstream| upstream.address.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let (server, _, _) = front(&grpc_block(&to, " policy round_robin"));
    let counts = |upstreams: &[Stub; 3]| upstreams.iter().map(Stub::calls).collect::<Vec<_>>();
    ask(&server, "www.example.org.").await;
    assert_eq!(counts(&upstreams), [0, 1, 0]);
    ask(&server, "www.example.org.").await;
    assert_eq!(counts(&upstreams), [0, 1, 1]);
    ask(&server, "www.example.org.").await;
    assert_eq!(counts(&upstreams), [1, 1, 1]);
}

#[tokio::test]
async fn sequential_always_starts_with_the_first_upstream() {
    let (first, second) = (stub(echo).await, stub(echo).await);
    let (server, _, _) = front(&grpc_block(
        &format!("{} {}", first.address, second.address),
        " policy sequential",
    ));
    for _ in 0..3 {
        ask(&server, "www.example.org.").await;
    }
    assert_eq!((first.calls(), second.calls()), (3, 0));
}

#[tokio::test]
async fn random_tries_every_upstream_until_one_answers() {
    let failing = stub(|_| Reply::Status(14)).await;
    let healthy = stub(echo).await;
    let (server, _, _) = front(&grpc_block(
        &format!("{} {}", failing.address, healthy.address),
        " policy random",
    ));
    for _ in 0..10 {
        assert_eq!(rcode(&ask(&server, "www.example.org.").await), 0);
    }
    assert_eq!(healthy.calls(), 10);
}

// CoreDNS v1.15.0 plugin/grpc/grpc.go ServeDNS: one `defaultTimeout` deadline covers all attempts.
#[tokio::test]
async fn a_hung_upstream_uses_up_the_shared_deadline() {
    let hung = stub(|_| Reply::Hang).await;
    let healthy = stub(echo).await;
    let (server, _, _) = front(&grpc_block(
        &format!("{} {}", hung.address, healthy.address),
        " policy sequential",
    ));
    let start = Instant::now();
    let response = ask(&server, "www.example.org.").await;
    assert!(start.elapsed() >= Duration::from_secs(5));
    assert_eq!(rcode(&response), 2);
    assert_eq!(healthy.calls(), 0);
}

#[tokio::test]
async fn one_connection_serves_many_queries_and_is_replaced_when_it_dies() {
    let upstream = stub(echo).await;
    let (server, _, _) = front(&grpc_block(&upstream.address.to_string(), ""));
    for _ in 0..3 {
        assert_eq!(rcode(&ask(&server, "www.example.org.").await), 0);
    }
    assert_eq!(upstream.accepted.load(Ordering::SeqCst), 1);
    upstream.kill_connections();
    assert_eq!(rcode(&ask(&server, "www.example.org.").await), 0);
    assert_eq!(upstream.accepted.load(Ordering::SeqCst), 2);
    assert_eq!(upstream.calls(), 4);
}

// CoreDNS v1.15.0 plugin/grpc/proxy_test.go TestShutdownClosesClientConnection.
#[tokio::test]
async fn shutdown_closes_the_connection() {
    let upstream = stub(echo).await;
    let (server, _, lifecycle) = front(&grpc_block(&upstream.address.to_string(), ""));
    assert_eq!(rcode(&ask(&server, "www.example.org.").await), 0);
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert_eq!(rcode(&ask(&server, "www.example.org.").await), 2);
}

#[tokio::test]
async fn tls_verifies_the_upstream_with_the_configured_name_and_roots() {
    let upstream = start(echo, true).await;
    let to = upstream.address.to_string();
    let ca = format!("{FIXTURES}/ca.pem");
    let (server, _, _) = front(&grpc_block(
        &to,
        &format!(" tls {ca}\n tls_servername localhost"),
    ));
    assert_eq!(rcode(&ask(&server, "www.example.org.").await), 0);
    // Without `tls_servername` the Upstream's IP address is verified, and the certificate carries it.
    let (server, _, _) = front(&grpc_block(&to, &format!(" tls {ca}")));
    assert_eq!(rcode(&ask(&server, "www.example.org.").await), 0);
    let (server, _, _) = front(&grpc_block(
        &to,
        &format!(" tls {ca}\n tls_servername wrong.example"),
    ));
    assert_eq!(rcode(&ask(&server, "www.example.org.").await), 2);
    // `tls_servername` alone verifies with the system roots, which do not hold the test CA.
    let (server, _, _) = front(&grpc_block(&to, " tls_servername localhost"));
    assert_eq!(rcode(&ask(&server, "www.example.org.").await), 2);
    // Without `tls` the call is plain-text and the TLS server cannot answer it.
    let (server, _, _) = front(&grpc_block(&to, ""));
    assert_eq!(rcode(&ask(&server, "www.example.org.").await), 2);
}

#[tokio::test]
async fn a_plain_upstream_fails_a_tls_call() {
    let upstream = stub(echo).await;
    let (server, _, _) = front(&grpc_block(
        &upstream.address.to_string(),
        &format!(" tls {FIXTURES}/ca.pem\n tls_servername localhost"),
    ));
    assert_eq!(rcode(&ask(&server, "www.example.org.").await), 2);
    assert_eq!(upstream.calls(), 0);
}

// CoreDNS v1.15.0 plugin/grpc/proxy_test.go TestProxyUnix.
#[tokio::test]
async fn a_unix_socket_upstream_answers() {
    let path = std::env::temp_dir().join(format!("pharos-grpc-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).unwrap();
    let (calls, seen) = (Arc::new(AtomicUsize::new(0)), Seen::default());
    let (task_calls, task_seen) = (calls.clone(), seen.clone());
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(serve_connection(
                stream,
                Arc::new(echo),
                task_calls.clone(),
                task_seen.clone(),
            ));
        }
    });
    let (server, _, _) = front(&grpc_block(&format!("unix://{}", path.display()), ""));
    assert_eq!(rcode(&ask(&server, "example.org.").await), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn metrics_count_answered_calls_per_upstream() {
    let upstream = stub(|query| match &query[13..16] {
        b"bad" => Reply::Status(14),
        b"nxd" => Reply::Status(5),
        _ => echo(query),
    })
    .await;
    let to = upstream.address.to_string();
    let (server, registry, _) = front(&grpc_block(&to, ""));
    for name in ["ok.example.org.", "bad.example.org.", "nxd.example.org."] {
        ask(&server, name).await;
    }
    let mut text = String::new();
    registry.encode(&mut text);
    for expected in [
        format!("pharos_grpc_requests_total{{to=\"{to}\"}} 1\n"),
        format!("pharos_grpc_responses_total{{rcode=\"NOERROR\",to=\"{to}\"}} 1\n"),
        format!("pharos_grpc_request_duration_seconds_count{{to=\"{to}\"}} 1\n"),
    ] {
        assert!(text.contains(&expected), "missing {expected}\n{text}");
    }
}

// CoreDNS v1.15.0 plugin/grpc/setup.go parseGRPC: the Directive is allowed once per Server Block.
#[test]
fn the_directive_is_allowed_once_per_server_block() {
    let blocks = parse("Corefile", ".:0 {\n grpc . ::1\n grpc com ::2\n}").unwrap();
    let error = configure::<Chain>(&blocks, directives())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("only be used once"), "{error}");
}

struct Listener {
    tls: ServerTls,
    calls: Arc<AtomicUsize>,
}

impl Handler for Listener {
    fn tls(&self) -> Option<ServerTls> {
        Some(self.tls.clone())
    }

    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        // CoreDNS v1.15.0 server_grpc.go: the Plugin Chain runs with the TCP rules.
        assert_eq!(protocol, Protocol::Tcp);
        self.calls.fetch_add(1, Ordering::SeqCst);
        response.extend_from_slice(query);
        response[2] |= 0x80;
        Action::Respond
    }
}

// CoreDNS v1.15.0 pb/dns.proto: the Pharos `grpc://` Listener is a `grpc` Upstream.
#[tokio::test]
async fn the_pharos_grpc_listener_answers() {
    let key = || ListenerKey {
        transport: Transport::Grpc,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let tls = ServerTls::load(&ServerOptions {
        cert: format!("{FIXTURES}/server.pem").into(),
        key: format!("{FIXTURES}/server.key.pem").into(),
        ca: None,
        client_auth: ClientAuth::NoCert,
        keylog: None,
    })
    .unwrap()
    .with_alpn(grpc::ALPN);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut listeners = ListenerRegistry::default();
    listeners
        .apply(std::collections::HashMap::from([(
            key(),
            Listener {
                tls,
                calls: calls.clone(),
            },
        )]))
        .await
        .unwrap();
    let address = listeners.get(&key()).unwrap().local_addr();
    let (server, _, _) = front(&grpc_block(
        &address.to_string(),
        &format!(" tls {FIXTURES}/ca.pem\n tls_servername localhost"),
    ));
    for _ in 0..3 {
        let response = ask(&server, "www.example.org.").await;
        assert_eq!(&response[..2], &[0x12, 0x34]);
        assert_eq!(rcode(&response), 0);
        assert!(!from_whoami(&response));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}
