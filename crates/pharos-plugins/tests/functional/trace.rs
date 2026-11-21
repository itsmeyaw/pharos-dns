#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-trace", feature = "plugin-whoami"))]

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers_with_registry};
use pharos_proto::Message;
use pharos_server::{Action, Handler, Lifecycle, Phase, Protocol, metrics::Registry};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const QUERY: &[u8] = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x07example\x03org\0\0\x01\0\x01";

#[derive(Clone, Copy)]
enum Mode {
    Accept,
    Hang,
}

struct Request {
    head: String,
    body: String,
    raw: Vec<u8>,
}

// A loopback stub of a Zipkin collector or Datadog agent: it records each request and answers 202, or never answers.
struct Collector {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl Collector {
    async fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let mut data = Vec::new();
                    let mut chunk = [0; 4096];
                    let (head, length) = loop {
                        let read = stream.read(&mut chunk).await.unwrap_or(0);
                        if read == 0 {
                            return;
                        }
                        data.extend_from_slice(&chunk[..read]);
                        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&data[..end]).into_owned();
                            let length = head
                                .lines()
                                .find_map(|line| line.strip_prefix("Content-Length: "))
                                .map_or(0, |value| value.parse::<usize>().unwrap());
                            data.drain(..end + 4);
                            break (head, length);
                        }
                    };
                    while data.len() < length {
                        let read = stream.read(&mut chunk).await.unwrap_or(0);
                        if read == 0 {
                            return;
                        }
                        data.extend_from_slice(&chunk[..read]);
                    }
                    let body = String::from_utf8_lossy(&data[..length]).into_owned();
                    let raw = data[..length].to_vec();
                    seen.lock().unwrap().push(Request { head, body, raw });
                    match mode {
                        Mode::Accept => {
                            let _ = stream
                                .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                .await;
                        }
                        Mode::Hang => std::future::pending::<()>().await,
                    }
                });
            }
        });
        Self { address, requests }
    }

    fn spans(&self) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| {
                // Datadog agent API: the trace count header; Zipkin: one `name` per JSON span.
                request
                    .head
                    .lines()
                    .find_map(|line| line.strip_prefix("X-Datadog-Trace-Count: "))
                    .map_or_else(
                        || request.body.matches(r#""name":"servedns""#).count(),
                        |count| count.parse().unwrap(),
                    )
            })
            .sum()
    }
}

// A port that refuses connections.
fn refused() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

async fn start(options: &str, collector: SocketAddr) -> (impl Handler, Lifecycle, Registry) {
    let text = format!(
        ".:0 {{\n trace http://{collector}/api/v2/spans {{\n service pharos-test\n {options}\n }}\n whoami\n}}"
    );
    let blocks = parse("Corefile", &text).unwrap();
    let registry = Registry::default();
    let (mut servers, lifecycle) = servers_with_registry(
        configure::<Chain>(&blocks, directives()).unwrap(),
        registry.clone(),
    )
    .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();
    (server, lifecycle, registry)
}

async fn start_datadog(
    options: &str,
    collector: SocketAddr,
) -> (impl Handler, Lifecycle, Registry) {
    let text = format!(
        ".:0 {{\n trace datadog http://{collector} {{\n service pharos-test\n {options}\n }}\n whoami\n}}"
    );
    let blocks = parse("Corefile", &text).unwrap();
    let registry = Registry::default();
    let (mut servers, lifecycle) = servers_with_registry(
        configure::<Chain>(&blocks, directives()).unwrap(),
        registry.clone(),
    )
    .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();
    (server, lifecycle, registry)
}

// MessagePack spec: a str of up to 31 bytes is a fixstr.
fn has_tag(body: &[u8], key: &str, value: &str) -> bool {
    let mut pair = vec![0xa0 | key.len() as u8];
    pair.extend_from_slice(key.as_bytes());
    pair.push(0xa0 | value.len() as u8);
    pair.extend_from_slice(value.as_bytes());
    body.windows(pair.len()).any(|window| window == pair)
}

async fn query(server: &impl Handler, response: &mut Vec<u8>) {
    let client = "127.0.0.1:1234".parse().unwrap();
    assert_eq!(
        server.handle(QUERY, client, Protocol::Udp, response).await,
        Action::Respond
    );
    assert_eq!(
        Message::parse(response).unwrap().rcode(),
        pharos_proto::Rcode::NOERROR
    );
}

async fn until(what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn metric(registry: &Registry, series: &str) -> u64 {
    let mut text = String::new();
    registry.encode(&mut text);
    text.lines()
        .find_map(|line| line.strip_prefix(series))
        .map_or(0, |value| value.trim().parse().unwrap())
}

#[tokio::test]
async fn sampled_query_exports_a_span_with_its_tags() {
    let collector = Collector::start(Mode::Accept).await;
    let (server, lifecycle, registry) =
        start("zipkin_max_batch_interval 20ms", collector.address).await;
    let mut response = Vec::with_capacity(512);
    query(&server, &mut response).await;
    until("the span", || collector.spans() == 1).await;
    {
        let requests = collector.requests.lock().unwrap();
        let request = &requests[0];
        // Zipkin v2 API: a JSON array POSTed to the configured path.
        assert!(
            request.head.starts_with("POST /api/v2/spans HTTP/1.1\r\n"),
            "{}",
            request.head
        );
        assert!(
            request.head.contains("Content-Type: application/json"),
            "{}",
            request.head
        );
        assert!(request.head.contains("b3: 0"), "{}", request.head);
        for expected in [
            r#""kind":"SERVER""#,
            r#""localEndpoint":{"serviceName":"pharos-test"}"#,
            r#""coredns.io/name":"example.org.""#,
            r#""coredns.io/type":"A""#,
            r#""coredns.io/rcode":"NOERROR""#,
            r#""coredns.io/proto":"udp""#,
            r#""coredns.io/remote":"127.0.0.1""#,
        ] {
            assert!(
                request.body.contains(expected),
                "{expected}: {}",
                request.body
            );
        }
    }
    until("the exported counter", || {
        metric(&registry, "pharos_trace_exported_spans_total ") == 1
    })
    .await;
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn every_n_exports_one_query_in_n() {
    let collector = Collector::start(Mode::Accept).await;
    let (server, lifecycle, _) = start(
        "every 3\n zipkin_max_batch_interval 20ms",
        collector.address,
    )
    .await;
    let mut response = Vec::with_capacity(512);
    for _ in 0..7 {
        query(&server, &mut response).await;
    }
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert_eq!(collector.spans(), 2);
}

#[tokio::test]
async fn shutdown_flushes_spans_not_yet_batched() {
    let collector = Collector::start(Mode::Accept).await;
    let (server, lifecycle, _) = start("zipkin_max_batch_interval 1h", collector.address).await;
    let mut response = Vec::with_capacity(512);
    for _ in 0..3 {
        query(&server, &mut response).await;
    }
    assert_eq!(collector.spans(), 0);
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert_eq!(collector.spans(), 3);
}

#[tokio::test]
async fn collector_down_neither_fails_nor_slows_queries() {
    let (server, lifecycle, registry) = start(
        "zipkin_max_batch_size 1\n zipkin_max_batch_interval 10ms",
        refused(),
    )
    .await;
    let mut response = Vec::with_capacity(512);
    let begin = Instant::now();
    for _ in 0..50 {
        query(&server, &mut response).await;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    // 50 Queries and their 2 ms pauses fit well inside a second when the exporter is not in the way.
    assert!(
        begin.elapsed() < Duration::from_secs(2),
        "{:?}",
        begin.elapsed()
    );
    until("dropped spans", || {
        metric(
            &registry,
            "pharos_trace_dropped_spans_total{reason=\"export_failed\"} ",
        ) > 0
    })
    .await;
    assert_eq!(metric(&registry, "pharos_trace_exported_spans_total "), 0);
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn hung_collector_neither_fails_nor_slows_queries() {
    let collector = Collector::start(Mode::Hang).await;
    let (server, lifecycle, _) = start(
        "zipkin_max_batch_size 1\n zipkin_max_batch_interval 10ms",
        collector.address,
    )
    .await;
    let mut response = Vec::with_capacity(512);
    query(&server, &mut response).await;
    until("the request to reach the collector", || {
        collector.spans() == 1
    })
    .await;
    let begin = Instant::now();
    for _ in 0..50 {
        query(&server, &mut response).await;
    }
    assert!(
        begin.elapsed() < Duration::from_secs(1),
        "{:?}",
        begin.elapsed()
    );
    // Shutdown gives the stuck request its timeout, then lets go.
    let begin = Instant::now();
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert!(
        begin.elapsed() < Duration::from_secs(8),
        "{:?}",
        begin.elapsed()
    );
}

#[tokio::test]
async fn full_queue_drops_the_oldest_spans_and_counts_them() {
    let collector = Collector::start(Mode::Accept).await;
    let (server, lifecycle, registry) = start(
        "zipkin_max_backlog_size 5\n zipkin_max_batch_size 1000\n zipkin_max_batch_interval 1h",
        collector.address,
    )
    .await;
    let mut response = Vec::with_capacity(512);
    for _ in 0..20 {
        query(&server, &mut response).await;
    }
    assert_eq!(
        metric(
            &registry,
            "pharos_trace_dropped_spans_total{reason=\"queue_full\"} "
        ),
        15
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert_eq!(collector.spans(), 5);
    assert_eq!(metric(&registry, "pharos_trace_exported_spans_total "), 5);
}

#[tokio::test]
async fn datadog_sampled_query_exports_a_msgpack_trace() {
    let collector = Collector::start(Mode::Accept).await;
    let (server, lifecycle, registry) =
        start_datadog("datadog_analytics_rate 0.5", collector.address).await;
    let mut response = Vec::with_capacity(512);
    query(&server, &mut response).await;
    // The Datadog exporter batches every second; shutdown flushes at once.
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert_eq!(collector.spans(), 1);
    let requests = collector.requests.lock().unwrap();
    let request = &requests[0];
    // Datadog agent API v0.4 and dd-trace-go v2.10.1 transport.go: a msgpack body POSTed with the tracer identity headers.
    assert!(
        request.head.starts_with("POST /v0.4/traces HTTP/1.1\r\n"),
        "{}",
        request.head
    );
    for header in [
        "Content-Type: application/msgpack",
        "Datadog-Meta-Lang: rust",
        "X-Datadog-Trace-Count: 1",
        "Datadog-Client-Computed-Top-Level: t",
    ] {
        assert!(request.head.contains(header), "{header}: {}", request.head);
    }
    // Msgpack fixarray of one trace holding a fixarray of one span.
    assert_eq!(&request.raw[..2], [0x91, 0x91]);
    for (key, value) in [
        ("name", "servedns"),
        ("service", "pharos-test"),
        ("type", "dns"),
        ("coredns.io@name", "example.org."),
        ("coredns.io@type", "A"),
        ("coredns.io@rcode", "NOERROR"),
        ("coredns.io@proto", "udp"),
        ("coredns.io@remote", "127.0.0.1"),
    ] {
        assert!(
            has_tag(&request.raw, key, value),
            "{key}={value}: {:?}",
            request.raw
        );
    }
    // The analytics rate 0.5 as a float64 metric.
    let mut rate = vec![0xad];
    rate.extend_from_slice(b"_dd1.sr.eausr");
    rate.push(0xcb);
    rate.extend_from_slice(&0.5_f64.to_be_bytes());
    assert!(request.raw.windows(rate.len()).any(|window| window == rate));
    drop(requests);
    assert_eq!(metric(&registry, "pharos_trace_exported_spans_total "), 1);
}

#[tokio::test]
async fn datadog_error_span_is_flagged() {
    let collector = Collector::start(Mode::Accept).await;
    let (server, lifecycle, _) = start_datadog("", collector.address).await;
    // A UDP Response buffer below 512 bytes makes whoami fail, which the Server answers with SERVFAIL.
    let mut response = Vec::new();
    let client = "127.0.0.1:1234".parse().unwrap();
    server
        .handle(QUERY, client, Protocol::Udp, &mut response)
        .await;
    lifecycle.run(Phase::Shutdown).await.unwrap();
    let requests = collector.requests.lock().unwrap();
    let raw = &requests[0].raw;
    assert!(has_tag(raw, "error.type", "dns_error"));
    assert!(has_tag(raw, "error.message", "Response buffer too small"));
    assert!(has_tag(raw, "coredns.io@rcode", "SERVFAIL"));
    // `error` is the int32 1 right at the end of the span.
    assert_eq!(&raw[raw.len() - 7..], b"\xa5error\x01");
}

#[tokio::test]
async fn datadog_collector_down_neither_fails_nor_slows_queries() {
    let (server, lifecycle, registry) = start_datadog("", refused()).await;
    let mut response = Vec::with_capacity(512);
    let begin = Instant::now();
    for _ in 0..50 {
        query(&server, &mut response).await;
    }
    assert!(
        begin.elapsed() < Duration::from_secs(1),
        "{:?}",
        begin.elapsed()
    );
    // Shutdown flushes the queued spans to the refused port, which counts them as dropped.
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert_eq!(
        metric(
            &registry,
            "pharos_trace_dropped_spans_total{reason=\"export_failed\"} "
        ),
        50
    );
    assert_eq!(metric(&registry, "pharos_trace_exported_spans_total "), 0);
}

#[tokio::test]
async fn datadog_bare_host_port_endpoint_reaches_the_agent() {
    let collector = Collector::start(Mode::Accept).await;
    let text = format!(".:0 {{\n trace datadog {} \n whoami\n}}", collector.address);
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, lifecycle) = servers_with_registry(
        configure::<Chain>(&blocks, directives()).unwrap(),
        Registry::default(),
    )
    .unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();
    query(&server, &mut Vec::with_capacity(512)).await;
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert_eq!(collector.spans(), 1);
}
