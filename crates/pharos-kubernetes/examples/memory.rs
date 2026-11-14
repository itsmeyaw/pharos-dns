//! Measure Kubernetes cache memory with the synthetic API in a separate process.

#![forbid(unsafe_code)]

#[path = "support/api.rs"]
mod api;

use std::{alloc::System, convert::Infallible, fmt::Write as _, io::Write as _, time::Duration};

use api::{Body, full};
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::{BodyExt, StreamBody};
use hyper::{Response, body::Frame};
use pharos_kubernetes::{ClientConfig, Controller, WatchConfig};
use stats_alloc::{INSTRUMENTED_SYSTEM, Stats, StatsAlloc};
use tokio::net::TcpListener;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const SERVICES: usize = 10_000;

#[derive(Clone, Copy)]
enum Resource {
    Service,
    EndpointSlice,
    Namespace,
}

impl Resource {
    fn from_path(path: &str) -> Option<Self> {
        match path {
            "/api/v1/services" => Some(Self::Service),
            "/apis/discovery.k8s.io/v1/endpointslices" => Some(Self::EndpointSlice),
            "/api/v1/namespaces" => Some(Self::Namespace),
            _ => None,
        }
    }

    fn api_and_kind(self) -> (&'static str, &'static str) {
        match self {
            Self::Service => ("v1", "Service"),
            Self::EndpointSlice => ("discovery.k8s.io/v1", "EndpointSlice"),
            Self::Namespace => ("v1", "Namespace"),
        }
    }

    fn count(self) -> usize {
        match self {
            Self::Namespace => 1,
            _ => SERVICES,
        }
    }

    fn write_object(self, out: &mut String, i: usize) {
        match self {
            Self::Service => {
                let ip = format!("10.{}.{}.{}", i / 65536, i / 256 % 256, i % 256);
                write!(out, r#"{{"apiVersion":"v1","kind":"Service","metadata":{{"name":"svc{i}","namespace":"bench","resourceVersion":"1"}},"spec":{{"type":"ClusterIP","clusterIP":"{ip}","clusterIPs":["{ip}"],"ports":[{{"port":80,"protocol":"TCP"}}]}}}}"#).unwrap();
            }
            Self::EndpointSlice => {
                write!(out, r#"{{"apiVersion":"discovery.k8s.io/v1","kind":"EndpointSlice","metadata":{{"name":"slice{i}","namespace":"bench","resourceVersion":"1","labels":{{"kubernetes.io/service-name":"svc{i}"}}}},"addressType":"IPv4","endpoints":["#).unwrap();
                for offset in 0..3 {
                    if offset != 0 { out.push(','); }
                    let address = i * 3 + offset;
                    write!(out, r#"{{"addresses":["192.{}.{}.{}"]}}"#, address / 65536, address / 256 % 256, address % 256).unwrap();
                }
                out.push_str("]}");
            }
            Self::Namespace => out.push_str(r#"{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"bench","resourceVersion":"1"}}"#),
        }
    }
}

fn list(resource: Resource) -> String {
    let (api, kind) = resource.api_and_kind();
    let mut out = format!(
        r#"{{"apiVersion":"{api}","kind":"{kind}List","metadata":{{"resourceVersion":"1"}},"items":["#
    );
    for i in 0..resource.count() {
        if i != 0 {
            out.push(',');
        }
        resource.write_object(&mut out, i);
    }
    out.push_str("]}");
    out
}

fn initial_watch(resource: Resource) -> String {
    let (api, kind) = resource.api_and_kind();
    let mut out = String::new();
    for i in 0..resource.count() {
        out.push_str(r#"{"type":"ADDED","object":"#);
        resource.write_object(&mut out, i);
        out.push_str("}\n");
    }
    writeln!(out, r#"{{"type":"BOOKMARK","object":{{"apiVersion":"{api}","kind":"{kind}","metadata":{{"resourceVersion":"1","annotations":{{"k8s.io/initial-events-end":"true"}}}}}}}}"#).unwrap();
    out
}

fn api_response(path: &str, query: Option<&str>) -> Response<Body> {
    let query = query.unwrap_or_default();
    let watch = query.split('&').any(|part| part == "watch=true");
    let initial = query
        .split('&')
        .any(|part| part == "sendInitialEvents=true");
    let (status, body) = if let Some(resource) = Resource::from_path(path) {
        if watch {
            let initial_data = if initial {
                initial_watch(resource)
            } else {
                String::new()
            };
            let first = futures::stream::once(async move {
                Ok::<_, Infallible>(Frame::data(Bytes::from(initial_data)))
            });
            let stream = first.chain(futures::stream::pending());
            (200, BodyExt::boxed(StreamBody::new(stream)))
        } else {
            (200, full(list(resource)))
        }
    } else {
        let body = match path {
            "/version" => r#"{"major":"1","minor":"37","gitVersion":"v1.37.0","gitCommit":"synthetic","gitTreeState":"clean","buildDate":"2026-01-01T00:00:00Z","goVersion":"go1","compiler":"gc","platform":"linux/amd64"}"#,
            "/api" => r#"{"kind":"APIVersions","apiVersion":"v1","versions":["v1"]}"#,
            "/apis" => r#"{"kind":"APIGroupList","apiVersion":"v1","groups":[{"name":"discovery.k8s.io","versions":[{"groupVersion":"discovery.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"discovery.k8s.io/v1","version":"v1"}}]}"#,
            "/api/v1" => r#"{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"v1","resources":[{"name":"services","namespaced":true,"kind":"Service","verbs":["get","list","watch"]},{"name":"namespaces","namespaced":false,"kind":"Namespace","verbs":["get","list","watch"]}]}"#,
            "/apis/discovery.k8s.io" => r#"{"kind":"APIGroup","apiVersion":"v1","name":"discovery.k8s.io","versions":[{"groupVersion":"discovery.k8s.io/v1","version":"v1"}],"preferredVersion":{"groupVersion":"discovery.k8s.io/v1","version":"v1"}}"#,
            "/apis/discovery.k8s.io/v1" => r#"{"kind":"APIResourceList","apiVersion":"v1","groupVersion":"discovery.k8s.io/v1","resources":[{"name":"endpointslices","namespaced":true,"kind":"EndpointSlice","verbs":["get","list","watch"]}]}"#,
            "/healthz" | "/readyz" => "ok",
            // RFC 9110 §15.5.5: A 404 response indicates no current representation.
            _ => return Response::builder().status(404).header("content-type", "application/json").body(full(r#"{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"NotFound","code":404}"#)).unwrap(),
        };
        (200, full(body))
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(body)
        .unwrap()
}

fn live_heap_bytes(stats: Stats) -> i128 {
    // Reallocation deltas are already included in both byte totals.
    stats.bytes_allocated as i128 - stats.bytes_deallocated as i128
}

#[cfg(target_os = "linux")]
fn rss_kib() -> Result<u64, Box<dyn std::error::Error>> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let rss = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .ok_or("VmRSS missing")?;
    Ok(rss
        .split_whitespace()
        .next()
        .ok_or("VmRSS empty")?
        .parse()?)
}

#[cfg(not(target_os = "linux"))]
fn rss_kib() -> Result<u64, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()?;
    if !output.status.success() {
        return Err("ps failed".into());
    }
    Ok(std::str::from_utf8(&output.stdout)?.trim().parse()?)
}

async fn serve(address: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(address).await?;
    let url = format!("http://{}", listener.local_addr()?);
    let mut kubeconfig = tempfile::NamedTempFile::new()?;
    serde_json::to_writer(
        &mut kubeconfig,
        &serde_json::json!({
            "apiVersion":"v1", "kind":"Config", "clusters":[{"name":"memory", "cluster":{"server":url}}],
            "contexts":[{"name":"memory", "context":{"cluster":"memory", "user":"memory"}}],
            "current-context":"memory", "users":[{"name":"memory", "user":{}}]
        }),
    )?;
    kubeconfig.flush()?;
    println!("API_URL={url}\nKUBECONFIG={}", kubeconfig.path().display());
    std::io::stdout().flush()?;
    api::serve(listener, api_response).await
}

async fn client(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let registry = pharos_server::metrics::Registry::new("memory", "memory", "memory");
    let config = ClientConfig {
        endpoint: Some(url.into()),
        ..Default::default()
    };
    let client = config.client(&registry).await?;
    let before_rss = rss_kib()?;
    let before_heap = live_heap_bytes(GLOBAL.stats());
    let mut controller =
        Controller::start_with_metrics(client, WatchConfig::default(), registry.kubernetes());
    tokio::time::timeout(Duration::from_secs(60), async {
        while !controller.has_synced() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let counts = controller.store().with_read(|index| index.counts());
    assert_eq!(counts, (SERVICES, SERVICES, SERVICES * 3, 0, 1));
    let after_heap = live_heap_bytes(GLOBAL.stats());
    let after_rss = rss_kib()?;
    println!(
        "RSS before: {before_rss} KiB; after: {after_rss} KiB; delta: {} KiB",
        i128::from(after_rss) - i128::from(before_rss)
    );
    println!(
        "Live heap before: {before_heap} bytes; after: {after_heap} bytes; delta: {} bytes",
        after_heap - before_heap
    );
    println!(
        "services: {}; slices: {}; endpoints: {}; pods: {}; namespaces: {}",
        counts.0, counts.1, counts.2, counts.3, counts.4
    );
    controller.stop().await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode] if mode == "serve" => serve("127.0.0.1:0").await,
        [mode, address] if mode == "serve" => serve(address).await,
        [mode, url] if mode == "client" => client(url).await,
        _ => Err("usage: memory serve [ADDR] | memory client URL".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{api_response, live_heap_bytes};
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn version_and_discovery_are_valid_kubernetes_responses() {
        for (path, expected) in [
            ("/version", "gitVersion"),
            ("/api", "APIVersions"),
            ("/apis", "APIGroupList"),
            ("/api/v1", "APIResourceList"),
            ("/apis/discovery.k8s.io/v1", "APIResourceList"),
        ] {
            let response = api_response(path, None);
            assert_eq!(response.status(), 200);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert!(std::str::from_utf8(&body).unwrap().contains(expected));
        }
        assert_eq!(api_response("/unknown", None).status(), 404);
    }

    #[tokio::test]
    async fn watch_list_contains_resources_and_end_bookmark() {
        let mut body = api_response(
            "/api/v1/services",
            Some("watch=true&sendInitialEvents=true"),
        )
        .into_body();
        let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
        let text = std::str::from_utf8(&frame).unwrap();
        assert_eq!(
            text.lines()
                .filter(|line| line.contains("\"type\":\"ADDED\""))
                .count(),
            10_000
        );
        assert!(text.contains("k8s.io/initial-events-end"));
        let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        let last: serde_json::Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
        assert_eq!(first["object"]["kind"], "Service");
        assert_eq!(
            last["object"]["metadata"]["annotations"]["k8s.io/initial-events-end"],
            "true"
        );
    }

    #[tokio::test]
    async fn endpoint_list_has_three_addresses_per_service() {
        let response = api_response("/apis/discovery.k8s.io/v1/endpointslices", None);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let list: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let slices = list["items"].as_array().unwrap();
        assert_eq!(slices.len(), 10_000);
        assert_eq!(
            slices
                .iter()
                .map(|slice| slice["endpoints"].as_array().unwrap().len())
                .sum::<usize>(),
            30_000
        );
    }

    #[test]
    fn live_heap_does_not_double_count_reallocations() {
        let stats = stats_alloc::Stats {
            bytes_allocated: 200,
            bytes_deallocated: 50,
            bytes_reallocated: -20,
            ..Default::default()
        };
        assert_eq!(live_heap_bytes(stats), 150);
    }
}
