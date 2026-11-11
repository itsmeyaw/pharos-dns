use std::{
    collections::HashMap,
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use futures::stream;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::{
    Request, Response,
    body::{Frame, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use pharos_kubernetes::{Controller, WatchConfig};
use serde_json::{Value, json};
use tokio::{
    net::TcpListener,
    sync::{Semaphore, mpsc},
};

#[path = "../../pharos/tests/support/mod.rs"]
mod support;

type Watches = Arc<Mutex<HashMap<String, mpsc::UnboundedSender<String>>>>;
type Requests = Arc<Mutex<Vec<String>>>;

struct FakeServer {
    url: String,
    watches: Watches,
    requests: Requests,
    lists: Arc<Mutex<HashMap<String, Value>>>,
    list_delay: Arc<std::sync::atomic::AtomicU64>,
    path_gates: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
    endpoint_page_gate: Arc<Mutex<Option<Arc<Semaphore>>>>,
    active: Arc<std::sync::atomic::AtomicUsize>,
    peak: Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeServer {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", support::free_port()))
            .await
            .unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let watches: Watches = Arc::default();
        let requests: Requests = Arc::default();
        let lists: Arc<Mutex<HashMap<String, Value>>> = Arc::default();
        let list_delay = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let path_gates: Arc<Mutex<HashMap<String, Arc<Semaphore>>>> = Arc::default();
        let endpoint_page_gate: Arc<Mutex<Option<Arc<Semaphore>>>> = Arc::default();
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task_watches = watches.clone();
        let task_requests = requests.clone();
        let task_lists = lists.clone();
        let task_delay = list_delay.clone();
        let task_path_gates = path_gates.clone();
        let task_page_gate = endpoint_page_gate.clone();
        let task_active = active.clone();
        let task_peak = peak.clone();
        let task = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let watches = task_watches.clone();
                let requests = task_requests.clone();
                let lists = task_lists.clone();
                let delay = task_delay.clone();
                let path_gates = task_path_gates.clone();
                let page_gate = task_page_gate.clone();
                let active = task_active.clone();
                let peak = task_peak.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let watches = watches.clone();
                        let requests = requests.clone();
                        let lists = lists.clone();
                        let delay = delay.clone();
                        let path_gates = path_gates.clone();
                        let page_gate = page_gate.clone();
                        let active = active.clone();
                        let peak = peak.clone();
                        async move {
                            requests.lock().unwrap().push(request.uri().to_string());
                            let path = request.uri().path().to_owned();
                            let body: BoxBody<Bytes, Infallible> = if request
                                .uri()
                                .query()
                                .is_some_and(|query| query.contains("watch=true"))
                            {
                                let (sender, receiver) = mpsc::unbounded_channel::<String>();
                                watches.lock().unwrap().insert(path, sender);
                                let stream = stream::unfold(receiver, |mut receiver| async move {
                                    receiver.recv().await.map(|line| {
                                        (
                                            Ok::<_, Infallible>(Frame::data(Bytes::from(line))),
                                            receiver,
                                        )
                                    })
                                });
                                StreamBody::new(stream).boxed()
                            } else {
                                let current =
                                    active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                                peak.fetch_max(current, std::sync::atomic::Ordering::SeqCst);
                                let delay_ms = delay.load(std::sync::atomic::Ordering::Relaxed);
                                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                let gate = path_gates.lock().unwrap().get(&path).cloned();
                                if let Some(gate) = gate {
                                    gate.acquire().await.unwrap().forget();
                                }
                                let page_gate =
                                    if path == "/apis/discovery.k8s.io/v1/endpointslices" {
                                        page_gate.lock().unwrap().clone()
                                    } else {
                                        None
                                    };
                                let next_page = request
                                    .uri()
                                    .query()
                                    .is_some_and(|query| query.contains("continue=next"));
                                if next_page && let Some(gate) = &page_gate {
                                    gate.acquire().await.unwrap().forget();
                                }
                                active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                                let (api, kind, items) = match path.as_str() {
                                    "/api/v1/services" => (
                                        "v1",
                                        "ServiceList",
                                        json!([{"metadata":{"name":"web","namespace":"prod","resourceVersion":"1"},"spec":{"clusterIP":"10.0.0.1"}}]),
                                    ),
                                    "/api/v1/namespaces" => (
                                        "v1",
                                        "NamespaceList",
                                        json!([{"metadata":{"name":"prod","resourceVersion":"1"}}]),
                                    ),
                                    "/apis/discovery.k8s.io/v1/endpointslices" => (
                                        "discovery.k8s.io/v1",
                                        "EndpointSliceList",
                                        json!([{"metadata":{"name":"slice","namespace":"prod","resourceVersion":"1","labels":{"kubernetes.io/service-name":"web"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.1.1"]}]}]),
                                    ),
                                    _ => ("v1", "PodList", json!([])),
                                };
                                let items = if next_page && page_gate.is_some() {
                                    json!([])
                                } else {
                                    lists.lock().unwrap().get(&path).cloned().unwrap_or(items)
                                };
                                let metadata = if page_gate.is_some() && !next_page {
                                    json!({"resourceVersion":"1", "continue":"next"})
                                } else {
                                    json!({"resourceVersion":"1"})
                                };
                                let body = json!({"apiVersion":api, "kind":kind, "metadata":metadata, "items":items}).to_string();
                                Full::new(Bytes::from(body)).boxed()
                            };
                            Ok::<_, Infallible>(Response::new(body))
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                });
            }
        });
        Self {
            url,
            watches,
            requests,
            lists,
            list_delay,
            path_gates,
            endpoint_page_gate,
            active,
            peak,
            task,
        }
    }

    fn send(&self, path: &str, typ: &str, object: Value) {
        self.watches
            .lock()
            .unwrap()
            .get(path)
            .unwrap()
            .send(format!("{}\n", json!({"type":typ, "object":object})))
            .unwrap();
    }
}

#[tokio::test]
async fn programming_metrics_record_before_all_initial_watchers_sync() {
    let server = FakeServer::start().await;
    let gate = Arc::new(Semaphore::new(0));
    server
        .path_gates
        .lock()
        .unwrap()
        .insert("/api/v1/namespaces".into(), gate);
    let registry = pharos_server::metrics::Registry::new("test", "test", "test");
    let config = pharos_kubernetes::ClientConfig {
        endpoint: Some(server.url.clone()),
        ..Default::default()
    };
    let client = config.client(&registry).await.unwrap();
    let mut controller =
        Controller::start_with_metrics(client, WatchConfig::default(), registry.kubernetes());
    let store = controller.store();
    until(|| {
        server.watches.lock().unwrap().len() >= 2
            && store.with_read(|index| index.service("prod", "web").is_some())
    })
    .await;
    assert!(!controller.has_synced());
    let endpoint = json!({"apiVersion":"discovery.k8s.io/v1", "kind":"EndpointSlice", "metadata":{
        "name":"slice", "namespace":"prod", "resourceVersion":"2", "labels":{"kubernetes.io/service-name":"web"},
        "annotations":{"endpoints.kubernetes.io/last-change-trigger-time":"2024-01-01T00:00:00Z"}},
        "addressType":"IPv4", "endpoints":[{"addresses":["10.0.1.9"]}]});
    server.send(
        "/apis/discovery.k8s.io/v1/endpointslices",
        "MODIFIED",
        endpoint,
    );
    until(|| {
        let mut out = String::new();
        registry.encode(&mut out);
        out.contains("pharos_kubernetes_dns_programming_duration_seconds_count{service_kind=\"cluster_ip\"} 1")
            && store.with_read(|index| index.endpoints_by_ip("10.0.1.9").count() == 1)
    }).await;
    let mut out = String::new();
    registry.encode(&mut out);
    assert!(out.contains(
        "pharos_kubernetes_dns_programming_duration_seconds_count{service_kind=\"cluster_ip\"} 1"
    ));
    server.send("/apis/discovery.k8s.io/v1/endpointslices", "ADDED", json!({
        "apiVersion":"discovery.k8s.io/v1", "kind":"EndpointSlice", "metadata":{
            "name":"slice2", "namespace":"prod", "resourceVersion":"3", "labels":{"kubernetes.io/service-name":"web"},
            "annotations":{"endpoints.kubernetes.io/last-change-trigger-time":"2024-01-01T00:00:00Z"}}, "addressType":"IPv4"
    }));
    until(|| {
        let mut out = String::new();
        registry.encode(&mut out);
        out.contains("pharos_kubernetes_dns_programming_duration_seconds_count{service_kind=\"cluster_ip\"} 2")
    }).await;
    server.send("/apis/discovery.k8s.io/v1/endpointslices", "DELETED", json!({
        "apiVersion":"discovery.k8s.io/v1", "kind":"EndpointSlice", "metadata":{
            "name":"slice", "namespace":"prod", "resourceVersion":"4", "labels":{"kubernetes.io/service-name":"web"},
            "annotations":{"endpoints.kubernetes.io/last-change-trigger-time":"2024-01-01T00:00:00Z"}}, "addressType":"IPv4"
    }));
    until(|| {
        let mut out = String::new();
        registry.encode(&mut out);
        out.contains("pharos_kubernetes_dns_programming_duration_seconds_count{service_kind=\"cluster_ip\"} 3")
    }).await;
    assert!(!controller.has_synced());
    assert_eq!(
        store.with_read(|index| index.endpoints("prod", "web").count()),
        1
    );
    controller.stop().await;
}

#[tokio::test]
async fn startup_timeout_allows_unsynced_then_becomes_ready() {
    let server = FakeServer::start().await;
    server
        .list_delay
        .store(200, std::sync::atomic::Ordering::Relaxed);
    let client = kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
    let mut controller = Controller::start(client, WatchConfig::default());
    controller.wait_for_sync(Duration::from_millis(20)).await;
    assert!(!controller.has_synced());
    until(|| controller.has_synced()).await;
    controller.stop().await;
}

#[tokio::test]
async fn watch_events_record_client_and_programming_metrics() {
    let server = FakeServer::start().await;
    let gate = Arc::new(Semaphore::new(0));
    server.path_gates.lock().unwrap().insert(
        "/apis/discovery.k8s.io/v1/endpointslices".into(),
        gate.clone(),
    );
    let namespace_gate = Arc::new(Semaphore::new(0));
    server
        .path_gates
        .lock()
        .unwrap()
        .insert("/api/v1/namespaces".into(), namespace_gate.clone());
    server.lists.lock().unwrap().insert("/apis/discovery.k8s.io/v1/endpointslices".into(), json!([{
        "metadata":{"name":"slice","namespace":"prod","resourceVersion":"1",
            "labels":{"kubernetes.io/service-name":"web"},
            "annotations":{"endpoints.kubernetes.io/last-change-trigger-time":"2024-01-01T00:00:00Z"}},
        "addressType":"IPv4","endpoints":[{"addresses":["10.0.1.1"]}]
    }]));
    let registry = pharos_server::metrics::Registry::new("test", "test", "test");
    let config = pharos_kubernetes::ClientConfig {
        endpoint: Some(server.url.clone()),
        ..Default::default()
    };
    let client = config.client(&registry).await.unwrap();
    let mut controller =
        Controller::start_with_metrics(client, WatchConfig::default(), registry.kubernetes());
    until(|| {
        controller
            .store()
            .with_read(|index| index.service("prod", "web").is_some())
    })
    .await;
    gate.add_permits(1);
    until(|| {
        server
            .watches
            .lock()
            .unwrap()
            .contains_key("/apis/discovery.k8s.io/v1/endpointslices")
    })
    .await;
    assert!(!controller.has_synced());
    let mut before = String::new();
    registry.encode(&mut before);
    assert!(before.contains(
        "pharos_kubernetes_dns_programming_duration_seconds_count{service_kind=\"cluster_ip\"} 1"
    ));
    namespace_gate.add_permits(1);
    until(|| controller.has_synced() && server.watches.lock().unwrap().len() == 3).await;
    server.send("/apis/discovery.k8s.io/v1/endpointslices", "MODIFIED", json!({
        "apiVersion":"discovery.k8s.io/v1", "kind":"EndpointSlice", "metadata":{
            "name":"slice", "namespace":"prod", "resourceVersion":"2",
            "labels":{"kubernetes.io/service-name":"web"},
            "annotations":{"endpoints.kubernetes.io/last-change-trigger-time":"2024-01-01T00:00:00Z"}
        }, "addressType":"IPv4", "endpoints":[{"addresses":["10.0.1.9"]}]
    }));
    until(|| { let mut out = String::new(); registry.encode(&mut out); out.contains("pharos_kubernetes_dns_programming_duration_seconds_count{service_kind=\"cluster_ip\"} 2") }).await;
    let mut out = String::new();
    registry.encode(&mut out);
    assert!(out.contains("pharos_kubernetes_rest_client_requests_total{code=\"200\""));
    assert!(out.contains("pharos_kubernetes_rest_client_request_duration_seconds_count{"));
    server.send("/api/v1/services", "MODIFIED", json!({"apiVersion":"v1", "kind":"Service", "metadata":{"name":"web","namespace":"prod","resourceVersion":"3"}, "spec":{"clusterIP":"None"}}));
    until(|| {
        controller.store().with_read(|index| {
            index
                .service("prod", "web")
                .is_some_and(|service| service.headless())
        })
    })
    .await;
    server.send("/apis/discovery.k8s.io/v1/endpointslices", "MODIFIED", json!({"apiVersion":"discovery.k8s.io/v1", "kind":"EndpointSlice", "metadata":{
        "name":"slice", "namespace":"prod", "resourceVersion":"3", "labels":{"kubernetes.io/service-name":"web"},
        "annotations":{"endpoints.kubernetes.io/last-change-trigger-time":"2024-01-01T00:00:00Z"}}, "addressType":"IPv4"}));
    until(|| { let mut out = String::new(); registry.encode(&mut out); out.contains("pharos_kubernetes_dns_programming_duration_seconds_count{service_kind=\"headless_with_selector\"} 1") }).await;
    controller.stop().await;
}

#[tokio::test]
async fn initial_slice_without_backing_service_is_not_recorded_later() {
    let server = FakeServer::start().await;
    let gate = Arc::new(Semaphore::new(0));
    server
        .path_gates
        .lock()
        .unwrap()
        .insert("/api/v1/services".into(), gate.clone());
    server.lists.lock().unwrap().insert("/apis/discovery.k8s.io/v1/endpointslices".into(), json!([{
        "metadata":{"name":"slice","namespace":"prod","resourceVersion":"1",
            "labels":{"kubernetes.io/service-name":"web"},
            "annotations":{"endpoints.kubernetes.io/last-change-trigger-time":"2024-01-01T00:00:00Z"}},
        "addressType":"IPv4","endpoints":[{"addresses":["10.0.1.1"]}]
    }]));
    let registry = pharos_server::metrics::Registry::new("test", "test", "test");
    let client = kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
    let mut controller =
        Controller::start_with_metrics(client, WatchConfig::default(), registry.kubernetes());
    until(|| {
        server
            .watches
            .lock()
            .unwrap()
            .contains_key("/apis/discovery.k8s.io/v1/endpointslices")
    })
    .await;
    assert!(!controller.has_synced());
    gate.add_permits(1);
    until(|| controller.has_synced()).await;
    let mut out = String::new();
    registry.encode(&mut out);
    assert!(!out.contains("pharos_kubernetes_dns_programming_duration_seconds_count"));
    controller.stop().await;
}

#[tokio::test]
async fn initial_slice_uses_service_available_when_list_batch_is_installed() {
    let server = FakeServer::start().await;
    let service_gate = Arc::new(Semaphore::new(0));
    let page_gate = Arc::new(Semaphore::new(0));
    server
        .path_gates
        .lock()
        .unwrap()
        .insert("/api/v1/services".into(), service_gate.clone());
    *server.endpoint_page_gate.lock().unwrap() = Some(page_gate.clone());
    server.lists.lock().unwrap().insert("/apis/discovery.k8s.io/v1/endpointslices".into(), json!([{
        "metadata":{"name":"slice","namespace":"prod","resourceVersion":"1",
            "labels":{"kubernetes.io/service-name":"web"},
            "annotations":{"endpoints.kubernetes.io/last-change-trigger-time":"2024-01-01T00:00:00Z"}},
        "addressType":"IPv4","endpoints":[{"addresses":["10.0.1.1"]}]
    }]));
    let registry = pharos_server::metrics::Registry::new("test", "test", "test");
    let client = kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
    let mut controller =
        Controller::start_with_metrics(client, WatchConfig::default(), registry.kubernetes());
    until(|| {
        server.requests.lock().unwrap().iter().any(|uri| {
            uri.starts_with("/apis/discovery.k8s.io/v1/endpointslices?")
                && uri.contains("continue=next")
        })
    })
    .await;
    assert!(
        controller
            .store()
            .with_read(|index| index.service("prod", "web").is_none())
    );
    service_gate.add_permits(1);
    until(|| {
        controller
            .store()
            .with_read(|index| index.service("prod", "web").is_some())
    })
    .await;
    page_gate.add_permits(1);
    until(|| controller.has_synced()).await;
    let mut out = String::new();
    registry.encode(&mut out);
    assert!(out.contains(
        "pharos_kubernetes_dns_programming_duration_seconds_count{service_kind=\"cluster_ip\"} 1"
    ));
    controller.stop().await;
}

#[tokio::test]
async fn client_records_throttled_requests() {
    let server = FakeServer::start().await;
    let registry = pharos_server::metrics::Registry::new("test", "test", "test");
    let config = pharos_kubernetes::ClientConfig {
        endpoint: Some(server.url.clone()),
        ..Default::default()
    };
    let client = config.client(&registry).await.unwrap();
    let services = kube::Api::<k8s_openapi::api::core::v1::Service>::all(client);
    for _ in 0..12 {
        services.list(&Default::default()).await.unwrap();
    }
    let mut out = String::new();
    registry.encode(&mut out);
    assert!(out.lines().any(|line| {
        line.starts_with("pharos_kubernetes_rest_client_rate_limiter_duration_seconds_count{")
            && line.ends_with(" 12")
    }));
}

#[tokio::test]
async fn watch_requests_count_results_without_list_latency() {
    let server = FakeServer::start().await;
    let registry = pharos_server::metrics::Registry::new("test", "test", "test");
    let config = pharos_kubernetes::ClientConfig {
        endpoint: Some(server.url.clone()),
        ..Default::default()
    };
    let client = config.client(&registry).await.unwrap();
    let mut controller =
        Controller::start_with_metrics(client, WatchConfig::default(), registry.kubernetes());
    until(|| {
        let mut out = String::new();
        registry.encode(&mut out);
        out.lines().any(|line| {
            line.starts_with("pharos_kubernetes_rest_client_requests_total{")
                && line.ends_with(" 6")
        })
    })
    .await;
    let mut out = String::new();
    registry.encode(&mut out);
    for name in ["request", "rate_limiter"] {
        let prefix = format!("pharos_kubernetes_rest_client_{name}_duration_seconds_count{{");
        assert!(
            out.lines()
                .any(|line| line.starts_with(&prefix) && line.ends_with(" 3")),
            "{out}"
        );
    }
    controller.stop().await;
}

#[tokio::test]
async fn api_client_accepts_custom_throttle_and_inflight_options() {
    let server = FakeServer::start().await;
    let registry = pharos_server::metrics::Registry::new("test", "test", "test");
    let config = pharos_kubernetes::ClientConfig {
        endpoint: Some(server.url.clone()),
        api_qps: 100.0,
        api_burst: 1,
        api_max_inflight: 1,
        ..Default::default()
    };
    let client = config.client(&registry).await.unwrap();
    let services = kube::Api::<k8s_openapi::api::core::v1::Service>::all(client);
    services.list(&Default::default()).await.unwrap();
    services.list(&Default::default()).await.unwrap();
    let mut out = String::new();
    registry.encode(&mut out);
    assert!(out.lines().any(|line| {
        line.starts_with("pharos_kubernetes_rest_client_rate_limiter_duration_seconds_count{")
            && line.ends_with(" 2")
    }));
}

#[tokio::test]
async fn max_inflight_limits_concurrent_api_requests() {
    for (max, expected_peak) in [(0, 2), (1, 1)] {
        let server = FakeServer::start().await;
        server
            .list_delay
            .store(100, std::sync::atomic::Ordering::Relaxed);
        let registry = pharos_server::metrics::Registry::new("test", "test", "test");
        let config = pharos_kubernetes::ClientConfig {
            endpoint: Some(server.url.clone()),
            api_max_inflight: max,
            ..Default::default()
        };
        let client = config.client(&registry).await.unwrap();
        let services = kube::Api::<k8s_openapi::api::core::v1::Service>::all(client);
        let params = Default::default();
        let (a, b) = tokio::join!(services.list(&params), services.list(&params));
        a.unwrap();
        b.unwrap();
        assert_eq!(server.active.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            server.peak.load(std::sync::atomic::Ordering::SeqCst),
            expected_peak
        );
    }
}

#[tokio::test]
async fn lifecycle_restart_failure_restarts_watchers_on_same_store() {
    let server = FakeServer::start().await;
    let client = kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
    let controller = Arc::new(tokio::sync::Mutex::new(Controller::start(
        client,
        WatchConfig::default(),
    )));
    let store = controller.lock().await.store();
    let mut lifecycle = pharos_server::Lifecycle::default();
    Controller::register_hooks(&controller, &mut lifecycle, Duration::from_secs(1));
    lifecycle.run(pharos_server::Phase::Startup).await.unwrap();
    assert!(store.with_read(|index| index.service("prod", "web").is_some()));
    lifecycle.run(pharos_server::Phase::Restart).await.unwrap();
    server
        .lists
        .lock()
        .unwrap()
        .insert("/api/v1/services".into(), json!([]));
    lifecycle
        .run(pharos_server::Phase::RestartFailed)
        .await
        .unwrap();
    assert!(store.with_read(|index| index.service("prod", "web").is_none()));
    lifecycle.run(pharos_server::Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn expired_watch_relist_removes_missing_services() {
    let server = FakeServer::start().await;
    let client = kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
    let mut controller = Controller::start(client, WatchConfig::default());
    let store = controller.store();
    until(|| controller.has_synced() && server.watches.lock().unwrap().len() == 3).await;
    assert!(store.with_read(|index| index.service("prod", "web").is_some()));
    server
        .lists
        .lock()
        .unwrap()
        .insert("/api/v1/services".into(), json!([]));
    let started = std::time::Instant::now();
    server.send("/api/v1/services", "ERROR", json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "reason":"Expired", "message":"resource version too old", "code":410}));
    until(|| store.with_read(|index| index.service("prod", "web").is_none())).await;
    assert!(started.elapsed() >= Duration::from_millis(700));
    controller.stop().await;
}

#[tokio::test]
async fn annotated_relist_records_programming_latency_after_initial_sync() {
    let server = FakeServer::start().await;
    let registry = pharos_server::metrics::Registry::new("test", "test", "test");
    let config = pharos_kubernetes::ClientConfig {
        endpoint: Some(server.url.clone()),
        ..Default::default()
    };
    let client = config.client(&registry).await.unwrap();
    let mut controller =
        Controller::start_with_metrics(client, WatchConfig::default(), registry.kubernetes());
    until(|| controller.has_synced() && server.watches.lock().unwrap().len() == 3).await;
    server.lists.lock().unwrap().insert("/apis/discovery.k8s.io/v1/endpointslices".into(), json!([{
        "metadata":{"name":"slice","namespace":"prod","resourceVersion":"2", "labels":{"kubernetes.io/service-name":"web"},
            "annotations":{"endpoints.kubernetes.io/last-change-trigger-time":"2024-01-01T00:00:00Z"}},
        "addressType":"IPv4","endpoints":[{"addresses":["10.0.1.7"]}]
    }]));
    server.send("/apis/discovery.k8s.io/v1/endpointslices", "ERROR", json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "reason":"Expired", "message":"resource version too old", "code":410}));
    until(|| { let mut out = String::new(); registry.encode(&mut out); out.contains("pharos_kubernetes_dns_programming_duration_seconds_count{service_kind=\"cluster_ip\"} 1") }).await;
    controller.stop().await;
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn controller_applies_list_watch_updates_and_deletions() {
    let server = FakeServer::start().await;
    let client = kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
    let mut controller = Controller::start(client, WatchConfig::default());
    let store = controller.store();
    until(|| controller.has_synced() && server.watches.lock().unwrap().len() == 3).await;
    store.with_read(|index| {
        assert_eq!(
            index.service("prod", "web").unwrap().cluster_ips,
            ["10.0.0.1"]
        );
        assert_eq!(index.endpoints("prod", "web").count(), 1);
        assert!(index.namespace("prod").is_some());
    });
    server.send(
        "/api/v1/services",
        "BOOKMARK",
        json!({"apiVersion":"v1","kind":"Service","metadata":{"resourceVersion":"2"}}),
    );
    server.send("/api/v1/services", "MODIFIED", json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"web","namespace":"prod","resourceVersion":"2"},"spec":{"clusterIP":"10.0.0.2"}}));
    server.send("/apis/discovery.k8s.io/v1/endpointslices", "DELETED", json!({"apiVersion":"discovery.k8s.io/v1","kind":"EndpointSlice","metadata":{"name":"slice","namespace":"prod","resourceVersion":"2"},"addressType":"IPv4"}));
    server.send("/api/v1/namespaces", "DELETED", json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"prod","resourceVersion":"2"}}));
    until(|| {
        store.with_read(|index| {
            index.services_by_ip("10.0.0.2").count() == 1
                && index.endpoints("prod", "web").count() == 0
                && index.namespace("prod").is_none()
        })
    })
    .await;
    server.send("/api/v1/services", "ADDED", json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"new","namespace":"prod","resourceVersion":"3"},"spec":{"clusterIP":"10.0.0.3"}}));
    server.send("/apis/discovery.k8s.io/v1/endpointslices", "ADDED", json!({"apiVersion":"discovery.k8s.io/v1","kind":"EndpointSlice","metadata":{"name":"new-slice","namespace":"prod","resourceVersion":"3","labels":{"kubernetes.io/service-name":"new"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.1.3"]}]}));
    server.send("/api/v1/namespaces", "ADDED", json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"new-ns","resourceVersion":"3"}}));
    until(|| {
        store.with_read(|index| {
            index.service("prod", "new").is_some()
                && index.endpoints_by_ip("10.0.1.3").count() == 1
                && index.namespace("new-ns").is_some()
        })
    })
    .await;
    server.send("/api/v1/services", "DELETED", json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"new","namespace":"prod","resourceVersion":"4"}}));
    server.send("/apis/discovery.k8s.io/v1/endpointslices", "MODIFIED", json!({"apiVersion":"discovery.k8s.io/v1","kind":"EndpointSlice","metadata":{"name":"new-slice","namespace":"prod","resourceVersion":"4","labels":{"kubernetes.io/service-name":"new"}},"addressType":"IPv4","endpoints":[{"addresses":["10.0.1.4"]}]}));
    server.send("/api/v1/namespaces", "MODIFIED", json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"new-ns","resourceVersion":"4"}}));
    until(|| {
        store.with_read(|index| {
            index.service("prod", "new").is_none()
                && index.endpoints_by_ip("10.0.1.4").count() == 1
                && index
                    .namespace("new-ns")
                    .is_some_and(|ns| ns.version == "4")
        })
    })
    .await;
    controller.stop().await;
}

#[tokio::test]
async fn zonal_watch_retains_zones_on_list_update_and_relist() {
    assert!(!WatchConfig::default().zonal);
    for zonal in [false, true] {
        let server = FakeServer::start().await;
        let path = "/apis/discovery.k8s.io/v1/endpointslices";
        let slice = |version: &str, zone: &str| {
            json!({
                "apiVersion":"discovery.k8s.io/v1", "kind":"EndpointSlice",
                "metadata":{"name":"slice", "namespace":"prod", "resourceVersion":version,
                    "labels":{"kubernetes.io/service-name":"web"}},
                "addressType":"IPv4", "endpoints":[{"addresses":["10.0.1.1"], "zone":zone}]
            })
        };
        server
            .lists
            .lock()
            .unwrap()
            .insert(path.into(), json!([slice("1", "Zone-A")]));
        let client =
            kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
        let mut controller = Controller::start(
            client,
            WatchConfig {
                zonal,
                ..Default::default()
            },
        );
        let store = controller.store();
        until(|| controller.has_synced() && server.watches.lock().unwrap().len() == 3).await;
        let check = |version: &str, zone: &str| {
            store.with_read(|index| {
                index.endpoints("prod", "web").next().is_some_and(|ep| {
                    ep.version == version
                        && ep
                            .zones
                            .as_ref()
                            .and_then(|zones| zones.get("10.0.1.1"))
                            .map(String::as_str)
                            == zonal.then_some(zone)
                })
            })
        };
        assert!(check("1", "zone-a"));
        server.send(path, "MODIFIED", slice("2", "Zone-B"));
        until(|| check("2", "zone-b")).await;
        server
            .lists
            .lock()
            .unwrap()
            .insert(path.into(), json!([slice("3", "Zone-C")]));
        server.send(path, "ERROR", json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "reason":"Expired", "message":"resource version too old", "code":410}));
        until(|| check("3", "zone-c")).await;
        controller.stop().await;
    }
}

#[tokio::test]
async fn controller_only_watches_verified_pods_and_sends_selectors() {
    let server = FakeServer::start().await;
    let client = kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
    let mut controller = Controller::start(
        client,
        WatchConfig {
            label_selector: Some("app=web".into()),
            namespace_label_selector: Some("team=dns".into()),
            pods_verified: true,
            endpoints: false,
            ..Default::default()
        },
    );
    until(|| controller.has_synced() && server.watches.lock().unwrap().len() == 3).await;
    server.send("/api/v1/pods", "ADDED", json!({"apiVersion":"v1", "kind":"Pod", "metadata":{"name":"pod","namespace":"prod","resourceVersion":"2"}, "status":{"podIPs":[{"ip":"10.0.2.1"}]}}));
    until(|| {
        controller
            .store()
            .with_read(|index| index.pods_by_ip("10.0.2.1").count() == 1)
    })
    .await;
    {
        let requests = server.requests.lock().unwrap();
        assert!(requests.iter().any(|uri| uri.starts_with("/api/v1/pods?")
            && uri.contains("fieldSelector=")
            && uri.contains("labelSelector=app%3Dweb")));
        assert!(
            requests
                .iter()
                .any(|uri| uri.starts_with("/api/v1/namespaces?")
                    && uri.contains("labelSelector=team%3Ddns"))
        );
        assert!(!requests.iter().any(|uri| uri.contains("endpointslices")));
    }
    controller.stop().await;
}

#[tokio::test]
async fn namespace_list_restricts_readable_store_entries() {
    let server = FakeServer::start().await;
    let client = kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
    let mut controller = Controller::start(
        client,
        WatchConfig {
            namespaces: vec!["other".into()],
            ..Default::default()
        },
    );
    until(|| controller.has_synced()).await;
    controller.store().with_read(|index| {
        assert!(index.namespace("prod").is_none());
        assert!(index.service("prod", "web").is_none());
        assert_eq!(index.services_by_ip("10.0.0.1").count(), 0);
        assert_eq!(index.endpoints("prod", "web").count(), 0);
        assert_eq!(index.endpoints_by_ip("10.0.1.1").count(), 0);
    });
    controller.stop().await;
}

#[tokio::test]
async fn namespace_label_selector_restricts_service_and_endpoint_lookups() {
    let server = FakeServer::start().await;
    server
        .lists
        .lock()
        .unwrap()
        .insert("/api/v1/namespaces".into(), json!([]));
    let client = kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
    let mut controller = Controller::start(
        client,
        WatchConfig {
            namespace_label_selector: Some("team=dns".into()),
            ..Default::default()
        },
    );
    until(|| controller.has_synced()).await;
    controller.store().with_read(|index| {
        assert!(index.service("prod", "web").is_none());
        assert_eq!(index.services_by_ip("10.0.0.1").count(), 0);
        assert_eq!(index.endpoints("prod", "web").count(), 0);
        assert_eq!(index.endpoints_by_ip("10.0.1.1").count(), 0);
    });
    controller.stop().await;
}

#[tokio::test]
async fn upstream_default_processor_service_and_terminating_pod() {
    let server = FakeServer::start().await;
    let client = kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
    let mut controller = Controller::start(
        client,
        WatchConfig {
            pods_verified: true,
            ..Default::default()
        },
    );
    let store = controller.store();
    until(|| controller.has_synced() && server.watches.lock().unwrap().len() == 4).await;

    let service = |name: &str, version: &str, ip: &str| {
        json!({
            "apiVersion":"v1", "kind":"Service",
            "metadata":{"name":name,"namespace":"prod","resourceVersion":version},
            "spec":{"clusterIP":ip,"clusterIPs":[ip],"ports":[{"port":80}]}
        })
    };
    for (name, ip) in [("service1", "1.2.3.4"), ("service2", "5.6.7.8")] {
        server.send("/api/v1/services", "ADDED", service(name, "2", ip));
    }
    until(|| {
        store.with_read(|index| {
            index.service("prod", "service1").is_some()
                && index.service("prod", "service2").is_some()
        })
    })
    .await;
    let mut updated_cluster_ip = service("service1", "3", "1.2.3.4");
    updated_cluster_ip["spec"]["clusterIP"] = json!("1.2.3.5");
    server.send("/api/v1/services", "MODIFIED", updated_cluster_ip);
    until(|| {
        store.with_read(|index| {
            index
                .service("prod", "service1")
                .is_some_and(|svc| svc.version == "3" && svc.cluster_ips == ["1.2.3.4"])
        })
    })
    .await;
    server.send(
        "/api/v1/services",
        "MODIFIED",
        service("service1", "4", "1.2.3.5"),
    );
    until(|| {
        store.with_read(|index| {
            index
                .service("prod", "service1")
                .is_some_and(|svc| svc.cluster_ips == ["1.2.3.5"])
        })
    })
    .await;
    server.send(
        "/api/v1/services",
        "DELETED",
        service("service2", "4", "5.6.7.8"),
    );
    until(|| store.with_read(|index| index.service("prod", "service2").is_none())).await;

    let pod = |version: &str, deleting: bool| {
        json!({
            "apiVersion":"v1", "kind":"Pod",
            "metadata":{"name":"pod1","namespace":"prod","resourceVersion":version,
                "deletionTimestamp": if deleting { Some("2024-01-01T00:00:00Z") } else { None }},
            "status":{"podIPs":[{"ip":"10.0.2.1"}]}
        })
    };
    server.send("/api/v1/pods", "ADDED", pod("2", false));
    until(|| store.with_read(|index| index.pods_by_ip("10.0.2.1").count() == 1)).await;
    server.send("/api/v1/pods", "MODIFIED", pod("3", true));
    server.send("/api/v1/pods", "ADDED", json!({
        "apiVersion":"v1", "kind":"Pod", "metadata":{"name":"marker","namespace":"prod","resourceVersion":"4"},
        "status":{"podIPs":[{"ip":"10.0.2.2"}]}
    }));
    until(|| store.with_read(|index| index.pods_by_ip("10.0.2.2").count() == 1)).await;
    store.with_read(|index| {
        let retained = index.pods_by_ip("10.0.2.1").next().unwrap();
        assert_eq!(retained.version, "2");
        assert!(!retained.deleting);
    });
    server.send("/api/v1/pods", "DELETED", pod("3", true));
    until(|| store.with_read(|index| index.pods_by_ip("10.0.2.1").count() == 0)).await;

    // kube-runtime reconciles a missed delete when the next list completes.
    server
        .lists
        .lock()
        .unwrap()
        .insert("/api/v1/services".into(), json!([]));
    server.send(
        "/api/v1/services",
        "ERROR",
        json!({"apiVersion":"v1","kind":"Status","status":"Failure","reason":"Expired","code":410}),
    );
    until(|| store.with_read(|index| index.service("prod", "service1").is_none())).await;
    controller.stop().await;
}

#[tokio::test]
async fn upstream_namespace_cases() {
    for (allowed, name, configured, valid) in [
        (vec!["foobar"], "foobar", true, true),
        (vec!["foobar"], "nsnoexist", false, false),
        (vec![], "foobar", true, true),
        (vec![], "nsnoexist", true, false),
    ] {
        let server = FakeServer::start().await;
        server.lists.lock().unwrap().insert(
            "/api/v1/namespaces".into(),
            json!([{"metadata":{"name":"foobar"}}]),
        );
        server.lists.lock().unwrap().insert(
            "/api/v1/services".into(),
            json!([
                {"metadata":{"name":"web","namespace":"foobar"},"spec":{"clusterIP":"10.0.0.1"}},
                {"metadata":{"name":"web","namespace":"nsnoexist"},"spec":{"clusterIP":"10.0.0.2"}}
            ]),
        );
        let client =
            kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
        let mut controller = Controller::start(
            client,
            WatchConfig {
                namespaces: allowed.into_iter().map(String::from).collect(),
                ..Default::default()
            },
        );
        until(|| controller.has_synced()).await;
        controller.store().with_read(|index| {
            assert_eq!(
                index.service(name, "web").is_some(),
                configured,
                "configured {name}"
            );
            assert_eq!(index.namespace(name).is_some(), valid, "valid {name}");
        });
        controller.stop().await;
    }
}

#[test]
fn upstream_metric_labels_preserve_valid_utf8() {
    let registry = pharos_server::metrics::Registry::new("test", "test", "test");
    for host in ["example.com", "例え.jp", ""] {
        registry.kubernetes().request("GET", host).result("200");
    }
    let mut output = String::new();
    registry.encode(&mut output);
    for host in ["example.com", "例え.jp", ""] {
        assert!(
            output.contains(&format!("host=\"{host}\"")),
            "{host:?}: {output}"
        );
    }
}

// CoreDNS object/metrics_test.go TestEndpointLatencyRecorder_record.
#[tokio::test]
async fn upstream_endpoint_latency_recorder_rows() {
    for (name, cluster_ip, annotated, expected_label, expected_count) in [
        (
            "headless annotated",
            Some("None"),
            true,
            "headless_with_selector",
            1,
        ),
        ("cluster annotated", Some("10.0.0.1"), true, "cluster_ip", 1),
        (
            "headless no annotation",
            Some("None"),
            false,
            "headless_with_selector",
            0,
        ),
        (
            "cluster no annotation",
            Some("10.0.0.1"),
            false,
            "cluster_ip",
            0,
        ),
        ("missing service", None, true, "cluster_ip", 0),
    ] {
        let server = FakeServer::start().await;
        let endpoints_path = "/apis/discovery.k8s.io/v1/endpointslices";
        let gate = Arc::new(Semaphore::new(0));
        server
            .path_gates
            .lock()
            .unwrap()
            .insert(endpoints_path.into(), gate.clone());
        let services = cluster_ip.map_or_else(
            || json!([]),
            |ip| {
                json!([
                    {"metadata":{"name":"web","namespace":"prod"},"spec":{"clusterIP":ip}}
                ])
            },
        );
        server
            .lists
            .lock()
            .unwrap()
            .insert("/api/v1/services".into(), services);
        let mut slice = json!({
            "metadata":{"name":"slice","namespace":"prod","labels":{"kubernetes.io/service-name":"web"}},
            "addressType":"IPv4", "endpoints":[{"addresses":["10.0.0.2"]}]
        });
        if annotated {
            slice["metadata"]["annotations"] =
                json!({"endpoints.kubernetes.io/last-change-trigger-time":"2024-01-01T00:00:00Z"});
        }
        server
            .lists
            .lock()
            .unwrap()
            .insert(endpoints_path.into(), json!([slice]));
        let registry = pharos_server::metrics::Registry::new("test", "test", "test");
        let client =
            kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
        let mut controller =
            Controller::start_with_metrics(client, WatchConfig::default(), registry.kubernetes());
        if cluster_ip.is_some() {
            until(|| {
                controller
                    .store()
                    .with_read(|index| index.service("prod", "web").is_some())
            })
            .await;
        }
        gate.add_permits(1);
        until(|| controller.has_synced()).await;
        let mut output = String::new();
        registry.encode(&mut output);
        let sample = format!(
            "pharos_kubernetes_dns_programming_duration_seconds_count{{service_kind=\"{expected_label}\"}} {expected_count}"
        );
        if expected_count == 0 {
            assert!(
                !output.contains("pharos_kubernetes_dns_programming_duration_seconds_count"),
                "{name}: {output}"
            );
        } else {
            assert!(output.contains(&sample), "{name}: {output}");
        }
        controller.stop().await;
    }
}

#[tokio::test]
async fn upstream_endpoint_equivalence_updates_serial_only_for_dns_changes() {
    let cases = [
        (
            "identical",
            json!([{"addresses":["10.0.0.1"],"hostname":"a"}]),
            json!([{"name":"http","port":80,"protocol":"TCP"}]),
            false,
        ),
        (
            "different address count",
            json!([]),
            json!([{"name":"http","port":80,"protocol":"TCP"}]),
            true,
        ),
        (
            "different port count",
            json!([{"addresses":["10.0.0.1"],"hostname":"a"}]),
            json!([]),
            true,
        ),
        (
            "different ip",
            json!([{"addresses":["10.0.0.2"],"hostname":"a"}]),
            json!([{"name":"http","port":80,"protocol":"TCP"}]),
            true,
        ),
        (
            "different hostname",
            json!([{"addresses":["10.0.0.1"],"hostname":"b"}]),
            json!([{"name":"http","port":80,"protocol":"TCP"}]),
            true,
        ),
        (
            "different port number",
            json!([{"addresses":["10.0.0.1"],"hostname":"a"}]),
            json!([{"name":"http","port":8080,"protocol":"TCP"}]),
            true,
        ),
        (
            "different port protocol",
            json!([{"addresses":["10.0.0.1"],"hostname":"a"}]),
            json!([{"name":"http","port":80,"protocol":"UDP"}]),
            true,
        ),
    ];
    futures::future::join_all(cases.into_iter().map(
        |(name, endpoints, ports, changed)| async move {
            let server = FakeServer::start().await;
            let path = "/apis/discovery.k8s.io/v1/endpointslices";
            let slice = |version: &str, endpoints: Value, ports: Value| {
                json!({
                    "apiVersion":"discovery.k8s.io/v1", "kind":"EndpointSlice",
                    "metadata":{"name":"slice","namespace":"prod","resourceVersion":version,
                        "labels":{"kubernetes.io/service-name":"web"}},
                    "addressType":"IPv4", "endpoints":endpoints, "ports":ports
                })
            };
            server.lists.lock().unwrap().insert(
                path.into(),
                json!([slice(
                    "1",
                    json!([{"addresses":["10.0.0.1"],"hostname":"a"}]),
                    json!([{"name":"http","port":80,"protocol":"TCP"}])
                )]),
            );
            let client =
                kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
            let mut controller = Controller::start(client, WatchConfig::default());
            let store = controller.store();
            until(|| controller.has_synced() && server.watches.lock().unwrap().contains_key(path))
                .await;
            let serial = store.with_read(|index| index.serial());
            tokio::time::sleep(Duration::from_millis(1100)).await;
            server.send(path, "MODIFIED", slice("2", endpoints, ports));
            until(|| {
                store.with_read(|index| {
                    index
                        .endpoints("prod", "web")
                        .next()
                        .is_some_and(|ep| ep.version == "2")
                })
            })
            .await;
            assert_eq!(
                store.with_read(|index| index.serial() != serial),
                changed,
                "{name}"
            );
            controller.stop().await;
        },
    ))
    .await;
}

#[tokio::test]
async fn upstream_endpoint_equivalence_add_and_remove() {
    futures::future::join_all(["ADDED", "DELETED"].into_iter().map(|event| async move {
        let server = FakeServer::start().await;
        let path = "/apis/discovery.k8s.io/v1/endpointslices";
        let slice = json!({"apiVersion":"discovery.k8s.io/v1", "kind":"EndpointSlice",
            "metadata":{"name":"slice","namespace":"prod","resourceVersion":"2",
                "labels":{"kubernetes.io/service-name":"web"}},
            "addressType":"IPv4", "endpoints":[{"addresses":["10.0.0.1"]}],
            "ports":[{"name":"http","port":80,"protocol":"TCP"}]
        });
        server.lists.lock().unwrap().insert(
            path.into(),
            if event == "ADDED" {
                json!([])
            } else {
                json!([slice.clone()])
            },
        );
        let client =
            kube::Client::try_from(kube::Config::new(server.url.parse().unwrap())).unwrap();
        let mut controller = Controller::start(client, WatchConfig::default());
        let store = controller.store();
        until(|| controller.has_synced() && server.watches.lock().unwrap().contains_key(path))
            .await;
        let serial = store.with_read(|index| index.serial());
        tokio::time::sleep(Duration::from_millis(1100)).await;
        server.send(path, event, slice);
        until(|| {
            store.with_read(|index| {
                (index.endpoints("prod", "web").count() == 1) == (event == "ADDED")
            })
        })
        .await;
        assert_ne!(store.with_read(|index| index.serial()), serial, "{event}");
        controller.stop().await;
    }))
    .await;
}
