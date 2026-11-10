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
use tokio::{net::TcpListener, sync::mpsc};

type Watches = Arc<Mutex<HashMap<String, mpsc::UnboundedSender<String>>>>;
type Requests = Arc<Mutex<Vec<String>>>;

struct FakeServer {
    url: String,
    watches: Watches,
    requests: Requests,
    lists: Arc<Mutex<HashMap<String, Value>>>,
    list_delay: Arc<std::sync::atomic::AtomicU64>,
    active: Arc<std::sync::atomic::AtomicUsize>,
    peak: Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let watches: Watches = Arc::default();
        let requests: Requests = Arc::default();
        let lists: Arc<Mutex<HashMap<String, Value>>> = Arc::default();
        let list_delay = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task_watches = watches.clone();
        let task_requests = requests.clone();
        let task_lists = lists.clone();
        let task_delay = list_delay.clone();
        let task_active = active.clone();
        let task_peak = peak.clone();
        let task = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let watches = task_watches.clone();
                let requests = task_requests.clone();
                let lists = task_lists.clone();
                let delay = task_delay.clone();
                let active = task_active.clone();
                let peak = task_peak.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let watches = watches.clone();
                        let requests = requests.clone();
                        let lists = lists.clone();
                        let delay = delay.clone();
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
                                tokio::time::sleep(Duration::from_millis(
                                    delay.load(std::sync::atomic::Ordering::Relaxed),
                                ))
                                .await;
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
                                let items =
                                    lists.lock().unwrap().get(&path).cloned().unwrap_or(items);
                                let body = json!({"apiVersion":api, "kind":kind, "metadata":{"resourceVersion":"1"}, "items":items}).to_string();
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
    until(|| controller.has_synced() && server.watches.lock().unwrap().len() == 3).await;
    let mut before = String::new();
    registry.encode(&mut before);
    assert!(!before.contains("pharos_kubernetes_dns_programming_duration_seconds_count"));
    server.send("/apis/discovery.k8s.io/v1/endpointslices", "MODIFIED", json!({
        "apiVersion":"discovery.k8s.io/v1", "kind":"EndpointSlice", "metadata":{
            "name":"slice", "namespace":"prod", "resourceVersion":"2",
            "labels":{"kubernetes.io/service-name":"web"},
            "annotations":{"endpoints.kubernetes.io/last-change-trigger-time":"2024-01-01T00:00:00Z"}
        }, "addressType":"IPv4", "endpoints":[{"addresses":["10.0.1.9"]}]
    }));
    until(|| { let mut out = String::new(); registry.encode(&mut out); out.contains("pharos_kubernetes_dns_programming_duration_seconds_count{service_kind=\"cluster_ip\"} 1") }).await;
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
    server.send("/api/v1/services", "ERROR", json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "reason":"Expired", "message":"resource version too old", "code":410}));
    until(|| store.with_read(|index| index.service("prod", "web").is_none())).await;
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
