use std::{
    fmt::Debug,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use futures::{StreamExt, pin_mut};
use k8s_openapi::api::{core::v1, discovery::v1::EndpointSlice};
use kube::{
    Api, Client, Resource, ResourceExt,
    core::{ApiResource, DynamicObject, GroupVersionKind},
    runtime::{
        WatchStreamExt,
        watcher::{self, Event},
    },
};
use serde::de::DeserializeOwned;
use tokio::task::JoinHandle;

use crate::object::Endpoints;
use crate::store::{Index, Store};
use pharos_server::metrics::KubernetesMetrics;

pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
type Conversion<K, T> = (fn(&K) -> Option<SliceLatency>, fn(K) -> T);

/// Values supplied by the kubernetes Plugin's Corefile configuration.
#[derive(Clone, Debug)]
pub struct WatchConfig {
    pub namespaces: Vec<String>,
    pub label_selector: Option<String>,
    pub namespace_label_selector: Option<String>,
    pub pods_verified: bool,
    pub endpoints: bool,
    pub zonal: bool,
    pub multicluster: bool,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            namespaces: Vec::new(),
            label_selector: None,
            namespace_label_selector: None,
            pods_verified: false,
            endpoints: true,
            zonal: false,
            multicluster: false,
        }
    }
}

pub struct Controller {
    store: Store,
    synced: Vec<Arc<AtomicBool>>,
    tasks: Vec<JoinHandle<()>>,
    client: Client,
    config: WatchConfig,
    metrics: Option<KubernetesMetrics>,
}

struct SyncStatus(Vec<Arc<AtomicBool>>);

impl pharos_server::Readiness for SyncStatus {
    fn ready(&self) -> bool {
        self.0.iter().all(|synced| synced.load(Ordering::Acquire))
    }
}

impl Controller {
    pub fn start(client: Client, config: WatchConfig) -> Self {
        let store = Store::new(
            &config.namespaces,
            config.namespace_label_selector.is_some(),
        );
        Self::start_with_store(client, config, store, None)
    }

    pub fn start_with_metrics(
        client: Client,
        config: WatchConfig,
        metrics: KubernetesMetrics,
    ) -> Self {
        let store = Store::new(
            &config.namespaces,
            config.namespace_label_selector.is_some(),
        );
        Self::start_with_store(client, config, store, Some(metrics))
    }

    fn start_with_store(
        client: Client,
        config: WatchConfig,
        store: Store,
        metrics: Option<KubernetesMetrics>,
    ) -> Self {
        let mut this = Self {
            store,
            synced: Vec::new(),
            tasks: Vec::new(),
            client: client.clone(),
            config: config.clone(),
            metrics,
        };
        let labels = watcher::Config {
            label_selector: config.label_selector.clone(),
            ..Default::default()
        };
        this.watch(
            Api::<v1::Service>::all(client.clone()),
            labels.clone(),
            Store::apply_service,
            Store::delete_service,
            |store, objects, _, _| store.replace_services(objects),
            (|_| None, Into::into),
        );
        if config.endpoints {
            this.watch(
                Api::<EndpointSlice>::all(client.clone()),
                labels.clone(),
                Store::apply_endpoints,
                Store::delete_endpoints,
                replace_endpoint_batch,
                (
                    endpoint_latency,
                    if config.zonal {
                        Endpoints::from_slice_with_zones
                    } else {
                        Endpoints::from
                    },
                ),
            );
        }
        if config.pods_verified {
            let pod_config = watcher::Config {
                field_selector: Some(
                    "status.phase!=Succeeded,status.phase!=Failed,status.phase!=Unknown".into(),
                ),
                ..labels.clone()
            };
            this.watch(
                Api::<v1::Pod>::all(client.clone()),
                pod_config,
                Store::apply_pod,
                Store::delete_pod,
                |store, objects, _, _| store.replace_pods(objects),
                (|_| None, Into::into),
            );
        }
        if config.multicluster {
            let selector = match &config.label_selector {
                Some(selector) if !selector.is_empty() => {
                    format!("{selector},multicluster.kubernetes.io/service-name")
                }
                _ => "multicluster.kubernetes.io/service-name".into(),
            };
            this.watch(
                Api::<EndpointSlice>::all(client.clone()),
                watcher::Config {
                    label_selector: Some(selector),
                    ..Default::default()
                },
                Store::apply_multicluster_endpoints,
                Store::delete_multicluster_endpoints,
                |store, objects, latencies, metrics| {
                    store.replace_multicluster_endpoints(objects);
                    for latency in latencies {
                        record_latency(store, metrics, Some(latency));
                    }
                },
                (endpoint_latency, Into::into),
            );
            let resource = ApiResource::from_gvk_with_plural(
                &GroupVersionKind::gvk("multicluster.x-k8s.io", "v1alpha1", "ServiceImport"),
                "serviceimports",
            );
            // CoreDNS matches ServiceImport labels against `namespace_labels`; that
            // hides imports in exposed Namespaces, so namespace filtering happens at lookup.
            this.watch(
                Api::<DynamicObject>::all_with(client.clone(), &resource),
                watcher::Config::default(),
                Store::apply_service_import,
                Store::delete_service_import,
                |store, objects, _, _| store.replace_service_imports(objects),
                (|_| None, Into::into),
            );
        }
        let ns_config = watcher::Config {
            label_selector: config.namespace_label_selector,
            ..Default::default()
        };
        this.watch(
            Api::<v1::Namespace>::all(client),
            ns_config,
            Store::apply_namespace,
            |store, _, name| store.delete_namespace(name),
            |store, objects, _, _| store.replace_namespaces(objects),
            (|_| None, Into::into),
        );
        this
    }

    /// Register the controller with the server configuration lifecycle.
    pub fn register_hooks(
        controller: &Arc<tokio::sync::Mutex<Self>>,
        lifecycle: &mut pharos_server::Lifecycle,
        startup_timeout: Duration,
    ) {
        let start = controller.clone();
        lifecycle.register(pharos_server::Phase::Startup, move || {
            let controller = start.clone();
            async move {
                controller.lock().await.wait_for_sync(startup_timeout).await;
                Ok(())
            }
        });
        let restart = controller.clone();
        lifecycle.register(pharos_server::Phase::RestartFailed, move || {
            let controller = restart.clone();
            async move {
                let mut current = controller.lock().await;
                *current = Self::start_with_store(
                    current.client.clone(),
                    current.config.clone(),
                    current.store.clone(),
                    current.metrics.clone(),
                );
                current.wait_for_sync(startup_timeout).await;
                Ok(())
            }
        });
        let stop = controller.clone();
        let stop = move || {
            let controller = stop.clone();
            async move {
                controller.lock().await.stop().await;
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Restart, stop.clone());
        lifecycle.register(pharos_server::Phase::Shutdown, stop);
    }

    fn watch<K, T>(
        &mut self,
        api: Api<K>,
        config: watcher::Config,
        apply: fn(&Store, T),
        delete: fn(&Store, &str, &str),
        replace: fn(&Store, Vec<T>, Vec<SliceLatency>, Option<&KubernetesMetrics>),
        conversion: Conversion<K, T>,
    ) where
        K: Resource + Clone + DeserializeOwned + Debug + Send + Sync + 'static,
        T: Send + 'static,
    {
        let (observe, convert) = conversion;
        let store = self.store.clone();
        let metrics = self.metrics.clone();
        let synced = Arc::new(AtomicBool::new(false));
        self.synced.push(synced.clone());
        self.tasks.push(tokio::spawn(async move {
            // shortcut: kube-runtime 5 retries a watch rejected with HTTP 410 using the same
            // expired resourceVersion; rebuild the watcher to relist until upstream fixes it.
            // KEP-752 §Implementation > Requirements: Relist after a watcher restart.
            'relist: loop {
                let stream = watcher::watcher(api.clone(), config.clone()).default_backoff();
                pin_mut!(stream);
                let mut initial = Vec::new();
                let mut list_latencies = Vec::new();
                while let Some(event) = stream.next().await {
                    match event {
                        Ok(Event::Init) => {
                            initial.clear();
                            list_latencies.clear();
                        }
                        Ok(Event::InitApply(object)) => {
                            if metrics.is_some()
                                && let Some(latency) = observe(&object)
                            {
                                list_latencies.push(latency);
                            }
                            initial.push(convert(object));
                        }
                        // Kubernetes API concepts §Efficient detection of changes: synchronize from a list.
                        Ok(Event::InitDone) => {
                            replace(
                                &store,
                                std::mem::take(&mut initial),
                                std::mem::take(&mut list_latencies),
                                metrics.as_ref(),
                            );
                            synced.store(true, Ordering::Release);
                        }
                        Ok(Event::Apply(object)) => {
                            let latency = metrics.is_some().then(|| observe(&object)).flatten();
                            apply(&store, convert(object));
                            record_latency(&store, metrics.as_ref(), latency);
                        }
                        Ok(Event::Delete(object)) => {
                            let latency = metrics.is_some().then(|| observe(&object)).flatten();
                            delete(
                                &store,
                                object.namespace().as_deref().unwrap_or(""),
                                &object.name_any(),
                            );
                            record_latency(&store, metrics.as_ref(), latency);
                        }
                        Err(error) => {
                            pharos_server::logging::log(
                                "WARN",
                                "kubernetes",
                                &format!("Kubernetes watch error: {error}"),
                            );
                            // Kubernetes API concepts, "Efficient detection of changes":
                            // 410 Gone means the resourceVersion expired; relist.
                            if let watcher::Error::WatchStartFailed(kube::Error::Api(status)) =
                                &error
                                && status.code == 410
                            {
                                // client-go reflector: backoff starts at 800 ms.
                                tokio::time::sleep(Duration::from_millis(800)).await;
                                continue 'relist;
                            }
                        }
                    }
                }
                break;
            }
        }));
    }

    pub fn store(&self) -> Store {
        self.store.clone()
    }
    pub fn sync_status(&self) -> Arc<dyn pharos_server::Readiness> {
        Arc::new(SyncStatus(self.synced.clone()))
    }
    /// Stop the previous watchers and start new ones against the existing cache.
    pub async fn restart(mut self) -> Self {
        self.stop().await;
        Self::start_with_store(
            self.client.clone(),
            self.config.clone(),
            self.store.clone(),
            self.metrics.clone(),
        )
    }
    pub fn has_synced(&self) -> bool {
        self.synced
            .iter()
            .all(|synced| synced.load(Ordering::Acquire))
    }
    pub async fn wait_for_sync(&self, timeout: Duration) {
        Self::wait_for_sync_status(self.sync_status().as_ref(), timeout).await;
    }
    pub async fn stop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
        for synced in &self.synced {
            synced.store(false, Ordering::Release);
        }
    }
    pub async fn wait_for_sync_status(status: &dyn pharos_server::Readiness, timeout: Duration) {
        let mut check = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_millis(100),
            Duration::from_millis(100),
        );
        let mut log = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_millis(500),
            Duration::from_millis(500),
        );
        let deadline = tokio::time::sleep(timeout);
        pin_mut!(deadline);
        loop {
            tokio::select! {
                _ = check.tick() => if status.ready() { return; },
                _ = log.tick() => pharos_server::logging::log("INFO", "kubernetes", "waiting for Kubernetes API before starting server"),
                _ = &mut deadline => {
                    pharos_server::logging::log("WARN", "kubernetes", "starting server with unsynced Kubernetes API");
                    return;
                }
            }
        }
    }
}

struct SliceLatency {
    timestamp: jiff::Timestamp,
    namespace: String,
    service: String,
}

fn endpoint_latency(slice: &EndpointSlice) -> Option<SliceLatency> {
    let metadata = slice
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| {
            annotations.get("endpoints.kubernetes.io/last-change-trigger-time")
        })?;
    let Ok(timestamp) = metadata.parse::<jiff::Timestamp>() else {
        return None;
    };
    let service = slice
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get("kubernetes.io/service-name"))?;
    Some(SliceLatency {
        timestamp,
        namespace: slice.metadata.namespace.clone().unwrap_or_default(),
        service: service.clone(),
    })
}

fn service_kind(index: &Index, latency: &SliceLatency) -> Option<&'static str> {
    index
        .service_unfiltered(&latency.namespace, &latency.service)
        .map(|service| {
            if service.headless() {
                "headless_with_selector"
            } else {
                "cluster_ip"
            }
        })
}

fn replace_endpoint_batch(
    store: &Store,
    objects: Vec<crate::object::Endpoints>,
    latencies: Vec<SliceLatency>,
    metrics: Option<&KubernetesMetrics>,
) {
    let matched = store.replace_endpoints(objects, |index| {
        latencies
            .into_iter()
            .filter_map(|latency| {
                service_kind(index, &latency).map(|kind| (latency.timestamp, kind))
            })
            .collect::<Vec<_>>()
    });
    if let Some(metrics) = metrics {
        for (timestamp, kind) in matched {
            metrics.programming_duration(
                kind,
                jiff::Timestamp::now()
                    .duration_since(timestamp)
                    .as_secs_f64(),
            );
        }
    }
}

fn record_latency(store: &Store, metrics: Option<&KubernetesMetrics>, value: Option<SliceLatency>) {
    if let (Some(metrics), Some(latency)) = (metrics, value) {
        let kind = store.with_read(|index| service_kind(index, &latency));
        if let Some(kind) = kind {
            metrics.programming_duration(
                kind,
                jiff::Timestamp::now()
                    .duration_since(latency.timestamp)
                    .as_secs_f64(),
            );
        }
    }
}

impl pharos_server::Readiness for Controller {
    fn ready(&self) -> bool {
        self.has_synced()
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
