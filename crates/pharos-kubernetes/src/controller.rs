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
    runtime::watcher::{self, Event},
};
use serde::de::DeserializeOwned;
use tokio::task::JoinHandle;

use crate::store::Store;
use pharos_server::metrics::KubernetesMetrics;

pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Values supplied by the kubernetes Plugin's Corefile configuration.
#[derive(Clone, Debug)]
pub struct WatchConfig {
    pub namespaces: Vec<String>,
    pub label_selector: Option<String>,
    pub namespace_label_selector: Option<String>,
    pub pods_verified: bool,
    pub endpoints: bool,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            namespaces: Vec::new(),
            label_selector: None,
            namespace_label_selector: None,
            pods_verified: false,
            endpoints: true,
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

impl Controller {
    pub fn start(client: Client, config: WatchConfig) -> Self {
        Self::start_with_store(client, config, Store::default(), None)
    }

    pub fn start_with_metrics(
        client: Client,
        config: WatchConfig,
        metrics: KubernetesMetrics,
    ) -> Self {
        Self::start_with_store(client, config, Store::default(), Some(metrics))
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
            label_selector: config.label_selector,
            ..Default::default()
        };
        this.watch(
            Api::<v1::Service>::all(client.clone()),
            labels.clone(),
            Store::apply_service,
            Store::delete_service,
            Store::replace_services,
            |_, _| None,
        );
        if config.endpoints {
            this.watch(
                Api::<EndpointSlice>::all(client.clone()),
                labels.clone(),
                Store::apply_endpoints,
                Store::delete_endpoints,
                Store::replace_endpoints,
                record_endpoint_latency,
            );
        }
        if config.pods_verified {
            let pod_config = watcher::Config {
                field_selector: Some(
                    "status.phase!=Succeeded,status.phase!=Failed,status.phase!=Unknown".into(),
                ),
                ..labels
            };
            this.watch(
                Api::<v1::Pod>::all(client.clone()),
                pod_config,
                Store::apply_pod,
                Store::delete_pod,
                Store::replace_pods,
                |_, _| None,
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
            Store::replace_namespaces,
            |_, _| None,
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
        replace: fn(&Store, Vec<T>),
        observe: fn(&Store, &K) -> Option<(jiff::Timestamp, &'static str)>,
    ) where
        K: Resource<DynamicType = ()> + Clone + DeserializeOwned + Debug + Send + Sync + 'static,
        T: From<K> + Send + 'static,
    {
        let store = self.store.clone();
        let metrics = self.metrics.clone();
        let synced = Arc::new(AtomicBool::new(false));
        self.synced.push(synced.clone());
        self.tasks.push(tokio::spawn(async move {
            let stream = watcher::watcher(api, config);
            pin_mut!(stream);
            let mut initial = Vec::new();
            while let Some(event) = stream.next().await {
                match event {
                    Ok(Event::Init) => initial.clear(),
                    Ok(Event::InitApply(object)) => initial.push(object.into()),
                    Ok(Event::InitDone) => {
                        replace(&store, std::mem::take(&mut initial));
                        synced.store(true, Ordering::Release);
                    }
                    Ok(Event::Apply(object)) => {
                        let latency = synced
                            .load(Ordering::Acquire)
                            .then(|| observe(&store, &object))
                            .flatten();
                        apply(&store, object.into());
                        record_latency(metrics.as_ref(), latency);
                    }
                    Ok(Event::Delete(object)) => {
                        let latency = synced
                            .load(Ordering::Acquire)
                            .then(|| observe(&store, &object))
                            .flatten();
                        delete(
                            &store,
                            object.namespace().as_deref().unwrap_or(""),
                            &object.name_any(),
                        );
                        record_latency(metrics.as_ref(), latency);
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
                }
            }
        }));
    }

    pub fn store(&self) -> Store {
        self.store.clone()
    }
    pub fn has_synced(&self) -> bool {
        self.synced
            .iter()
            .all(|synced| synced.load(Ordering::Acquire))
    }
    pub async fn wait_for_sync(&self, timeout: Duration) {
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
                _ = check.tick() => if self.has_synced() { return; },
                _ = log.tick() => pharos_server::logging::log("INFO", "kubernetes", "waiting for Kubernetes API before starting server"),
                _ = &mut deadline => {
                    pharos_server::logging::log("WARN", "kubernetes", "starting server with unsynced Kubernetes API");
                    return;
                }
            }
        }
    }
    pub async fn stop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
    }
}

fn record_endpoint_latency(
    store: &Store,
    slice: &EndpointSlice,
) -> Option<(jiff::Timestamp, &'static str)> {
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
    let namespace = slice.metadata.namespace.as_deref().unwrap_or("");
    store.with_read(|index| {
        index.service(namespace, service).map(|service| {
            let kind = if service.headless() {
                "headless_with_selector"
            } else {
                "cluster_ip"
            };
            (timestamp, kind)
        })
    })
}

fn record_latency(
    metrics: Option<&KubernetesMetrics>,
    value: Option<(jiff::Timestamp, &'static str)>,
) {
    if let (Some(metrics), Some((timestamp, kind))) = (metrics, value) {
        metrics.programming_duration(
            kind,
            jiff::Timestamp::now()
                .duration_since(timestamp)
                .as_secs_f64(),
        );
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
