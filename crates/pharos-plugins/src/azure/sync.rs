//! Keeps every hosted zone's Zone in step with Azure: a background task lists, builds and swaps.

use std::{sync::Arc, sync::Mutex, time::Duration};

use pharos_proto::Name;
use pharos_server::logging::log;
use tokio::task::JoinHandle;

use super::{HostedZone, client::Client, records::build_zone};

#[derive(Debug)]
pub(super) struct Syncer {
    client: Client,
    zones: Vec<Arc<HostedZone>>,
    /// Configured zone names as they appear in the failure log.
    names: String,
    refresh: Duration,
    list_timeout: Duration,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Syncer {
    pub(super) fn new(
        client: Client,
        zones: Vec<Arc<HostedZone>>,
        names: &[Name],
        refresh: Duration,
        list_timeout: Duration,
    ) -> Self {
        let names = names.iter().map(Name::to_string).collect::<Vec<_>>();
        Self {
            client,
            zones,
            names: format!("[{}]", names.join(" ")),
            refresh,
            list_timeout,
            task: Mutex::new(None),
        }
    }

    /// CoreDNS v1.15.0 plugin/azure/azure.go updateZones: every hosted zone is tried; the errors are collected.
    pub(super) async fn update_zones(&self) -> Result<(), String> {
        let mut errors = Vec::new();
        for hosted in &self.zones {
            if let Err(error) = self.update_zone(hosted).await {
                errors.push(format!(
                    "failed to update {}:{} from azure: {error}",
                    hosted.spec.resource_group, hosted.spec.zone
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!("errors updating zones: [{}]", errors.join(", ")))
        }
    }

    /// CoreDNS v1.15.0 plugin/azure/azure.go updateZone: all pages within one deadline, a Zone with an SOA, then one swap.
    async fn update_zone(&self, hosted: &HostedZone) -> Result<(), String> {
        let records = tokio::time::timeout(self.list_timeout, self.client.list(&hosted.spec))
            .await
            .map_err(|_| format!("listing timed out after {:?}", self.list_timeout))??;
        // RFC 1035 §6.1: building a large Zone is CPU work that must not stall Query tasks on this worker.
        let apex = hosted.apex.clone();
        let zone = tokio::task::spawn_blocking(move || build_zone(&apex, records))
            .await
            .map_err(|error| format!("zone build failed: {error}"))??;
        hosted.publish(zone);
        Ok(())
    }

    /// The log line for a failed sync; no secret or token can appear in it.
    pub(super) fn failure_message(&self, error: String) -> String {
        // CoreDNS v1.15.0 plugin/azure/azure.go run: `Failed to update zones %v: %v`.
        self.client
            .scrub(format!("Failed to update zones {}: {error}", self.names))
    }

    /// Start (or restart) the background sync; returns at once.
    pub(super) fn start(self: &Arc<Self>) {
        let syncer = Arc::clone(self);
        let task = tokio::spawn(async move {
            // CoreDNS v1.15.0 plugin/azure/azure.go run: sync now, then one refresh interval after each finish.
            loop {
                if let Err(error) = syncer.update_zones().await {
                    log("ERROR", "azure", &syncer.failure_message(error));
                }
                tokio::time::sleep(syncer.refresh).await;
            }
        });
        if let Some(previous) = self.task.lock().unwrap().replace(task) {
            previous.abort();
        }
    }

    /// Cancel the background sync, aborting a request in flight, and wait for it to end.
    pub(super) async fn stop(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }
}
