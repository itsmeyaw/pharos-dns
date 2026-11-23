//! Readiness of the Plugin: a cached flag a background probe keeps current.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use pharos_server::{Lifecycle, Phase, Readiness};
use tokio::task::JoinHandle;

use super::client::Client;

/// Time between two probes of `/v1/agent/self`.
const PROBE_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(super) struct Health {
    client: Arc<Client>,
    interval: Duration,
    up: AtomicBool,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Health {
    pub(super) fn new(client: Arc<Client>) -> Arc<Self> {
        Self::with_interval(client, PROBE_INTERVAL)
    }

    fn with_interval(client: Arc<Client>, interval: Duration) -> Arc<Self> {
        Arc::new(Self {
            // CoreDNS v1.15.0 plugin/nomad/setup.go getClient: a single client is never probed, so it is always ready.
            up: AtomicBool::new(client.endpoints() == 1),
            client,
            interval,
            task: Mutex::new(None),
        })
    }

    /// Probe in the background from Startup until Restart or Shutdown; the hooks never wait for Nomad.
    pub(super) fn register(self: &Arc<Self>, lifecycle: &mut Lifecycle) {
        let health = Arc::clone(self);
        let start = move || {
            health.start();
            std::future::ready(Ok(()))
        };
        lifecycle.register(Phase::Startup, start.clone());
        lifecycle.register(Phase::RestartFailed, start);
        let health = Arc::clone(self);
        let stop = move || {
            health.stop();
            std::future::ready(Ok(()))
        };
        lifecycle.register(Phase::Restart, stop.clone());
        lifecycle.register(Phase::Shutdown, stop);
    }

    fn start(self: &Arc<Self>) {
        if self.client.endpoints() < 2 {
            return;
        }
        let health = Arc::clone(self);
        let task = tokio::spawn(async move {
            loop {
                // CoreDNS v1.15.0 plugin/nomad/ready.go Ready: ready when some client answers `Agent().Self()`.
                health
                    .up
                    .store(health.client.probe().await, Ordering::Relaxed);
                tokio::time::sleep(health.interval).await;
            }
        });
        if let Some(old) = self.task.lock().unwrap().replace(task) {
            old.abort();
        }
    }

    fn stop(&self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
    }
}

impl Readiness for Health {
    fn ready(&self) -> bool {
        self.up.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests;
