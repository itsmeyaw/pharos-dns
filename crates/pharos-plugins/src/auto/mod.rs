//! Automatically discovered authoritative Zones.

pub(crate) mod setup;
#[cfg(test)]
mod tests;
#[cfg(feature = "plugin-transfer")]
mod transfer;
mod walk;

use crate::zone::{Zone, ZoneHolder, contains};
use pharos_proto::{Name, Rcode};
use pharos_server::{Context, Next, Outcome, Plugin};
use std::{
    collections::HashMap,
    fmt::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Debug)]
struct Entry {
    origin: String,
    apex: Name,
    path: Mutex<PathBuf>,
    current: ZoneHolder,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Debug)]
struct Shared {
    directory: PathBuf,
    regex: regex::Regex,
    template: String,
    zones: arc_swap::ArcSwap<Zones>,
    scan_gate: Mutex<()>,
    #[cfg(feature = "plugin-prometheus")]
    metrics: pharos_server::metrics::DynamicZones,
    shutdown: tokio::sync::watch::Sender<bool>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    #[cfg(feature = "plugin-transfer")]
    notifier: crate::zone::ZoneNotifier,
}

#[derive(Debug, Default)]
struct Zones {
    origins: HashMap<String, Arc<Entry>>,
    canonical: HashMap<String, Arc<Entry>>,
}

/// Directory-backed authoritative Zones.
#[derive(Debug)]
pub struct Auto {
    origins: Vec<Name>,
    interval: Duration,
    shared: Arc<Shared>,
}

impl Auto {
    #[cfg(feature = "plugin-prometheus")]
    pub(crate) fn metric_zones(&self) -> &pharos_server::metrics::DynamicZones {
        &self.shared.metrics
    }

    fn new(
        origins: Vec<Name>,
        directory: PathBuf,
        regex: regex::Regex,
        template: String,
        interval: Duration,
    ) -> Self {
        Self {
            origins,
            interval,
            shared: Arc::new(Shared {
                directory,
                regex,
                template,
                zones: arc_swap::ArcSwap::from_pointee(Zones::default()),
                scan_gate: Mutex::new(()),
                #[cfg(feature = "plugin-prometheus")]
                metrics: pharos_server::metrics::DynamicZones::default(),
                shutdown: tokio::sync::watch::channel(false).0,
                tasks: Mutex::new(Vec::new()),
                #[cfg(feature = "plugin-transfer")]
                notifier: crate::zone::ZoneNotifier::default(),
            }),
        }
    }

    fn register_hooks(&self, lifecycle: &mut pharos_server::Lifecycle) {
        let shared = Arc::clone(&self.shared);
        let interval = self.interval;
        let start = move || {
            let shared = Arc::clone(&shared);
            async move {
                shared.shutdown.send_replace(false);
                let worker = Arc::clone(&shared);
                tokio::task::spawn_blocking(move || worker.scan())
                    .await
                    .map_err(std::io::Error::other)?;
                shared.start_watchers(interval);
                #[cfg(feature = "plugin-transfer")]
                notify_all(&shared).await;
                if !interval.is_zero() {
                    let scan = Arc::clone(&shared);
                    let mut shutdown = shared.shutdown.subscribe();
                    let scan_task = tokio::spawn(async move {
                        loop {
                            if *shutdown.borrow() {
                                break;
                            }
                            tokio::select! {
                                _ = tokio::time::sleep(interval) => {},
                                _ = shutdown.changed() => break,
                            }
                            let worker = Arc::clone(&scan);
                            let _ = tokio::task::spawn_blocking(move || worker.scan()).await;
                            if *shutdown.borrow() {
                                break;
                            }
                            scan.start_watchers(interval);
                            #[cfg(feature = "plugin-transfer")]
                            notify_all(&scan).await;
                        }
                    });
                    shared.tasks.lock().unwrap().push(scan_task);
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Startup, start.clone());
        lifecycle.register(pharos_server::Phase::RestartFailed, start);
        let shared = Arc::clone(&self.shared);
        let stop = move || {
            shared.shutdown.send_replace(true);
            let tasks = std::mem::take(&mut *shared.tasks.lock().unwrap());
            let shared = Arc::clone(&shared);
            async move {
                for task in tasks {
                    let _ = task.await;
                }
                let zones = shared.zones.load_full();
                for entry in zones.origins.values() {
                    let task = entry.task.lock().unwrap().take();
                    if let Some(task) = task {
                        let _ = task.await;
                    }
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Restart, stop.clone());
        lifecycle.register(pharos_server::Phase::Shutdown, stop);
    }

    pub(crate) async fn serve_with<N: Next + Send>(
        &self,
        cx: &mut Context<'_, '_>,
        next: N,
        has_next: bool,
    ) -> Outcome {
        match self.select(cx, has_next) {
            Selection::Next => next.run(cx).await,
            Selection::Refused => Outcome::Unanswered(Rcode::REFUSED),
            Selection::Zone(entry) => match entry.current.load_full() {
                Some(zone) => {
                    let case_mismatch = entry.origin.bytes().any(|byte| byte.is_ascii_uppercase());
                    zone.lookup_auto(cx, next, case_mismatch).await
                }
                None => Outcome::Unanswered(Rcode::SERVFAIL),
            },
        }
    }

    fn select(&self, cx: &Context<'_, '_>, has_next: bool) -> Selection {
        let Some(question) = cx.query.questions().next() else {
            return Selection::Next;
        };
        let mut wire = [0u8; 255];
        let mut len = 0;
        for label in question.name.labels() {
            wire[len] = label.len() as u8;
            len += 1;
            wire[len..len + label.len()].copy_from_slice(label);
            wire[len..len + label.len()].make_ascii_lowercase();
            len += label.len();
        }
        let name = &wire[..len + 1];
        if !self.origins.iter().any(|origin| contains(name, origin)) {
            return Selection::Next;
        }
        let Some(entry) = self.shared.find(name) else {
            return if has_next {
                Selection::Next
            } else {
                Selection::Refused
            };
        };
        Selection::Zone(entry)
    }
}

enum Selection {
    Next,
    Refused,
    Zone(Arc<Entry>),
}

struct NameText {
    bytes: [u8; 1024],
    len: usize,
}

impl std::fmt::Write for NameText {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(std::fmt::Error)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or(std::fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

impl Shared {
    fn find(&self, mut name: &[u8]) -> Option<Arc<Entry>> {
        let zones = self.zones.load();
        // RFC 1034 §4.3.2: choose the closest enclosing authoritative Zone.
        loop {
            let mut text = NameText {
                bytes: [0; 1024],
                len: 0,
            };
            let suffix = pharos_proto::NameRef::parse(name, 0).ok()?;
            write!(&mut text, "{suffix}").ok()?;
            let key = std::str::from_utf8(&text.bytes[..text.len]).ok()?;
            if let Some(entry) = zones.canonical.get(key) {
                return Some(Arc::clone(entry));
            }
            if name[0] == 0 {
                return None;
            }
            name = &name[usize::from(name[0]) + 1..];
        }
    }

    fn start_watchers(self: &Arc<Self>, interval: Duration) {
        if interval.is_zero() {
            return;
        }
        for entry in self.zones.load().origins.values() {
            let mut task = entry.task.lock().unwrap();
            if task.is_some() {
                continue;
            }
            let entry = Arc::clone(entry);
            let mut shutdown = self.shutdown.subscribe();
            #[cfg(feature = "plugin-transfer")]
            let notifier = self.notifier.clone();
            *task = Some(tokio::spawn(async move {
                loop {
                    if *shutdown.borrow() {
                        break;
                    }
                    tokio::select! {
                        _ = tokio::time::sleep(interval) => {},
                        _ = shutdown.changed() => break,
                    }
                    let worker = Arc::clone(&entry);
                    let changed = tokio::task::spawn_blocking(move || worker.reload())
                        .await
                        .unwrap_or(false);
                    if *shutdown.borrow() {
                        break;
                    }
                    #[cfg(feature = "plugin-transfer")]
                    if changed && let Some(transfer) = notifier.get() {
                        // RFC 1996 §3.1: notify Secondary Servers after Zone changes.
                        if let Err(error) = transfer.notify(&entry.apex).await {
                            pharos_server::logging::log(
                                "WARN",
                                "auto",
                                &format!("NOTIFY {}: {error}", entry.apex),
                            );
                        }
                    }
                    #[cfg(not(feature = "plugin-transfer"))]
                    let _ = changed;
                }
            }));
        }
    }
}

impl Plugin for Auto {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        self.serve_with(cx, next, true).await
    }
}

#[cfg(feature = "plugin-transfer")]
async fn notify_all(shared: &Shared) {
    if let Some(transfer) = shared.notifier.get() {
        let zones = shared.zones.load_full();
        for zone in zones.origins.values() {
            // RFC 1996 §4.1: notify Secondary Servers when a Zone is loaded.
            if let Err(error) = transfer.notify(&zone.apex).await {
                pharos_server::logging::log(
                    "WARN",
                    "auto",
                    &format!("NOTIFY {}: {error}", zone.apex),
                );
            }
        }
    }
}
