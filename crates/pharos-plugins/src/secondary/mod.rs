//! Authoritative Zones retrieved from Primary Servers.

mod catalog;
pub(crate) mod setup;
#[cfg(test)]
mod tests;
#[cfg(feature = "plugin-transfer")]
mod transfer;
mod update;

use crate::zone::{ZoneHolder, contains};
use pharos_corefile::{Cursor, Error};
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Opcode, Rcode, Type};
use pharos_server::{Context, Next, Outcome, Plugin};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

#[derive(Debug, Clone)]
struct ZoneConfig {
    apex: Name,
    from: Vec<String>,
    catalog: Option<Vec<Name>>,
}

#[derive(Debug)]
struct SecondaryZone {
    config: ZoneConfig,
    current: ZoneHolder,
    expired: AtomicBool,
    notify: tokio::sync::Notify,
    notify_pending: AtomicUsize,
    task: Mutex<Option<tokio::task::AbortHandle>>,
}

impl SecondaryZone {
    fn new(config: ZoneConfig) -> Self {
        Self {
            config,
            current: ZoneHolder::empty(),
            expired: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
            notify_pending: AtomicUsize::new(0),
            task: Mutex::new(None),
        }
    }
}

#[derive(Debug)]
struct Shared {
    zones: arc_swap::ArcSwap<Vec<Arc<SecondaryZone>>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    running: AtomicBool,
    catalogs: Mutex<catalog::State>,
    #[cfg(feature = "plugin-transfer")]
    notifier: crate::zone::ZoneNotifier,
}

/// Retrieves and serves secondary Zones.
#[derive(Debug)]
pub struct Secondary {
    shared: Arc<Shared>,
    fallthrough: Vec<Name>,
}

impl Secondary {
    fn parse(cursor: &mut Cursor<'_>, domains: &[&str]) -> Result<Self, Error> {
        let (zones, fallthrough) = setup::parse(cursor, domains)?;
        Ok(Self {
            shared: Arc::new(Shared {
                zones: arc_swap::ArcSwap::from_pointee(
                    zones
                        .into_iter()
                        .map(|zone| Arc::new(SecondaryZone::new(zone)))
                        .collect(),
                ),
                tasks: Mutex::new(Vec::new()),
                running: AtomicBool::new(false),
                catalogs: Mutex::new(catalog::State::default()),
                #[cfg(feature = "plugin-transfer")]
                notifier: crate::zone::ZoneNotifier::default(),
            }),
            fallthrough,
        })
    }

    fn register_hooks(&self, lifecycle: &mut pharos_server::Lifecycle) {
        let shared = Arc::clone(&self.shared);
        let start = move || {
            let shared = Arc::clone(&shared);
            async move {
                let mut tasks = shared.tasks.lock().unwrap();
                shared.running.store(true, Ordering::Relaxed);
                for task in tasks.drain(..) {
                    task.abort();
                }
                for zone in shared.zones.load().iter() {
                    let task = tokio::spawn(update::run(Arc::clone(&shared), Arc::clone(zone)));
                    *zone.task.lock().unwrap() = Some(task.abort_handle());
                    tasks.push(task);
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Startup, start.clone());
        lifecycle.register(pharos_server::Phase::RestartFailed, start);
        let shared = Arc::clone(&self.shared);
        let stop = move || {
            let mut locked = shared.tasks.lock().unwrap();
            shared.running.store(false, Ordering::Relaxed);
            let tasks = std::mem::take(&mut *locked);
            drop(locked);
            async move {
                for task in tasks {
                    task.abort();
                    let _ = task.await;
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
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        let mut wire = [0u8; 255];
        let mut len = 0;
        for label in question.name.labels() {
            wire[len] = label.len() as u8;
            len += 1;
            wire[len..len + label.len()].copy_from_slice(label);
            len += label.len();
        }
        let name = &wire[..len + 1];
        let zone = self
            .shared
            .zones
            .load()
            .iter()
            .filter(|zone| contains(name, &zone.config.apex))
            .max_by_key(|zone| zone.config.apex.label_count())
            .cloned();
        let Some(zone) = zone else {
            return if has_next {
                next.run(cx).await
            } else {
                Outcome::Unanswered(Rcode::REFUSED)
            };
        };
        if matches!(question.qtype, Type::AXFR | Type::IXFR) {
            return Outcome::Unanswered(Rcode::REFUSED);
        }
        if cx.query.opcode() == Opcode::NOTIFY {
            // RFC 1996 §3.10: ignore NOTIFY from unconfigured Primary Servers.
            if !zone
                .config
                .from
                .iter()
                .any(|address| update::primary_matches(address, cx.client))
            {
                return Outcome::Drop;
            }
            let max = cx.max_response_size.max(512);
            if cx.response.capacity() < max {
                if cx.protocol == pharos_server::Protocol::Tcp {
                    cx.response.reserve(max.saturating_sub(cx.response.len()));
                } else {
                    return Outcome::Error(pharos_server::Error::ResponseBufferTooSmall);
                }
            }
            let result = (|| {
                let mut builder = MessageBuilder::new(
                    cx.response,
                    max,
                    cx.query.id(),
                    0x8400 | (cx.query.flags() & 0x7910),
                )?;
                builder.question(question.name, question.qtype, question.qclass)?;
                let _ = builder.finish();
                Ok::<(), pharos_proto::BuildError>(())
            })();
            zone.notify_pending.fetch_add(1, Ordering::Relaxed);
            zone.notify.notify_one();
            return result.map_or_else(
                |error| Outcome::Error(pharos_server::Error::Build(error)),
                |()| Outcome::Response,
            );
        }
        if zone.expired.load(Ordering::Relaxed) {
            return Outcome::Unanswered(Rcode::SERVFAIL);
        }
        let Some(snapshot) = zone.current.load_full() else {
            return Outcome::Unanswered(Rcode::SERVFAIL);
        };
        snapshot.lookup(cx, next, &self.fallthrough).await
    }
}

impl Plugin for Secondary {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        self.serve_with(cx, next, true).await
    }
}
