//! Offline signing of authoritative Zone files.

#[cfg(all(test, feature = "plugin-file"))]
mod interop;
mod output;
pub(crate) mod setup;
mod signer;

use pharos_dnssec::keys::KeyPair;
use pharos_proto::Name;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
struct Signer {
    apex: Name,
    key_owner: Name,
    source: PathBuf,
    directory: PathBuf,
    keys: Arc<Vec<KeyPair>>,
    inception_jitter: u32,
    expiration_jitter: u32,
}

#[derive(Debug, Default)]
pub struct Sign;

struct Running {
    stop: tokio::sync::watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    async fn stop(self) {
        let _ = self.stop.send(true);
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

impl Signer {
    fn refresh(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |time| time.as_secs()) as u32;
        let target = self.directory.join(format!("db.{}signed", self.apex));
        if !output::needs_resign(&target, now) {
            return;
        }
        let result = signer::sign_with_owner(
            &self.apex,
            &self.key_owner,
            &self.source,
            &self.keys,
            now,
            self.inception_jitter,
            self.expiration_jitter,
        )
        .and_then(|records| output::write(&self.directory, &target, &records));
        if let Err(error) = result {
            pharos_server::logging::log(
                "WARN",
                "sign",
                &format!("Error signing {}: {error}", self.apex),
            );
        }
    }
}

fn register_hooks(lifecycle: &mut pharos_server::Lifecycle, signers: Vec<Signer>) {
    let signers: Vec<_> = signers.into_iter().map(Arc::new).collect();
    let tasks = Arc::new(Mutex::new(None::<Running>));
    let start_tasks = Arc::clone(&tasks);
    let start = move || {
        let signers = signers.clone();
        let tasks = Arc::clone(&start_tasks);
        async move {
            let old = tasks.lock().unwrap().take();
            if let Some(old) = old {
                old.stop().await;
            }
            let (stop, receiver) = tokio::sync::watch::channel(false);
            let mut handles = Vec::new();
            for signer in signers {
                let mut receiver = receiver.clone();
                handles.push(tokio::spawn(async move {
                    let period = Duration::from_secs(5 * 3600);
                    let mut timer =
                        tokio::time::interval_at(tokio::time::Instant::now() + period, period);
                    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        if *receiver.borrow() {
                            break;
                        }
                        let current = Arc::clone(&signer);
                        let _ = tokio::task::spawn_blocking(move || current.refresh()).await;
                        tokio::select! {
                            _ = timer.tick() => {},
                            _ = receiver.changed() => break,
                        }
                    }
                }));
            }
            *tasks.lock().unwrap() = Some(Running {
                stop,
                tasks: handles,
            });
            Ok(())
        }
    };
    lifecycle.register(pharos_server::Phase::Startup, start.clone());
    lifecycle.register(pharos_server::Phase::RestartFailed, start);
    let stop = move || {
        let tasks = tasks.lock().unwrap().take();
        async move {
            if let Some(tasks) = tasks {
                tasks.stop().await;
            }
            Ok(())
        }
    };
    lifecycle.register(pharos_server::Phase::Restart, stop.clone());
    lifecycle.register(pharos_server::Phase::Shutdown, stop);
}
