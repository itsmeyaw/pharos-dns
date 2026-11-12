//! Offline signing of authoritative Zone files.

pub(crate) mod setup;
mod signer;
mod output;

use std::{path::PathBuf, sync::{Arc, Mutex}, time::{Duration, SystemTime, UNIX_EPOCH}};
use pharos_dnssec::keys::KeyPair;
use pharos_proto::Name;

#[derive(Debug)]
struct Signer {
    apex: Name,
    source: PathBuf,
    directory: PathBuf,
    keys: Arc<Vec<KeyPair>>,
    inception_jitter: u32,
    expiration_jitter: u32,
}

#[derive(Debug, Default)]
pub struct Sign;

impl Signer {
    fn refresh(&self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |time| time.as_secs()) as u32;
        let target = self.directory.join(format!("db.{}signed", self.apex));
        if !output::needs_resign(&target, now) { return; }
        let result = signer::sign(&self.apex, &self.source, &self.keys, now, self.inception_jitter, self.expiration_jitter)
            .and_then(|records| output::write(&self.directory, &target, &records));
        if let Err(error) = result {
            pharos_server::logging::log("WARN", "sign", &format!("Error signing {}: {error}", self.apex));
        }
    }
}

fn register_hooks(lifecycle: &mut pharos_server::Lifecycle, signers: Vec<Signer>) {
    let signers: Vec<_> = signers.into_iter().map(Arc::new).collect();
    let tasks = Arc::new(Mutex::new(Vec::<tokio::task::JoinHandle<()>>::new()));
    let start_tasks = Arc::clone(&tasks);
    let start = move || {
        let signers = signers.clone();
        let tasks = Arc::clone(&start_tasks);
        async move {
            let mut tasks = tasks.lock().unwrap();
            for task in tasks.drain(..) { task.abort(); }
            for signer in signers {
                tasks.push(tokio::spawn(async move {
                    loop {
                        let current = Arc::clone(&signer);
                        let _ = tokio::task::spawn_blocking(move || current.refresh()).await;
                        tokio::time::sleep(Duration::from_secs(5 * 3600)).await;
                    }
                }));
            }
            Ok(())
        }
    };
    lifecycle.register(pharos_server::Phase::Startup, start.clone());
    lifecycle.register(pharos_server::Phase::RestartFailed, start);
    let stop = move || {
        let tasks = std::mem::take(&mut *tasks.lock().unwrap());
        async move { for task in tasks { task.abort(); let _ = task.await; } Ok(()) }
    };
    lifecycle.register(pharos_server::Phase::Restart, stop.clone());
    lifecycle.register(pharos_server::Phase::Shutdown, stop);
}
