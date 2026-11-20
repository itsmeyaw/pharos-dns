//! The tasks that obtain certificates when none is stored and renew them as they near their end.

use std::{
    io,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant, SystemTime},
};

use pharos_server::{Lifecycle, Phase, logging::log, tls::client_config_with_roots};
use tokio::{task::JoinHandle, time::sleep};

use super::{
    Entry, Runtime,
    client::Client,
    der::Validity,
    http::Http,
    jws::AccountKey,
    resolver,
    store::{Store, renewal_time},
};

// certmagic v0.25 DefaultRetryIntervals: 1m, 2m, 5m, 10m, 20m, 40m, 1h, 2h, 3h, 6h between failed attempts.
const RETRY: [u64; 10] = [60, 120, 300, 600, 1200, 2400, 3600, 7200, 10800, 21600];
// certmagic v0.25 DefaultRenewCheckInterval: certificates are checked every 10 minutes.
const CHECK: Duration = Duration::from_secs(600);

/// How long until a certificate valid over `validity` needs a new one; `None` means now.
pub(crate) fn due_in(validity: Option<&Validity>, now: SystemTime) -> Option<Duration> {
    let validity = validity?;
    if now >= validity.not_after {
        return None;
    }
    renewal_time(validity)
        .duration_since(now)
        .ok()
        .filter(|wait| !wait.is_zero())
}

impl Runtime {
    /// Load stored certificates at Startup, obtain and renew them once Listeners answer, stop on Restart and Shutdown.
    pub(crate) fn register(self: &Arc<Self>, lifecycle: &mut Lifecycle) {
        let tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let runtime = Arc::clone(self);
        lifecycle.register_sync(Phase::Startup, move || {
            for entry in &runtime.entries {
                load_stored(entry);
            }
            Ok(())
        });
        let start = {
            let (runtime, tasks) = (Arc::clone(self), Arc::clone(&tasks));
            move || -> io::Result<()> {
                let mut tasks = tasks.lock().unwrap_or_else(PoisonError::into_inner);
                // The challenge answers come from the Listeners, so issuance only starts once they are up.
                tasks.extend(runtime.entries.iter().map(|entry| {
                    tokio::spawn(maintain(Arc::clone(entry), Arc::clone(&runtime.solver)))
                }));
                Ok(())
            }
        };
        lifecycle.register_sync(Phase::Started, start.clone());
        lifecycle.register_sync(Phase::RestartFailed, start);
        let stop = move || -> io::Result<()> {
            for task in tasks
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .drain(..)
            {
                task.abort();
            }
            Ok(())
        };
        lifecycle.register_sync(Phase::Restart, stop.clone());
        lifecycle.register_sync(Phase::Shutdown, stop);
    }
}

// Serve a stored certificate immediately so the first handshakes after a restart do not wait for the CA.
pub(super) fn load_stored(entry: &Entry) {
    let store = Store::new(&entry.options);
    for name in &entry.options.domains {
        let Some((certificate, key, validity)) = store.certificate(name) else {
            continue;
        };
        // RFC 5280 §4.1.2.5: an expired certificate is not served; the maintenance task replaces it.
        if SystemTime::now() >= validity.not_after {
            continue;
        }
        if let Err(error) = entry.slot.load(name, &certificate, &key) {
            log(
                "WARNING",
                "tls",
                &format!("ACME: stored certificate for {name} is unusable: {error}"),
            );
        }
    }
}

async fn maintain(entry: Arc<Entry>, solver: Arc<super::Solver>) {
    let store = Store::new(&entry.options);
    // Per name: the failed attempts so far and the earliest next attempt.
    let mut retries: Vec<(u32, Option<Instant>)> = vec![(0, None); entry.options.domains.len()];
    loop {
        let mut wake = CHECK;
        for (name, (failures, not_before)) in entry.options.domains.iter().zip(&mut retries) {
            let validity = store.certificate(name).map(|(_, _, validity)| validity);
            if let Some(wait) = due_in(validity.as_ref(), SystemTime::now()) {
                wake = wake.min(wait);
                continue;
            }
            if let Some(at) = *not_before
                && let Some(wait) = at.checked_duration_since(Instant::now())
            {
                wake = wake.min(wait);
                continue;
            }
            match obtain(&entry, &solver, &store, name).await {
                Ok(()) => (*failures, *not_before) = (0, None),
                Err(error) => {
                    let wait =
                        Duration::from_secs(RETRY[(*failures as usize).min(RETRY.len() - 1)]);
                    log(
                        "ERROR",
                        "tls",
                        &format!(
                            "ACME: obtaining a certificate for {name} failed, retrying in {wait:?}: {error}"
                        ),
                    );
                    *failures += 1;
                    *not_before = Some(Instant::now() + wait);
                    wake = wake.min(wait);
                }
            }
        }
        sleep(wake.max(Duration::from_secs(1))).await;
    }
}

pub(super) async fn obtain(
    entry: &Entry,
    solver: &super::Solver,
    store: &Store,
    name: &str,
) -> io::Result<()> {
    let options = &entry.options;
    let http = Http::new(client_config_with_roots(options.ca_root.as_deref())?);
    let key = match store.account(options.email.as_deref()) {
        Some(pkcs8) => AccountKey::from_pkcs8(&pkcs8).map_err(io::Error::other)?,
        None => {
            let (key, pkcs8) = AccountKey::generate()
                .map_err(|_| io::Error::other("generating an account key failed"))?;
            store.save_account(options.email.as_deref(), &pkcs8)?;
            key
        }
    };
    let mut client = Client::connect(&http, &options.ca, &key, options.email.as_deref()).await?;
    let resolver = options.resolver.clone();
    let issued = client
        .obtain(name, solver, move |record, value| {
            let resolver = resolver.clone();
            async move {
                match resolver {
                    Some(resolver) => resolver::wait(&resolver, &record, &value).await,
                    None => Ok(()),
                }
            }
        })
        .await?;
    let (certificate, private_key) = store.save_certificate(name, &issued.chain, &issued.key)?;
    entry.slot.load(name, &certificate, &private_key)?;
    log(
        "INFO",
        "tls",
        &format!("ACME: obtained a certificate for {name}"),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::due_in;
    use crate::tls::acme::der::Validity;

    // certmagic v0.25 DefaultRenewalWindowRatio: renewal starts with a third of the lifetime left.
    #[test]
    fn certificates_are_due_when_missing_expired_or_inside_the_renewal_window() {
        let at = |days: u64| UNIX_EPOCH + Duration::from_secs(days * 86_400);
        let validity = Validity {
            not_before: at(0),
            not_after: at(90),
        };
        assert_eq!(due_in(None, at(1)), None);
        assert_eq!(
            due_in(Some(&validity), at(30)),
            Some(Duration::from_secs(30 * 86_400))
        );
        assert_eq!(due_in(Some(&validity), at(60)), None);
        assert_eq!(due_in(Some(&validity), at(80)), None);
        assert_eq!(due_in(Some(&validity), at(100)), None);
    }
}
