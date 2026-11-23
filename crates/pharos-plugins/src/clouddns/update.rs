//! Startup checks, the refresh loop and Lifecycle hooks of the Plugin.

use std::{io, sync::Arc, time::Duration};

use pharos_server::{Lifecycle, Phase, logging::log};
use tokio::{task::JoinSet, time::timeout};

use super::{
    CloudDns, DnsName, Hosted, Instance, Shared,
    api::Api,
    auth::{Environment, TokenSource},
    http::Http,
    records,
};

// A whole hosted-zone listing, every page, is bounded so one stuck zone cannot hold the refresh forever.
const LISTING_LIMIT: Duration = Duration::from_secs(60);

impl Instance {
    pub(super) fn api(&self) -> Option<Api> {
        self.api.lock().unwrap().clone()
    }

    // CoreDNS v1.15.0 plugin/clouddns/setup.go: the client is built from `credentials`, else from ADC.
    fn connect(&self) -> Result<Api, String> {
        let http = Http::default();
        let tokens = match &self.credentials {
            Some(path) => TokenSource::from_file(path, http.clone()),
            // Google ADC: discovery runs at Startup, not at Corefile parse time.
            None => TokenSource::discover(&Environment::from_process(), http.clone()),
        }
        .map_err(|error| format!("failed to create client: {error}"))?;
        Ok(Api::new(&self.endpoint, tokens, http))
    }

    // CoreDNS v1.15.0 plugin/clouddns/clouddns.go New and Run: every hosted zone must exist, then the first load
    // is synchronous and fatal.
    async fn prepare(self: &Arc<Self>) -> Result<(), String> {
        let api = self.connect()?;
        for name in &self.names {
            for hosted in &name.hosted {
                match api.zone_exists(&hosted.project, &hosted.zone).await {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(format!(
                            "failed to create plugin: managed zone {} not found in project {}",
                            hosted.zone, hosted.project
                        ));
                    }
                    Err(error) => return Err(format!("failed to create plugin: {error}")),
                }
            }
        }
        *self.api.lock().unwrap() = Some(api.clone());
        self.update(&api)
            .await
            .map_err(|error| format!("failed to initialize plugin: {error}"))
    }

    // CoreDNS v1.15.0 plugin/clouddns/clouddns.go updateZones: DNS names update concurrently, and an error in one
    // does not stop the others.
    pub(super) async fn update(self: &Arc<Self>, api: &Api) -> Result<(), String> {
        let mut updates = JoinSet::new();
        for index in 0..self.names.len() {
            let (instance, api) = (Arc::clone(self), api.clone());
            updates.spawn(async move { instance.update_name(&api, index).await });
        }
        let mut errors = Vec::new();
        while let Some(joined) = updates.join_next().await {
            match joined {
                Ok(failed) => errors.extend(failed),
                Err(error) => errors.push(format!("update task failed: {error}")),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!("errors updating zones: {errors:?}"))
        }
    }

    // The hosted zones of one name update in order. One that fails keeps its last good Zone (CoreDNS stops at the
    // first failure; the later hosted zones still refresh here so one broken zone cannot starve them).
    async fn update_name(&self, api: &Api, index: usize) -> Vec<String> {
        let name = &self.names[index];
        let mut errors = Vec::new();
        for hosted in &name.hosted {
            if let Err(error) = refresh(api, name, hosted).await {
                errors.push(format!(
                    "failed to list resource records for {}:{}:{} from gcp: {error}",
                    name.apex, hosted.project, hosted.zone
                ));
            }
        }
        errors
    }

    fn describe(&self) -> String {
        let names: Vec<String> = self
            .names
            .iter()
            .map(|name| name.apex.to_string())
            .collect();
        format!("[{}]", names.join(" "))
    }
}

async fn refresh(api: &Api, name: &DnsName, hosted: &Hosted) -> Result<(), String> {
    let rrsets = timeout(
        LISTING_LIMIT,
        api.list_rrsets(&hosted.project, &hosted.zone),
    )
    .await
    .map_err(|_| "listing timed out".to_owned())?
    .map_err(|error| error.to_string())?;
    // Building a large Zone is CPU work: keep it off the runtime threads that serve Queries.
    let apex = name.apex.clone();
    let label = format!("{}:{}", hosted.project, hosted.zone);
    let zone = tokio::task::spawn_blocking(move || records::build(&apex, &label, &rrsets))
        .await
        .map_err(|error| error.to_string())??;
    // RFC 1035 §6.1.2: a fully built Zone replaces the previous one in one atomic step.
    hosted.current.store(Some(Arc::new(zone)));
    Ok(())
}

impl Shared {
    fn spawn_loops(&self) {
        let mut tasks = self.tasks.lock().unwrap();
        for task in tasks.drain(..) {
            task.abort();
        }
        for instance in &self.instances {
            let Some(api) = instance.api() else { continue };
            let instance = Arc::clone(instance);
            tasks.push(tokio::spawn(async move {
                loop {
                    // CoreDNS v1.15.0 plugin/clouddns/clouddns.go Run: the timer restarts after each update.
                    tokio::time::sleep(instance.refresh).await;
                    if let Err(error) = instance.update(&api).await {
                        log(
                            "ERROR",
                            "clouddns",
                            &format!("Failed to update zones {}: {error}", instance.describe()),
                        );
                    }
                }
            }));
        }
    }

    pub(super) async fn start(&self) -> io::Result<()> {
        // CoreDNS v1.15.0 plugin/clouddns/setup.go: a failed check or first load stops the server.
        for instance in &self.instances {
            instance
                .prepare()
                .await
                .map_err(|error| io::Error::other(format!("clouddns: {error}")))?;
        }
        self.spawn_loops();
        Ok(())
    }

    pub(super) async fn stop(&self) {
        let tasks = std::mem::take(&mut *self.tasks.lock().unwrap());
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
    }
}

impl CloudDns {
    pub(super) fn register_hooks(&self, lifecycle: &mut Lifecycle) {
        let shared = Arc::clone(&self.shared);
        lifecycle.register(Phase::Startup, move || {
            let shared = Arc::clone(&shared);
            async move { shared.start().await }
        });
        // A failed Restart leaves the loaded Zones in place: only the refresh loops come back, as `file` does.
        let shared = Arc::clone(&self.shared);
        lifecycle.register_sync(Phase::RestartFailed, move || {
            shared.spawn_loops();
            Ok(())
        });
        let stop = |shared: Arc<Shared>| {
            move || {
                let shared = Arc::clone(&shared);
                async move {
                    shared.stop().await;
                    Ok(())
                }
            }
        };
        lifecycle.register(Phase::Restart, stop(Arc::clone(&self.shared)));
        lifecycle.register(Phase::Shutdown, stop(Arc::clone(&self.shared)));
    }
}
