//! Serve Zones mirrored from Azure DNS and Azure Private DNS hosted zones.

mod config;
pub(crate) mod setup;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use pharos_proto::{Name, Rcode};
use pharos_server::{Context, Next, Outcome, Plugin};

pub use config::{Config, Environment, Secret, ZoneSpec};

use crate::zone::{Zone, ZoneHolder, contains};

/// One Azure hosted zone and the Zone last loaded from it; empty until the first successful sync.
#[derive(Debug)]
pub struct HostedZone {
    pub spec: ZoneSpec,
    /// `spec.zone` as an absolute name.
    pub apex: Name,
    /// The Query path only loads this; the refresh swaps in a fully built Zone.
    pub current: ZoneHolder,
}

impl HostedZone {
    /// RFC 1035 §6.1.2: publish a fully built Zone as one generation.
    pub fn publish(&self, zone: Zone) {
        self.current.store(Some(Arc::new(zone)));
    }
}

/// The `azure` Plugin: every configured hosted zone of one Server Block.
#[derive(Debug)]
pub struct Azure {
    config: Config,
    /// Configured zone names, sorted and without duplicates.
    names: Vec<Name>,
    /// Hosted zones in Corefile order; several may share one zone name.
    zones: Vec<Arc<HostedZone>>,
    fallthrough: Vec<Name>,
}

impl Azure {
    /// CoreDNS v1.15.0 plugin/azure/azure.go New: configure every Zone without contacting Azure.
    pub fn new(config: Config) -> Result<Self, String> {
        let root: Name = ".".parse().map_err(|_| "invalid root name".to_owned())?;
        let mut names = Vec::with_capacity(config.zones.len());
        let mut zones = Vec::with_capacity(config.zones.len());
        for spec in &config.zones {
            // CoreDNS v1.15.0 plugin/azure/azure.go New: the zone name is made fully qualified.
            let apex = Name::parse(&spec.zone, &root)
                .map_err(|error| format!("invalid zone {:?}: {error}", spec.zone))?;
            names.push(apex.clone());
            zones.push(Arc::new(HostedZone {
                spec: spec.clone(),
                apex,
                current: ZoneHolder::empty(),
            }));
        }
        names.sort();
        names.dedup();
        let mut fallthrough: Vec<Name> = Vec::with_capacity(config.fallthrough.domains.len());
        for domain in &config.fallthrough.domains {
            fallthrough.push(
                domain
                    .parse()
                    .map_err(|_| format!("invalid fallthrough zone {domain:?}"))?,
            );
        }
        Ok(Self {
            config,
            names,
            zones,
            fallthrough,
        })
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Hosted zones in Corefile order.
    pub fn hosted_zones(&self) -> &[Arc<HostedZone>] {
        &self.zones
    }

    /// Configured zone names, sorted and without duplicates.
    pub fn zone_names(&self) -> &[Name] {
        &self.names
    }

    /// Registers the background sync; the Zones stay unloaded, and Queries get SERVFAIL, until it runs.
    pub(crate) fn register_hooks(&self, _lifecycle: &mut pharos_server::Lifecycle) {}

    /// The hosted zone of `apex` that answers `name`.
    fn select(&self, apex: &Name, name: &[u8]) -> Option<&Arc<HostedZone>> {
        let mut last_loaded = None;
        for hosted in self.zones.iter().filter(|hosted| hosted.apex == *apex) {
            // RFC 8020 §3.1: the first loaded copy that holds the name answers, as CoreDNS stops at the first answer or NODATA.
            if let Some(zone) = hosted.current.load().as_ref() {
                if zone.exists(name) {
                    return Some(hosted);
                }
                last_loaded = Some(hosted);
            }
        }
        // CoreDNS v1.15.0 plugin/azure/azure.go ServeDNS: when no copy holds the name the last lookup's NXDOMAIN stands.
        last_loaded
    }
}

impl Plugin for Azure {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        // RFC 1035 §3.1: expand the QNAME to uncompressed wire form on the stack.
        let mut wire = [0u8; 255];
        let mut len = 0;
        for label in question.name.labels() {
            wire[len] = label.len() as u8;
            len += 1;
            wire[len..len + label.len()].copy_from_slice(label);
            len += label.len();
        }
        let name = &wire[..len + 1];
        // CoreDNS v1.15.0 plugin/azure/azure.go ServeDNS: the longest matching configured zone name serves; none passes the Query on.
        let Some(apex) = self
            .names
            .iter()
            .filter(|apex| contains(name, apex))
            .max_by_key(|apex| apex.as_wire().len())
        else {
            return next.run(cx).await;
        };
        let snapshot = self.select(apex, name).map(|hosted| hosted.current.load());
        match snapshot.as_ref().and_then(|snapshot| snapshot.as_ref()) {
            Some(zone) => zone.lookup(cx, next, &self.fallthrough).await,
            // CoreDNS v1.15.0 plugin/azure/azure.go ServeDNS: a Zone without records has no answer, so Fallthrough applies, else SERVFAIL.
            None if self.fallthrough.iter().any(|zone| contains(name, zone)) => next.run(cx).await,
            None => Outcome::Unanswered(Rcode::SERVFAIL),
        }
    }
}
