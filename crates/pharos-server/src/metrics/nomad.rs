use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use pharos_proto::NameRef;

use super::{SortedSamples, header};

/// Distinct `namespace` label values kept for one `server`; later ones are counted under `OVERFLOW`.
// Deviation from CoreDNS v1.15.0 plugin/nomad/metrics.go: the namespace comes from the Query name, so an unbounded label would exhaust memory.
const MAX_NAMESPACES: usize = 64;
/// A Nomad namespace is `[a-zA-Z0-9-]{1,128}`, so this value never collides with a real one.
const OVERFLOW: &str = "_other";

// CoreDNS v1.15.0 plugin/nomad/metrics.go: both counters are labelled by `server` and `namespace`.
#[derive(Default)]
pub(super) struct NomadRegistry(Mutex<BTreeMap<String, Arc<Server>>>);

#[derive(Default)]
struct Server {
    /// Keyed by the lower-cased namespace label as it appears on the wire.
    namespaces: RwLock<HashMap<Vec<u8>, Counts>>,
    overflow: Counts,
}

#[derive(Default)]
struct Counts {
    success: AtomicU64,
    failed: AtomicU64,
}

/// Request counters of the `nomad` Plugin for one `server` label.
#[derive(Clone)]
pub struct NomadMetrics(Arc<Server>);

impl std::fmt::Debug for NomadMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NomadMetrics").finish_non_exhaustive()
    }
}

impl NomadRegistry {
    pub(super) fn resolve(&self, server: &str) -> NomadMetrics {
        NomadMetrics(Arc::clone(
            self.0.lock().unwrap().entry(server.into()).or_default(),
        ))
    }

    pub(super) fn encode(&self, out: &mut String) {
        let servers = self.0.lock().unwrap();
        for (name, help, failed) in [
            (
                "nomad_success_requests_total",
                "Counter of DNS requests handled successfully.",
                false,
            ),
            (
                "nomad_failed_requests_total",
                "Counter of DNS requests failed.",
                true,
            ),
        ] {
            let mut sorted = SortedSamples::default();
            for (server, series) in servers.iter() {
                let namespaces = series.namespaces.read().unwrap();
                let overflow = (OVERFLOW.to_owned(), &series.overflow);
                let counted = namespaces
                    .iter()
                    .map(|(label, counts)| (presentation(label), counts))
                    .chain(std::iter::once(overflow));
                for (namespace, counts) in counted {
                    let counter = if failed {
                        &counts.failed
                    } else {
                        &counts.success
                    };
                    let n = counter.load(Ordering::Relaxed);
                    if n != 0 {
                        sorted.sample(name, &[("namespace", &namespace), ("server", server)], n);
                    }
                }
            }
            if !sorted.0.is_empty() {
                header(out, name, help, "counter");
                sorted.write(out);
            }
        }
    }
}

// RFC 4343 §2.1: a label is shown in presentation form, without the root dot.
fn presentation(label: &[u8]) -> String {
    let mut wire = Vec::with_capacity(label.len() + 2);
    wire.push(label.len() as u8);
    wire.extend_from_slice(label);
    wire.push(0);
    let mut text = NameRef::parse(&wire, 0)
        .map(|name| name.to_string())
        .unwrap_or_default();
    text.pop();
    text
}

impl NomadMetrics {
    /// Count a Response that carried an answer. `namespace` is one lower-cased label of the Query name.
    // CoreDNS v1.15.0 plugin/nomad/nomad.go ServeDNS: `requestSuccessCount` after the Response is written.
    pub fn success(&self, namespace: &[u8]) {
        self.count(namespace, |counts| &counts.success);
    }

    /// Count a lookup failure, a name without registrations or an unsupported Query.
    // CoreDNS v1.15.0 plugin/nomad/nomad.go handleServiceLookupError and handleResponseError: `requestFailedCount`.
    pub fn failure(&self, namespace: &[u8]) {
        self.count(namespace, |counts| &counts.failed);
    }

    fn count(&self, namespace: &[u8], counter: impl Fn(&Counts) -> &AtomicU64) {
        let series = &*self.0;
        // Prometheus text exposition format: one series per name and label set, so a Query namespace spelled `_other` joins the overflow series.
        if namespace == OVERFLOW.as_bytes() {
            counter(&series.overflow).fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Deviation from CoreDNS v1.15.0 plugin/nomad/metrics.go: at most MAX_NAMESPACES labels per server bound memory; later ones count under OVERFLOW.
        let namespaces = series.namespaces.read().unwrap();
        if let Some(counts) = namespaces.get(namespace) {
            counter(counts).fetch_add(1, Ordering::Relaxed);
        } else if namespaces.len() >= MAX_NAMESPACES {
            counter(&series.overflow).fetch_add(1, Ordering::Relaxed);
        } else {
            drop(namespaces);
            let mut namespaces = series.namespaces.write().unwrap();
            // Another Query may have taken the last slot between the two locks.
            let counts: &Counts =
                if namespaces.len() < MAX_NAMESPACES || namespaces.contains_key(namespace) {
                    namespaces.entry(namespace.to_vec()).or_default()
                } else {
                    &series.overflow
                };
            counter(counts).fetch_add(1, Ordering::Relaxed);
        }
    }
}
