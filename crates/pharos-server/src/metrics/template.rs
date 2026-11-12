use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use super::{header, sample};

type Key = (String, String, String, String, String);
type FailureKey = (String, String);

#[derive(Default)]
pub(super) struct TemplateRegistry(Mutex<BTreeMap<Key, Arc<Series>>>);

#[derive(Default)]
struct Series {
    matches: AtomicU64,
    failures: Mutex<BTreeMap<FailureKey, Arc<Failures>>>,
}

#[derive(Default)]
struct Failures {
    render: AtomicU64,
    rr: AtomicU64,
}

/// Template match counter with labels resolved before processing Queries.
#[derive(Clone)]
pub struct TemplateMetrics(Arc<Series>);

/// Template failure counters with labels resolved before processing Queries.
#[derive(Clone)]
pub struct TemplateFailureMetrics(Arc<Failures>);

impl TemplateRegistry {
    pub(super) fn resolve(
        &self,
        server: &str,
        zone: &str,
        view: &str,
        class: &str,
        typ: &str,
    ) -> TemplateMetrics {
        TemplateMetrics(Arc::clone(
            self.0
                .lock()
                .unwrap()
                .entry((
                    server.into(),
                    zone.into(),
                    view.into(),
                    class.into(),
                    typ.into(),
                ))
                .or_default(),
        ))
    }

    pub(super) fn encode(&self, out: &mut String) {
        let series = self.0.lock().unwrap();
        if series
            .values()
            .any(|s| s.matches.load(Ordering::Relaxed) != 0)
        {
            let name = "template_matches_total";
            header(out, name, "Counter of template regex matches.", "counter");
            for ((server, zone, view, class, typ), counters) in series.iter() {
                let count = counters.matches.load(Ordering::Relaxed);
                if count != 0 {
                    sample(
                        out,
                        name,
                        &[
                            ("class", class),
                            ("server", server),
                            ("type", typ),
                            ("view", view),
                            ("zone", zone),
                        ],
                        count,
                    );
                }
            }
        }
        for (name, help, render) in [
            (
                "template_template_failures_total",
                "Counter of go template failures.",
                true,
            ),
            (
                "template_rr_failures_total",
                "Counter of mis-templated RRs.",
                false,
            ),
        ] {
            let mut has_header = false;
            for ((server, zone, view, class, typ), counters) in series.iter() {
                for ((section, template), failures) in counters.failures.lock().unwrap().iter() {
                    let count = if render {
                        &failures.render
                    } else {
                        &failures.rr
                    }
                    .load(Ordering::Relaxed);
                    if count != 0 {
                        if !has_header {
                            header(out, name, help, "counter");
                            has_header = true;
                        }
                        sample(
                            out,
                            name,
                            &[
                                ("class", class),
                                ("section", section),
                                ("server", server),
                                ("template", template),
                                ("type", typ),
                                ("view", view),
                                ("zone", zone),
                            ],
                            count,
                        );
                    }
                }
            }
        }
    }
}

impl TemplateMetrics {
    pub fn matched(&self) {
        self.0.matches.fetch_add(1, Ordering::Relaxed);
    }

    /// Resolve failure labels before processing Queries.
    pub fn failure(&self, section: &str, template: &str) -> TemplateFailureMetrics {
        TemplateFailureMetrics(Arc::clone(
            self.0
                .failures
                .lock()
                .unwrap()
                .entry((section.into(), template.into()))
                .or_default(),
        ))
    }
}

impl TemplateFailureMetrics {
    pub fn render_failure(&self) {
        self.0.render.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rr_failure(&self) {
        self.0.rr.fetch_add(1, Ordering::Relaxed);
    }
}
