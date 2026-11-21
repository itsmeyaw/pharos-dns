use std::{
    fmt::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use super::{SortedSamples, header};

// Pharos-only series: CoreDNS v1.15.0 plugin/trace exports no metrics, so these carry the `pharos_trace_` prefix of ADR-0003.
#[derive(Default)]
pub(super) struct TraceCounters {
    enabled: AtomicBool,
    exported: AtomicU64,
    dropped_queue_full: AtomicU64,
    dropped_export_failed: AtomicU64,
}

/// Span counters of the `trace` Plugin; a default value is detached from any registry.
#[derive(Clone, Default)]
pub struct TraceMetrics(Arc<TraceCounters>);

impl TraceCounters {
    pub(super) fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }

    pub(super) fn encode(&self, out: &mut String) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        header(
            out,
            "trace_exported_spans_total",
            "Counter of spans accepted by the collector.",
            "counter",
        );
        writeln!(
            out,
            "pharos_trace_exported_spans_total {}",
            self.exported.load(Ordering::Relaxed)
        )
        .unwrap();
        header(
            out,
            "trace_dropped_spans_total",
            "Counter of spans dropped before reaching the collector, by reason.",
            "counter",
        );
        let mut sorted = SortedSamples::default();
        for (reason, counter) in [
            ("export_failed", &self.dropped_export_failed),
            ("queue_full", &self.dropped_queue_full),
        ] {
            sorted.sample(
                "trace_dropped_spans_total",
                &[("reason", reason)],
                counter.load(Ordering::Relaxed),
            );
        }
        sorted.write(out);
    }
}

impl TraceMetrics {
    pub(super) fn shared(counters: &Arc<TraceCounters>) -> Self {
        counters.enable();
        Self(Arc::clone(counters))
    }

    pub fn exported(&self, spans: u64) {
        self.0.exported.fetch_add(spans, Ordering::Relaxed);
    }

    /// A span was disposed because the bounded queue was full.
    pub fn dropped_queue_full(&self, spans: u64) {
        self.0
            .dropped_queue_full
            .fetch_add(spans, Ordering::Relaxed);
    }

    /// A batch could not be delivered, so its spans were discarded.
    pub fn dropped_export_failed(&self, spans: u64) {
        self.0
            .dropped_export_failed
            .fetch_add(spans, Ordering::Relaxed);
    }

    #[must_use]
    pub fn exported_total(&self) -> u64 {
        self.0.exported.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn dropped_queue_full_total(&self) -> u64 {
        self.0.dropped_queue_full.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn dropped_export_failed_total(&self) -> u64 {
        self.0.dropped_export_failed.load(Ordering::Relaxed)
    }
}
