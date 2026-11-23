use std::{
    fmt::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use super::{header, sample};

/// Why a dnstap message never reached a sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnstapDrop {
    /// The slot pool and queue had no room, as CoreDNS's full `dio.queue` channel.
    QueueFull,
    /// The writer dequeued the message while no sink connection was open.
    NoConnection,
    /// The write to the sink failed.
    WriteError,
}

const DROP_REASONS: [(DnstapDrop, &str); 3] = [
    (DnstapDrop::QueueFull, "queue_full"),
    (DnstapDrop::NoConnection, "no_connection"),
    (DnstapDrop::WriteError, "write_error"),
];

#[derive(Default)]
struct Counters {
    enqueued: AtomicU64,
    dropped: [AtomicU64; 3],
    written: AtomicU64,
    connect_failures: AtomicU64,
    reconnects: AtomicU64,
    connected: AtomicU64,
}

// CoreDNS has no dnstap metrics; these are a Pharos addition, process-wide and unlabelled like forward's.
#[derive(Default)]
pub(super) struct DnstapRegistry {
    counters: Arc<Counters>,
    enabled: AtomicBool,
}

/// Process-wide dnstap counters, resolved once during setup.
#[derive(Clone)]
pub struct DnstapMetrics(Arc<Counters>);

impl DnstapRegistry {
    pub(super) fn resolve(&self) -> DnstapMetrics {
        self.enabled.store(true, Ordering::Relaxed);
        DnstapMetrics(Arc::clone(&self.counters))
    }

    pub(super) fn encode(&self, out: &mut String) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let counters = &self.counters;
        for (name, help, value) in [
            (
                "dnstap_messages_enqueued_total",
                "Counter of dnstap messages queued for a sink.",
                &counters.enqueued,
            ),
            (
                "dnstap_messages_written_total",
                "Counter of dnstap messages written to a sink.",
                &counters.written,
            ),
            (
                "dnstap_connect_failures_total",
                "Counter of failed dials of a dnstap sink.",
                &counters.connect_failures,
            ),
            (
                "dnstap_reconnects_total",
                "Counter of dnstap sink connections opened after the first.",
                &counters.reconnects,
            ),
        ] {
            header(out, name, help, "counter");
            writeln!(out, "pharos_{name} {}", value.load(Ordering::Relaxed)).unwrap();
        }
        header(
            out,
            "dnstap_messages_dropped_total",
            "Counter of dnstap messages dropped, by reason.",
            "counter",
        );
        for (reason, label) in DROP_REASONS {
            sample(
                out,
                "dnstap_messages_dropped_total",
                &[("reason", label)],
                counters.dropped[reason as usize].load(Ordering::Relaxed),
            );
        }
        header(
            out,
            "dnstap_connected",
            "Number of connected dnstap sinks.",
            "gauge",
        );
        writeln!(
            out,
            "pharos_dnstap_connected {}",
            counters.connected.load(Ordering::Relaxed)
        )
        .unwrap();
    }
}

impl DnstapMetrics {
    pub fn enqueued(&self) {
        self.0.enqueued.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dropped(&self, reason: DnstapDrop, count: u64) {
        self.0.dropped[reason as usize].fetch_add(count, Ordering::Relaxed);
    }

    pub fn written(&self, count: u64) {
        self.0.written.fetch_add(count, Ordering::Relaxed);
    }

    pub fn connect_failure(&self) {
        self.0.connect_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn reconnect(&self) {
        self.0.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connected(&self) {
        self.0.connected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn disconnected(&self) {
        self.0.connected.fetch_sub(1, Ordering::Relaxed);
    }
}
