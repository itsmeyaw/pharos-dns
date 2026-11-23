//! Bounded span queue that disposes the oldest span rather than block a Query.

use std::{
    collections::VecDeque,
    sync::{
        Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use pharos_server::metrics::TraceMetrics;
use tokio::sync::Notify;

use super::span::SpanRecord;

pub(super) struct Queue {
    spans: Mutex<VecDeque<SpanRecord>>,
    backlog: usize,
    batch_size: usize,
    metrics: TraceMetrics,
    pub wake: Notify,
    closed: AtomicBool,
}

impl Queue {
    pub(super) fn new(backlog: usize, batch_size: usize, metrics: TraceMetrics) -> Self {
        Self {
            // The preallocation keeps a warm sampled Query from allocating; it is capped so a huge backlog setting costs memory only when used.
            spans: Mutex::new(VecDeque::with_capacity(backlog.min(1024))),
            backlog,
            batch_size,
            metrics,
            wake: Notify::new(),
            closed: AtomicBool::new(false),
        }
    }

    // zipkin-go reporter/http append: beyond the backlog the oldest spans are disposed.
    pub(super) fn push(&self, span: SpanRecord) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let mut spans = self.spans.lock().unwrap_or_else(PoisonError::into_inner);
        if spans.len() >= self.backlog {
            spans.pop_front();
            self.metrics.dropped_queue_full(1);
        }
        spans.push_back(span);
        let full = spans.len() >= self.batch_size;
        drop(spans);
        // zipkin-go reporter/http loop: a full batch is sent without waiting for the interval.
        if full {
            self.wake.notify_one();
        }
    }

    pub(super) fn len(&self) -> usize {
        self.spans
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    // zipkin-go reporter/http sendBatch: one request carries every span queued so far.
    // Swapping with the exporter's empty spare keeps the lock short and both buffers allocated.
    pub(super) fn swap(&self, spare: &mut VecDeque<SpanRecord>) {
        debug_assert!(spare.is_empty());
        std::mem::swap(
            &mut *self.spans.lock().unwrap_or_else(PoisonError::into_inner),
            spare,
        );
    }

    /// Empty the queue and return how many spans it held.
    pub(super) fn discard(&self) -> usize {
        let mut spans = self.spans.lock().unwrap_or_else(PoisonError::into_inner);
        let count = spans.len();
        spans.clear();
        count
    }

    pub(super) fn spare(&self) -> VecDeque<SpanRecord> {
        VecDeque::with_capacity(self.backlog.min(1024))
    }

    pub(super) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    pub(super) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}
