//! Bounded queue of encoded dnstap payloads over a pool of recycled buffers.
//!
//! CoreDNS v1.15.0 `plugin/dnstap/io.go` `dio.Dnstap` does a non-blocking send on a buffered
//! channel and counts a drop when it is full. Here the Query path takes an empty buffer, encodes
//! into it and queues it; the writer returns spent buffers in batches. Buffers are created lazily,
//! at most `capacity` of them, so the bound covers queued and in-flight payloads together, and a
//! warm pool allocates nothing per Query.
//!
//! Each lock is held only for a push, a pop or a swap of a whole batch: never across IO or an
//! await. Producers contend with one another for a few instructions, and the writer takes each lock
//! once per batch, not once per message.

use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use tokio::sync::Notify;

#[cfg(test)]
mod tests;

// Pharos choice: room for the envelope and a typical non-`full` message without regrowing.
const INITIAL_BUFFER: usize = 512;

// Pharos choice: a buffer grown past this by one large `full` message is dropped on return, so the pool's footprint stays near `capacity * INITIAL_BUFFER`.
const MAX_RETAINED_BUFFER: usize = 16 * 1024;

#[derive(Debug)]
pub(super) struct Queue {
    free: Mutex<Vec<Vec<u8>>>,
    pending: Mutex<VecDeque<Vec<u8>>>,
    created: AtomicUsize,
    capacity: usize,
    ready: Notify,
}

impl Queue {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            free: Mutex::new(Vec::new()),
            pending: Mutex::new(VecDeque::new()),
            created: AtomicUsize::new(0),
            capacity,
            ready: Notify::new(),
        }
    }

    /// An empty buffer, or `None` once `capacity` buffers are in use: the caller drops the message.
    // CoreDNS v1.15.0 plugin/dnstap/io.go dio.Dnstap: a full queue drops the message rather than blocking the Query.
    pub(super) fn acquire(&self) -> Option<Vec<u8>> {
        if let Some(buffer) = self.free.lock().unwrap().pop() {
            return Some(buffer);
        }
        let mut created = self.created.load(Ordering::Relaxed);
        loop {
            if created >= self.capacity {
                return None;
            }
            match self.created.compare_exchange_weak(
                created,
                created + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Vec::with_capacity(INITIAL_BUFFER)),
                Err(actual) => created = actual,
            }
        }
    }

    /// Queues an encoded payload and wakes the writer if it may be waiting.
    pub(super) fn push(&self, payload: Vec<u8>) {
        let mut pending = self.pending.lock().unwrap();
        let was_empty = pending.is_empty();
        pending.push_back(payload);
        drop(pending);
        // `Notify` keeps one permit, so a push between the writer's check and its wait is not lost.
        if was_empty {
            self.ready.notify_one();
        }
    }

    /// Takes everything queued so far into `batch` (which must be empty), waiting while the queue is empty.
    pub(super) async fn next_batch(&self, batch: &mut VecDeque<Vec<u8>>) {
        debug_assert!(batch.is_empty());
        loop {
            if self.try_batch(batch) {
                return;
            }
            self.ready.notified().await;
        }
    }

    /// Like `next_batch` without waiting: whether anything was taken.
    pub(super) fn try_batch(&self, batch: &mut VecDeque<Vec<u8>>) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if pending.is_empty() {
            return false;
        }
        std::mem::swap(&mut *pending, batch);
        true
    }

    /// Returns buffers whose payloads have been written or abandoned.
    pub(super) fn recycle(&self, spent: &mut Vec<Vec<u8>>) {
        for buffer in spent.iter_mut() {
            buffer.clear();
            if buffer.capacity() > MAX_RETAINED_BUFFER {
                *buffer = Vec::with_capacity(INITIAL_BUFFER);
            }
        }
        self.free.lock().unwrap().append(spent);
    }
}
