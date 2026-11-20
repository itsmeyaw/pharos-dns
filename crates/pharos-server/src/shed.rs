//! Bounded, newest-first UDP response queue.

use crate::metrics::ShedMetrics;
use std::{
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::Poll,
};
use tokio::{net::UdpSocket, sync::Notify};

const DEPTH: usize = 1024;
const MAX_MESSAGE: usize = 65535;

struct Inner {
    entries: Vec<Option<(Vec<u8>, SocketAddr)>>,
    free: Vec<Vec<u8>>,
    next: usize,
    size: usize,
    closed: bool,
}

pub(crate) struct ShedStack {
    inner: Mutex<Inner>,
    depth: usize,
    size: AtomicUsize,
    writing: AtomicBool,
    notify: Notify,
    free_notify: Notify,
    metrics: ShedMetrics,
}

impl ShedStack {
    pub(crate) fn new(depth: usize, metrics: ShedMetrics) -> Self {
        Self {
            inner: Mutex::new(Inner {
                entries: std::iter::repeat_with(|| None).take(depth).collect(),
                free: (0..depth + 2)
                    .map(|_| Vec::with_capacity(MAX_MESSAGE))
                    .collect(),
                next: 0,
                size: 0,
                closed: false,
            }),
            size: AtomicUsize::new(0),
            writing: AtomicBool::new(false),
            depth,
            notify: Notify::new(),
            free_notify: Notify::new(),
            metrics,
        }
    }

    pub(crate) fn for_socket(metrics: ShedMetrics) -> Arc<Self> {
        Arc::new(Self::new(DEPTH, metrics))
    }

    pub(crate) fn checkout(&self) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().free.pop()
    }

    pub(crate) async fn checkout_wait(&self) -> Vec<u8> {
        loop {
            let notified = self.free_notify.notified();
            tokio::pin!(notified);
            // Tokio Notified::enable: register before checkout to avoid lost wakeups.
            notified.as_mut().enable();
            if let Some(data) = self.checkout() {
                return data;
            }
            notified.await;
        }
    }

    pub(crate) fn release(&self, mut data: Vec<u8>) {
        data.clear();
        self.inner.lock().unwrap().free.push(data);
        // Tokio Notify::notify_one: wake one registered buffer waiter per release.
        self.free_notify.notify_one();
    }

    pub(crate) fn full(&self) -> bool {
        self.size.load(Ordering::Relaxed) >= self.depth
    }

    pub(crate) fn query_drop(&self) {
        self.metrics.query_drop();
    }

    pub(crate) fn push(&self, data: Vec<u8>, peer: SocketAddr) {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            self.metrics.response_drop();
            inner.free.push(data);
            return;
        }
        let index = inner.next;
        if let Some((mut evicted, _)) = inner.entries[index].take() {
            self.metrics.response_drop();
            evicted.clear();
            inner.free.push(evicted);
            self.free_notify.notify_one();
        } else {
            inner.size += 1;
        }
        inner.entries[index] = Some((data, peer));
        inner.next = (index + 1) % inner.entries.len();
        self.size.store(inner.size, Ordering::Relaxed);
        drop(inner);
        self.notify.notify_one();
    }

    fn pop(&self) -> Option<(Vec<u8>, SocketAddr)> {
        let mut inner = self.inner.lock().unwrap();
        if inner.size == 0 {
            return None;
        }
        inner.next = (inner.next + inner.entries.len() - 1) % inner.entries.len();
        let index = inner.next;
        let result = inner.entries[index].take();
        inner.size -= 1;
        self.size.store(inner.size, Ordering::Relaxed);
        result
    }

    pub(crate) fn close(&self) {
        self.inner.lock().unwrap().closed = true;
        self.notify.notify_one();
    }

    pub(crate) async fn writer(self: Arc<Self>, socket: Arc<UdpSocket>) {
        loop {
            if let Some((data, peer)) = self.pop() {
                self.writing.store(true, Ordering::Relaxed);
                match recover_write(socket.send_to(&data, peer)).await {
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        self.metrics.response_drop();
                        crate::logging::log(
                            "DEBUG",
                            "shed",
                            &format!("Deferred response write failed: {error}"),
                        );
                    }
                    None => {
                        self.metrics.response_drop();
                        crate::logging::log("ERROR", "shed", "Recovered panic in shed writer");
                    }
                }
                self.writing.store(false, Ordering::Relaxed);
                self.release(data);
            } else if self.inner.lock().unwrap().closed {
                return;
            } else {
                self.notify.notified().await;
            }
        }
    }
}

impl Drop for ShedStack {
    fn drop(&mut self) {
        let pending =
            self.inner.get_mut().unwrap().size + usize::from(self.writing.load(Ordering::Relaxed));
        for _ in 0..pending {
            self.metrics.response_drop();
        }
    }
}

async fn recover_write(
    future: impl Future<Output = io::Result<usize>>,
) -> Option<io::Result<usize>> {
    let mut future = std::pin::pin!(future);
    poll_fn(
        |cx| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
            Ok(result) => result.map(Some),
            Err(_) => Poll::Ready(None),
        },
    )
    .await
}

#[cfg(test)]
mod tests;
