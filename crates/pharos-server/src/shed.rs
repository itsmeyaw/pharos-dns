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
            if let Some(data) = self.checkout() {
                return data;
            }
            notified.await;
        }
    }

    pub(crate) fn release(&self, mut data: Vec<u8>) {
        data.clear();
        self.inner.lock().unwrap().free.push(data);
        self.free_notify.notify_waiters();
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
            self.free_notify.notify_waiters();
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
mod tests {
    use super::*;
    use crate::metrics::Registry;

    #[test]
    fn stack_evicts_oldest_and_pops_newest() {
        let registry = Registry::new("v", "r", "rust");
        let stack = ShedStack::new(3, registry.shed("dns://:53"));
        let peer = "127.0.0.1:53".parse().unwrap();
        for value in 1..=5 {
            let mut data = stack.checkout().unwrap();
            data.push(value);
            stack.push(data, peer);
        }
        assert!(stack.full());
        for value in [5, 4, 3] {
            let (data, _) = stack.pop().unwrap();
            assert_eq!(data, [value]);
            stack.release(data);
        }
        assert!(stack.pop().is_none());
        let mut text = String::new();
        registry.encode(&mut text);
        assert!(
            text.contains("reason=\"response\",server=\"dns://:53\"} 2"),
            "{text}"
        );
    }

    #[test]
    fn close_rejects_new_responses_and_drains_accepted_entries() {
        let registry = Registry::new("v", "r", "rust");
        let stack = ShedStack::new(3, registry.shed("dns://:53"));
        let peer = "127.0.0.1:53".parse().unwrap();
        let mut first = stack.checkout().unwrap();
        first.push(1);
        stack.push(first, peer);
        stack.close();
        let second = stack.checkout().unwrap();
        stack.push(second, peer);
        assert_eq!(stack.pop().unwrap().0, [1]);
        assert!(stack.pop().is_none());
        let mut output = String::new();
        registry.encode(&mut output);
        assert!(
            output.contains("reason=\"response\",server=\"dns://:53\"} 1"),
            "{output}"
        );
    }

    #[test]
    fn abandoned_stack_counts_pending_responses() {
        let registry = Registry::new("v", "r", "rust");
        let stack = ShedStack::new(3, registry.shed("dns://:53"));
        let peer = "127.0.0.1:53".parse().unwrap();
        stack.push(stack.checkout().unwrap(), peer);
        stack.push(stack.checkout().unwrap(), peer);
        drop(stack);
        let mut output = String::new();
        registry.encode(&mut output);
        assert!(
            output.contains("reason=\"response\",server=\"dns://:53\"} 2"),
            "{output}"
        );
    }

    #[tokio::test]
    async fn concurrent_buffer_waiters_all_wake_after_release() {
        let registry = Registry::new("v", "r", "rust");
        let stack = Arc::new(ShedStack::new(1, registry.shed("dns://:53")));
        let held = (0..3)
            .map(|_| stack.checkout().unwrap())
            .collect::<Vec<_>>();
        let one = tokio::spawn({
            let stack = Arc::clone(&stack);
            async move { stack.checkout_wait().await }
        });
        let two = tokio::spawn({
            let stack = Arc::clone(&stack);
            async move { stack.checkout_wait().await }
        });
        tokio::task::yield_now().await;
        for data in held {
            stack.release(data);
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            one.await.unwrap();
            two.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn failed_deferred_write_increments_response_counter() {
        let registry = Registry::new("v", "r", "rust");
        let stack = Arc::new(ShedStack::new(3, registry.shed("dns://:53")));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = "[::1]:53".parse().unwrap();
        let mut data = stack.checkout().unwrap();
        data.push(1);
        stack.push(data, peer);
        stack.close();
        Arc::clone(&stack).writer(socket).await;
        let mut output = String::new();
        registry.encode(&mut output);
        assert!(
            output.contains("reason=\"response\",server=\"dns://:53\"} 1"),
            "{output}"
        );
    }

    #[tokio::test]
    async fn writer_recovers_panics() {
        assert!(
            recover_write(async { panic!("writer exploded") })
                .await
                .is_none()
        );
        assert_eq!(recover_write(async { Ok(7) }).await.unwrap().unwrap(), 7);
    }
}
