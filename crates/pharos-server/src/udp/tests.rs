use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

struct Blocking {
    started: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

struct Shedding(bool);
impl Handler for Shedding {
    fn shed_query(&self, _: &[u8], _: SocketAddr) -> bool {
        self.0
    }
    async fn handle(&self, _: &[u8], _: SocketAddr, _: Protocol, _: &mut Vec<u8>) -> Action {
        Action::Drop
    }
}

#[tokio::test]
async fn completed_buffer_pool_is_bounded() {
    let mut free = Vec::new();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let handler = Arc::new(Shedding(false));
    // Rust Vec::capacity: retaining completed slots must stay bounded after a burst.
    for _ in 0..MAX_IN_FLIGHT {
        recycle(
            Some(Ok(Some(Slot::new(&handler, &socket, None)))),
            &mut free,
        );
    }
    assert_eq!(free.len(), MAX_REUSABLE_BUFFERS);
}

#[tokio::test]
async fn ready_queries_keep_the_same_pinned_coroutine() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let handler = Arc::new(Shedding(false));
    let mut slot = Some(Slot::new(&handler, &socket, None));
    let mut pending = JoinSet::new();
    let mut free = Vec::new();
    let address = slot.as_ref().unwrap().future.as_ref().get_ref() as *const _ as *const ();
    let peer = "127.0.0.1:53".parse().unwrap();
    // Rust Pin: repeated ready Queries must keep the same coroutine allocation.
    for _ in 0..32 {
        slot.as_mut()
            .unwrap()
            .prepare(b"query", (peer, peer), "", None);
        dispatch(&mut slot, &mut pending, &mut free, &handler, &socket, None).await;
        let current = slot.as_ref().unwrap().future.as_ref().get_ref() as *const _ as *const ();
        assert_eq!(current, address);
        assert!(pending.is_empty());
    }
}

#[tokio::test]
async fn shutdown_reaps_panics_and_cancels_pending_queries() {
    let mut pending = JoinSet::new();
    let panic = pending.spawn(async { panic!("test shutdown panic") });
    let started = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let handler = Arc::new(Blocking {
        started: started.clone(),
        dropped: dropped.clone(),
    });
    pending.spawn(async move {
        let mut response = Vec::new();
        handler
            .handle(
                &[],
                "127.0.0.1:53".parse().unwrap(),
                Protocol::Udp,
                &mut response,
            )
            .await;
        None
    });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !panic.is_finished() || !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    shutdown_pending(&mut pending).await;
    assert!(pending.is_empty());
    assert!(dropped.load(Ordering::SeqCst));
}

struct Panicking {
    pending: bool,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
struct ProbePanic {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
impl Handler for ProbePanic {
    async fn handle(&self, _: &[u8], _: SocketAddr, _: Protocol, _: &mut Vec<u8>) -> Action {
        // Rust Future::poll: a probe can panic after yielding.
        self.entered.notify_one();
        self.release.notified().await;
        panic!("test probe panic");
    }
}
impl Handler for Panicking {
    async fn handle(&self, _: &[u8], _: SocketAddr, _: Protocol, _: &mut Vec<u8>) -> Action {
        // Rust Future::poll: a panic can occur before or after a Pending result.
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            if self.pending {
                tokio::task::yield_now().await;
            }
            panic!("test panic");
        }
        Action::Drop
    }
}

#[tokio::test]
async fn shed_panics_return_checked_out_buffers() {
    for pending_panic in [false, true] {
        let stack = Arc::new(crate::shed::ShedStack::new(
            1,
            crate::metrics::Registry::default().shed("dns://:53"),
        ));
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let response = stack.checkout().unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let handler = Arc::new(Panicking {
            pending: pending_panic,
            calls: calls.clone(),
        });
        let mut slot = Some(Slot::new(&handler, &socket, Some(&stack)));
        let mut pending = JoinSet::new();
        let mut free = Vec::new();
        let peer = "127.0.0.1:53".parse().unwrap();
        slot.as_mut()
            .unwrap()
            .prepare(&[0], (peer, peer), "", Some(response));
        dispatch(
            &mut slot,
            &mut pending,
            &mut free,
            &handler,
            &socket,
            Some(&stack),
        )
        .await;
        assert!(slot.is_some());
        if pending_panic {
            recycle(pending.join_next().await, &mut free);
        }
        let response = stack.checkout().unwrap();
        slot.as_mut()
            .unwrap()
            .prepare(&[1], (peer, peer), "", Some(response));
        dispatch(
            &mut slot,
            &mut pending,
            &mut free,
            &handler,
            &socket,
            Some(&stack),
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(pending.is_empty());
        let held = (0..3)
            .map(|_| stack.checkout().expect("buffer returned after panic"))
            .collect::<Vec<_>>();
        assert!(stack.checkout().is_none());
        for buffer in held {
            stack.release(buffer);
        }
    }
}

#[tokio::test]
async fn shed_probe_panic_returns_checked_out_buffer() {
    let stack = Arc::new(crate::shed::ShedStack::new(
        1,
        crate::metrics::Registry::default().shed("dns://:53"),
    ));
    let mut held = vec![stack.checkout().unwrap(), stack.checkout().unwrap()];
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let (_shutdown, receiver) = watch::channel(false);
    let (_cancel, cancelled) = watch::channel(false);
    spawn_parallel(
        socket,
        Arc::new(ProbePanic {
            entered: entered.clone(),
            release: release.clone(),
        }),
        b"probe",
        "127.0.0.1:53".parse().unwrap(),
        receiver,
        cancelled,
        Some(stack.clone()),
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    assert!(stack.checkout().is_none());
    release.notify_one();
    let returned = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Some(buffer) = stack.checkout() {
                break buffer;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    held.push(returned);
    for buffer in held {
        stack.release(buffer);
    }
}

#[tokio::test]
async fn shed_exhaustion_defers_checkout_until_a_buffer_returns() {
    let stack = Arc::new(crate::shed::ShedStack::new(
        1,
        crate::metrics::Registry::default().shed("dns://:53"),
    ));
    let mut held = (0..3)
        .map(|_| stack.checkout().unwrap())
        .collect::<Vec<_>>();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let handler = Arc::new(Shedding(false));
    let (_shutdown, mut receiver) = watch::channel(false);
    let stack_clone = stack.clone();
    let waiter = tokio::spawn(async move {
        shed_buffer(&stack_clone, &socket, &handler, &mut receiver, &mut None).await
    });
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());
    stack.release(held.pop().unwrap());
    let response = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    held.push(response);
    for buffer in held {
        stack.release(buffer);
    }
}

#[tokio::test]
async fn overloaded_shed_counts_eligible_queries_if_stack_is_full() {
    let registry = crate::metrics::Registry::default();
    let stack = Arc::new(crate::shed::ShedStack::new(1, registry.shed("dns://:53")));
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    stack.push(stack.checkout().unwrap(), client.local_addr().unwrap());
    client
        .send_to(b"ordinary", server.local_addr().unwrap())
        .await
        .unwrap();
    let (_shutdown, receiver) = watch::channel(false);
    receive_probe(
        &server,
        &Arc::new(Shedding(true)),
        receiver,
        Some(&stack),
        &mut None,
    )
    .await
    .unwrap();
    let mut output = String::new();
    registry.encode(&mut output);
    assert!(
        output.contains("reason=\"query\",server=\"dns://:53\"} 1"),
        "{output}"
    );
}
#[test]
fn full_stack_only_drops_queries_from_shed_blocks() {
    let registry = crate::metrics::Registry::default();
    let stack = crate::shed::ShedStack::new(1, registry.shed("dns://:53"));
    let peer = "127.0.0.1:53".parse().unwrap();
    assert!(!should_shed(&stack, &Shedding(true), &[], peer));
    stack.push(stack.checkout().unwrap(), peer);
    assert!(!should_shed(&stack, &Shedding(false), &[], peer));
    assert!(should_shed(&stack, &Shedding(true), &[], peer));
    let mut text = String::new();
    registry.encode(&mut text);
    assert!(
        text.contains("reason=\"query\",server=\"dns://:53\"} 1"),
        "{text}"
    );
}
struct Guard(Arc<AtomicBool>);
impl Drop for Guard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
impl Handler for Blocking {
    async fn handle(&self, _: &[u8], _: SocketAddr, _: Protocol, _: &mut Vec<u8>) -> Action {
        let _guard = Guard(Arc::clone(&self.dropped));
        self.started.store(true, Ordering::SeqCst);
        std::future::pending().await
    }
}

#[tokio::test]
async fn parallel_query_is_cancelled_when_configuration_restarts() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let dropped = Arc::new(AtomicBool::new(false));
    let started = Arc::new(AtomicBool::new(false));
    let (shutdown, receiver) = watch::channel(false);
    let (restart, cancelled) = watch::channel(false);
    spawn_parallel(
        socket,
        Arc::new(Blocking {
            started: Arc::clone(&started),
            dropped: Arc::clone(&dropped),
        }),
        &[0],
        "127.0.0.1:1234".parse().unwrap(),
        receiver,
        cancelled,
        None,
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    restart.send_replace(true);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !dropped.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(shutdown);
}
