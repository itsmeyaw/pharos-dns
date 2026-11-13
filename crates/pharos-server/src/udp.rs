use std::{
    future::{Future, poll_fn},
    io,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    task::{Context, Poll},
};

use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use std::sync::{Arc, Mutex};
use tokio::task::{JoinHandle, JoinSet};
use tokio::{net::UdpSocket, sync::watch};

use crate::{Action, Handler, Protocol};

// Implementation limit: bound pending work and retained coroutine slots per worker.
pub(crate) const MAX_IN_FLIGHT: usize = 256;
// Implementation limit: retain 16 slots; larger bursts allocate again.
const MAX_REUSABLE_BUFFERS: usize = 16;
struct ResponseBuffer<'a> {
    data: Option<Vec<u8>>,
    stack: Option<&'a crate::shed::ShedStack>,
}

// Rust Drop::drop: return checked-out storage when a Query is cancelled or panics.
impl Drop for ResponseBuffer<'_> {
    fn drop(&mut self) {
        if let (Some(stack), Some(data)) = (&self.stack, self.data.take()) {
            stack.release(data);
        }
    }
}

struct SlotData {
    query: Vec<u8>,
    response: Option<Vec<u8>>,
    peer: Option<(SocketAddr, SocketAddr)>,
    done: bool,
}

pub(crate) struct Slot {
    data: Arc<Mutex<SlotData>>,
    future: Pin<Box<dyn Future<Output = ()> + Send>>,
}

impl Slot {
    // Rust Future::poll: one pinned coroutine reuses its Handler future storage across Queries.
    pub(crate) fn new<H: Handler>(
        handler: &Arc<H>,
        socket: &Arc<UdpSocket>,
        stack: Option<&Arc<crate::shed::ShedStack>>,
    ) -> Self {
        let data = Arc::new(Mutex::new(SlotData {
            query: Vec::with_capacity(65535),
            response: stack.is_none().then(|| Vec::with_capacity(65535)),
            peer: None,
            done: false,
        }));
        // Rust Mutex: initialize macOS pthread storage before the ready Query path.
        drop(data.lock().unwrap());
        let future = Box::pin(serve_slot(
            Arc::clone(&data),
            Arc::clone(handler),
            Arc::clone(socket),
            stack.cloned(),
        ));
        Self { data, future }
    }

    // RFC 1035 §4.2.1: each datagram retains its own Query and peer until completion.
    pub(crate) fn prepare(
        &mut self,
        query: &[u8],
        peer: SocketAddr,
        client: SocketAddr,
        response: Option<Vec<u8>>,
    ) {
        let mut data = self.data.lock().unwrap();
        debug_assert!(data.peer.is_none() && !data.done);
        data.query.clear();
        data.query.extend_from_slice(query);
        data.peer = Some((peer, client));
        if response.is_some() {
            data.response = response;
        }
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ()>> {
        // Rust AssertUnwindSafe: drop a panicked future; shared Handler state may be partially mutated.
        match catch_unwind(AssertUnwindSafe(|| self.future.as_mut().poll(cx))) {
            Err(_) => Poll::Ready(Err(())),
            Ok(_) if std::mem::take(&mut self.data.lock().unwrap().done) => Poll::Ready(Ok(())),
            Ok(_) => Poll::Pending,
        }
    }
}

// RFC 1035 §4.2.1: process UDP Messages independently while reusing the pinned coroutine.
async fn serve_slot<H: Handler>(
    data: Arc<Mutex<SlotData>>,
    handler: Arc<H>,
    socket: Arc<UdpSocket>,
    stack: Option<Arc<crate::shed::ShedStack>>,
) {
    loop {
        // Rust Future::poll: idle slots are polled explicitly after input is installed.
        let (query, response, peer, client) = poll_fn(|_| {
            let mut data = data.lock().unwrap();
            match data.peer.take() {
                Some((peer, client)) => Poll::Ready((
                    std::mem::take(&mut data.query),
                    data.response.take(),
                    peer,
                    client,
                )),
                None => Poll::Pending,
            }
        })
        .await;
        // RFC 1035 §4.2.2: forwarded TCP Messages can reach 65,535 octets before UDP truncation.
        let mut response = ResponseBuffer {
            data: Some(response.unwrap_or_else(|| Vec::with_capacity(65535))),
            stack: stack.as_deref(),
        };
        let body = response.data.as_mut().unwrap();
        body.clear();
        let action = H::handle_shared(&handler, &query, client, Protocol::Udp, body).await;
        if action == Action::Respond {
            if let Some(stack) = response.stack {
                stack.push(response.data.take().unwrap(), peer);
            } else {
                #[cfg(target_os = "linux")]
                let result = socket
                    .async_io(tokio::io::Interest::WRITABLE, || {
                        crate::udp_linux::send(&socket, response.data.as_ref().unwrap(), peer)
                    })
                    .await;
                #[cfg(not(target_os = "linux"))]
                let result = socket
                    .send_to(response.data.as_ref().unwrap(), peer)
                    .await
                    .map(|_| ());
                if let Err(error) = result {
                    crate::logging::log(
                        "ERROR",
                        "server",
                        &format!("UDP Response to {peer} failed: {error}"),
                    );
                }
            }
        }
        let mut data = data.lock().unwrap();
        data.query = query;
        if response.stack.is_none() {
            data.response = response.data.take();
        }
        data.done = true;
    }
}

// Rust Future::poll: ready Queries reuse the coroutine; waiting Queries transfer it to a task.
pub(crate) async fn dispatch<H: Handler>(
    slot: &mut Option<Slot>,
    pending: &mut JoinSet<Option<Slot>>,
    free: &mut Vec<Slot>,
    handler: &Arc<H>,
    socket: &Arc<UdpSocket>,
    stack: Option<&Arc<crate::shed::ShedStack>>,
) {
    let polled = poll_fn(|cx| Poll::Ready(slot.as_mut().unwrap().poll(cx))).await;
    match polled {
        Poll::Ready(Ok(())) => {}
        Poll::Pending => {
            let mut task = slot.take().unwrap();
            pending.spawn(async move {
                if poll_fn(|cx| task.poll(cx)).await.is_ok() {
                    Some(task)
                } else {
                    crate::logging::log("ERROR", "server", "Recovered panic in UDP Query");
                    None
                }
            });
            // Rust Future::poll: allocate replacements on the pending path, not the next ready Query.
            take_slot(slot, free, handler, socket, stack);
        }
        Poll::Ready(Err(())) => {
            *slot = None;
            crate::logging::log("ERROR", "server", "Recovered panic in UDP Query");
            take_slot(slot, free, handler, socket, stack);
        }
    }
}

// Implementation limit: retain one deferred Query and drop further ordinary datagrams at capacity.
pub(crate) async fn capacity<H: Handler>(
    pending: &mut JoinSet<Option<Slot>>,
    free: &mut Vec<Slot>,
    shutdown: &mut watch::Receiver<bool>,
    socket: &Arc<UdpSocket>,
    handler: &Arc<H>,
    stack: Option<&Arc<crate::shed::ShedStack>>,
    scratch: &mut Option<Vec<u8>>,
) -> bool {
    while pending.len() >= MAX_IN_FLIGHT {
        let probe_shutdown = shutdown.clone();
        tokio::select! {
            biased;
            _ = shutdown.changed() => return false,
            result = pending.join_next() => recycle(result, free),
            result = receive_probe(socket, handler, probe_shutdown, stack, scratch) => if let Err(error) = result {
                crate::logging::log("ERROR", "server", &format!("UDP receive failed: {error}"));
                tokio::select! { _ = shutdown.changed() => return false, _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {} }
            },
        }
    }
    while let Some(result) = pending.try_join_next() {
        recycle(Some(result), free);
    }
    true
}

// RFC 1035 §4.2.1: inspect datagrams while a deferred Query waits for capacity.
async fn receive_probe<H: Handler>(
    socket: &Arc<UdpSocket>,
    handler: &Arc<H>,
    shutdown: watch::Receiver<bool>,
    stack: Option<&Arc<crate::shed::ShedStack>>,
    scratch: &mut Option<Vec<u8>>,
) -> io::Result<()> {
    let buffer = scratch.get_or_insert_with(|| vec![0; 65535]);
    let (length, peer) = socket.recv_from(buffer).await?;
    if let Some(cancelled) = handler.parallel_query(&buffer[..length], crate::canonical_peer(peer))
    {
        spawn_parallel(
            Arc::clone(socket),
            Arc::clone(handler),
            &buffer[..length],
            peer,
            shutdown,
            cancelled,
            stack.cloned(),
        );
    } else if let Some(stack) = stack {
        // CoreDNS shed: count shed-eligible Queries when the deferred stack is full.
        should_shed(
            stack,
            &**handler,
            &buffer[..length],
            crate::canonical_peer(peer),
        );
    }
    Ok(())
}

// Implementation limit: wait for a shed buffer before starting an ordinary Query.
async fn shed_buffer<H: Handler>(
    stack: &Arc<crate::shed::ShedStack>,
    socket: &Arc<UdpSocket>,
    handler: &Arc<H>,
    shutdown: &mut watch::Receiver<bool>,
    scratch: &mut Option<Vec<u8>>,
) -> Option<Vec<u8>> {
    if let Some(buffer) = stack.checkout() {
        return Some(buffer);
    }
    loop {
        let probe_shutdown = shutdown.clone();
        tokio::select! {
            biased;
            _ = shutdown.changed() => return None,
            buffer = stack.checkout_wait() => return Some(buffer),
            result = receive_probe(socket, handler, probe_shutdown, Some(stack), scratch) => if let Err(error) = result {
                crate::logging::log("ERROR", "server", &format!("UDP receive failed: {error}"));
                tokio::select! { _ = shutdown.changed() => return None, _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {} }
            },
        }
    }
}

// Tokio JoinSet::join_next: completed Queries return reusable buffers; panic loses only that Query.
pub(crate) fn recycle(
    result: Option<Result<Option<Slot>, tokio::task::JoinError>>,
    free: &mut Vec<Slot>,
) {
    match result {
        Some(Ok(Some(slot))) if free.len() < MAX_REUSABLE_BUFFERS => free.push(slot),
        Some(Err(error)) if error.is_panic() => {
            crate::logging::log("ERROR", "server", "Recovered panic in UDP Query")
        }
        _ => {}
    }
}

// Tokio JoinSet::abort_all: cancel Queries and report panics completed before shutdown.
pub(crate) async fn shutdown_pending(pending: &mut JoinSet<Option<Slot>>) {
    pending.abort_all();
    while let Some(result) = pending.join_next().await {
        if let Err(error) = result
            && error.is_panic()
        {
            crate::logging::log("ERROR", "server", "Recovered panic in UDP Query");
        }
    }
}

// Rust Future::poll: reuse a completed slot before allocating a new coroutine.
pub(crate) fn take_slot<H: Handler>(
    slot: &mut Option<Slot>,
    free: &mut Vec<Slot>,
    handler: &Arc<H>,
    socket: &Arc<UdpSocket>,
    stack: Option<&Arc<crate::shed::ShedStack>>,
) {
    if slot.is_none() {
        *slot = Some(
            free.pop()
                .unwrap_or_else(|| Slot::new(handler, socket, stack)),
        );
    }
}

// A forwarding-loop probe must not hold the receive worker while it returns to us.
pub(crate) fn spawn_parallel<H: Handler>(
    socket: Arc<UdpSocket>,
    handler: Arc<H>,
    query: &[u8],
    peer: SocketAddr,
    mut shutdown: watch::Receiver<bool>,
    mut cancelled: watch::Receiver<bool>,
    stack: Option<Arc<crate::shed::ShedStack>>,
) {
    let query = query.to_vec();
    tokio::spawn(async move {
        if *cancelled.borrow() {
            return;
        }
        let data = if let Some(stack) = &stack {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = cancelled.changed() => return,
                data = stack.checkout_wait() => data,
            }
        } else {
            Vec::with_capacity(65535)
        };
        let mut response = ResponseBuffer {
            data: Some(data),
            stack: stack.as_deref(),
        };
        let action = {
            // Rust catch_unwind: isolate probe panics even after the handler yields.
            let future = async {
                handler
                    .handle(
                        &query,
                        crate::canonical_peer(peer),
                        Protocol::Udp,
                        response.data.as_mut().unwrap(),
                    )
                    .await
            };
            tokio::pin!(future);
            tokio::select! {
                _ = shutdown.changed() => None,
                _ = cancelled.changed() => None,
                result = poll_fn(|cx| match catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(cx))) {
                    Ok(result) => result.map(Ok),
                    Err(_) => Poll::Ready(Err(())),
                }) => Some(result),
            }
        };
        match action {
            Some(Ok(Action::Respond)) => {
                if let Some(stack) = &response.stack {
                    stack.push(response.data.take().unwrap(), peer);
                } else if let Err(error) =
                    socket.send_to(response.data.as_ref().unwrap(), peer).await
                {
                    crate::logging::log(
                        "ERROR",
                        "server",
                        &format!("UDP Response to {peer} failed: {error}"),
                    );
                }
            }
            Some(Err(())) => crate::logging::log("ERROR", "server", "Recovered panic in UDP Query"),
            _ => {}
        }
    });
}

pub(crate) fn bind(address: SocketAddr) -> io::Result<StdUdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(SocketProtocol::UDP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(!address.ip().is_unspecified())?;
    }
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    Ok(socket.into())
}

// Growing the descriptor table waits for an RCU grace period once threads exist (~25 ms here).
#[cfg(target_os = "linux")]
pub fn reserve_descriptors(count: i32) -> io::Result<()> {
    let null = std::fs::File::open("/dev/null")?;
    let fd = nix::fcntl::fcntl(&null, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(count))
        .map_err(io::Error::from)?;
    nix::unistd::close(fd).map_err(io::Error::from)
}

#[cfg(not(target_os = "linux"))]
pub fn reserve_descriptors(_count: i32) -> io::Result<()> {
    Ok(())
}

pub(crate) fn spawn<H: Handler>(
    socket: UdpSocket,
    handler: Arc<H>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<io::Result<()>> {
    if let Some(metrics) = handler.shed_metrics() {
        return spawn_shed(socket, handler, shutdown, metrics);
    }
    #[cfg(target_os = "linux")]
    {
        crate::udp_linux::spawn(socket, handler, shutdown)
    }
    #[cfg(not(target_os = "linux"))]
    {
        spawn_plain(socket, handler, shutdown)
    }
}

fn spawn_shed<H: Handler>(
    socket: UdpSocket,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
    metrics: crate::metrics::ShedMetrics,
) -> JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let socket = Arc::new(socket);
        let stack = crate::shed::ShedStack::for_socket(metrics);
        let mut writer = AbortOnDrop(tokio::spawn(Arc::clone(&stack).writer(Arc::clone(&socket))));
        let mut query = vec![0; 65535];
        let mut slot = None;
        let mut pending = JoinSet::new();
        let mut free = Vec::new();
        let mut scratch = None;
        loop {
            let received = tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                result = pending.join_next(), if !pending.is_empty() => { recycle(result, &mut free); continue; },
                received = socket.recv_from(&mut query) => received,
            };
            let (length, peer) = match received {
                Ok(message) => message,
                Err(error) => {
                    crate::logging::log("ERROR", "server", &format!("UDP receive failed: {error}"));
                    tokio::select! { _ = shutdown.changed() => break, _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {} }
                    continue;
                }
            };
            let client = crate::canonical_peer(peer);
            if should_shed(&stack, &*handler, &query[..length], client) {
                continue;
            }
            if let Some(cancelled) = handler.parallel_query(&query[..length], client) {
                spawn_parallel(
                    Arc::clone(&socket),
                    Arc::clone(&handler),
                    &query[..length],
                    peer,
                    shutdown.clone(),
                    cancelled,
                    Some(Arc::clone(&stack)),
                );
                continue;
            }
            if !capacity(
                &mut pending,
                &mut free,
                &mut shutdown,
                &socket,
                &handler,
                Some(&stack),
                &mut scratch,
            )
            .await
            {
                break;
            }
            let Some(response) =
                shed_buffer(&stack, &socket, &handler, &mut shutdown, &mut scratch).await
            else {
                break;
            };
            take_slot(&mut slot, &mut free, &handler, &socket, Some(&stack));
            slot.as_mut()
                .unwrap()
                .prepare(&query[..length], peer, client, Some(response));
            dispatch(
                &mut slot,
                &mut pending,
                &mut free,
                &handler,
                &socket,
                Some(&stack),
            )
            .await;
        }
        shutdown_pending(&mut pending).await;
        stack.close();
        (&mut writer.0).await.map_err(io::Error::other)?;
        Ok(())
    })
}

struct AbortOnDrop(JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn should_shed<H: Handler>(
    stack: &crate::shed::ShedStack,
    handler: &H,
    query: &[u8],
    peer: SocketAddr,
) -> bool {
    if stack.full() && handler.shed_query(query, peer) {
        stack.query_drop();
        true
    } else {
        false
    }
}

#[cfg(not(target_os = "linux"))]
fn spawn_plain<H: Handler>(
    socket: UdpSocket,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let socket = Arc::new(socket);
        let mut query = vec![0; 65535];
        let mut slot = None;
        let mut pending = JoinSet::new();
        let mut free = Vec::new();
        let mut scratch = None;
        'read: loop {
            tokio::select! {
                biased;
                _ = shutdown.changed() => break 'read,
                result = pending.join_next(), if !pending.is_empty() => { recycle(result, &mut free); continue; },
                received = socket.recv_from(&mut query) => {
                    let (length, peer) = match received {
                        Ok(message) => message,
                        Err(error) => {
                            crate::logging::log("ERROR", "server", &format!("UDP receive failed: {error}"));
                            tokio::select! {
                                _ = shutdown.changed() => break 'read,
                                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {},
                            }
                            continue;
                        }
                    };
                    let client = crate::canonical_peer(peer);
                    if let Some(cancelled) = handler.parallel_query(&query[..length], client) {
                        spawn_parallel(Arc::clone(&socket), Arc::clone(&handler), &query[..length], peer, shutdown.clone(), cancelled, None);
                        continue;
                    }
                    if !capacity(&mut pending, &mut free, &mut shutdown, &socket, &handler, None, &mut scratch).await { break 'read; }
                    take_slot(&mut slot, &mut free, &handler, &socket, None);
                    slot.as_mut().unwrap().prepare(&query[..length], peer, client, None);
                    dispatch(&mut slot, &mut pending, &mut free, &handler, &socket, None).await;
                }
            }
        }
        // Tokio JoinSet::abort_all: release pending sockets before the Listener is replaced.
        shutdown_pending(&mut pending).await;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
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
            slot.as_mut().unwrap().prepare(b"query", peer, peer, None);
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
                .prepare(&[0], peer, peer, Some(response));
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
                .prepare(&[1], peer, peer, Some(response));
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
}
