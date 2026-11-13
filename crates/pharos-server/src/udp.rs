use std::{
    future::{Future, poll_fn},
    io,
    net::{SocketAddr, UdpSocket as StdUdpSocket},
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    task::Poll,
};

use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use std::sync::Arc;
use tokio::task::{JoinHandle, JoinSet};
use tokio::{net::UdpSocket, sync::watch};

use crate::{Action, Handler, Protocol};

// Implementation limit: bound pending work and retained buffer pairs per worker.
pub(crate) const MAX_IN_FLIGHT: usize = 256;
// Implementation limit: retain 16 pairs (about 1 MiB of Responses); larger bursts allocate again.
const MAX_REUSABLE_BUFFERS: usize = 16;
pub(crate) type Buffers = (Vec<u8>, Option<Vec<u8>>);

struct ResponseBuffer {
    data: Option<Vec<u8>>,
    stack: Option<Arc<crate::shed::ShedStack>>,
}

// Rust Drop::drop: return checked-out storage when a Query is cancelled or panics.
impl Drop for ResponseBuffer {
    fn drop(&mut self) {
        if let (Some(stack), Some(data)) = (&self.stack, self.data.take()) {
            stack.release(data);
        }
    }
}

// RFC 1035 §4.2.1: UDP carries DNS Messages in datagrams.
pub(crate) async fn answer<H: Handler>(
    handler: Arc<H>,
    socket: Arc<UdpSocket>,
    query: Vec<u8>,
    peer: SocketAddr,
    response: Option<Vec<u8>>,
    stack: Option<Arc<crate::shed::ShedStack>>,
) -> Buffers {
    // RFC 1035 §4.2.2: a forwarded TCP Message can reach 65,535 octets before UDP truncation.
    let data = response.unwrap_or_else(|| Vec::with_capacity(65535));
    let mut response = ResponseBuffer {
        data: Some(data),
        stack,
    };
    let data = response.data.as_mut().unwrap();
    data.clear();
    let action = H::handle_shared(
        &handler,
        &query,
        crate::canonical_peer(peer),
        Protocol::Udp,
        data,
    )
    .await;
    if action == Action::Respond {
        if let Some(stack) = &response.stack {
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
    let data = if response.stack.is_some() {
        None
    } else {
        response.data.take()
    };
    (query, data)
}

// Rust Future::poll: reuse completed futures; spawn pending ones to isolate each Query.
pub(crate) async fn dispatch<F: Future<Output = Buffers> + Send + 'static>(
    future: F,
    slot: &mut Option<Pin<Box<F>>>,
    pending: &mut JoinSet<Buffers>,
) -> Option<Buffers> {
    if let Some(slot) = slot.as_mut() {
        slot.as_mut().set(future);
    } else {
        *slot = Some(Box::pin(future));
    }
    // Rust AssertUnwindSafe: drop the panicked future; shared handler state may be partially mutated.
    let polled = poll_fn(|cx| {
        Poll::Ready(catch_unwind(AssertUnwindSafe(|| {
            slot.as_mut().unwrap().as_mut().poll(cx)
        })))
    })
    .await;
    match polled {
        Ok(Poll::Ready(buffers)) => Some(buffers),
        Ok(Poll::Pending) => {
            pending.spawn(slot.take().unwrap());
            None
        }
        Err(_) => {
            *slot = None;
            crate::logging::log("ERROR", "server", "Recovered panic in UDP Query");
            None
        }
    }
}

// Implementation limit: retain one deferred Query and drop further ordinary datagrams at capacity.
pub(crate) async fn capacity<H: Handler>(
    pending: &mut JoinSet<Buffers>,
    free: &mut Vec<Buffers>,
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
    result: Option<Result<Buffers, tokio::task::JoinError>>,
    free: &mut Vec<Buffers>,
) {
    match result {
        Some(Ok(buffers)) if free.len() < MAX_REUSABLE_BUFFERS => free.push(buffers),
        Some(Err(error)) if error.is_panic() => {
            crate::logging::log("ERROR", "server", "Recovered panic in UDP Query")
        }
        _ => {}
    }
}

// Rust Vec::capacity: reuse a completed Query's buffers before allocating replacements.
pub(crate) fn take_buffers(
    query: &mut Vec<u8>,
    response: &mut Option<Vec<u8>>,
    free: &mut Vec<Buffers>,
) {
    if query.capacity() == 0
        && let Some((reused, data)) = free.pop()
    {
        *query = reused;
        if response.is_none() {
            *response = data;
        }
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
            stack,
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
        let mut owned_query = Vec::with_capacity(65535);
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
            take_buffers(&mut owned_query, &mut None, &mut free);
            owned_query.clear();
            owned_query.extend_from_slice(&query[..length]);
            if let Some((reused, _)) = dispatch(
                answer(
                    Arc::clone(&handler),
                    Arc::clone(&socket),
                    std::mem::take(&mut owned_query),
                    peer,
                    Some(response),
                    Some(Arc::clone(&stack)),
                ),
                &mut slot,
                &mut pending,
            )
            .await
            {
                owned_query = reused;
            }
        }
        pending.shutdown().await;
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
        let mut owned_query = Vec::with_capacity(65535);
        let mut response = Some(Vec::with_capacity(65535));
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
                    take_buffers(&mut owned_query, &mut response, &mut free);
                    owned_query.clear();
                    owned_query.extend_from_slice(&query[..length]);
                    if let Some((reused, data)) = dispatch(answer(Arc::clone(&handler), Arc::clone(&socket), std::mem::take(&mut owned_query), peer, response.take(), None), &mut slot, &mut pending).await {
                        owned_query = reused;
                        response = data;
                    }
                }
            }
        }
        // Tokio JoinSet::shutdown: release pending sockets before the Listener is replaced.
        pending.shutdown().await;
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

    #[test]
    fn completed_buffer_pool_is_bounded() {
        let mut free = Vec::new();
        // Rust Vec::capacity: retaining completed buffers must stay bounded after a burst.
        for _ in 0..MAX_IN_FLIGHT {
            recycle(Some(Ok((vec![0], Some(vec![0])))), &mut free);
        }
        assert_eq!(free.len(), MAX_REUSABLE_BUFFERS);
    }

    struct Panicking(bool);
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
            if self.0 {
                tokio::task::yield_now().await;
            }
            panic!("test panic");
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
            let mut slot = None;
            let mut pending = JoinSet::new();
            let mut free = Vec::new();
            let future = answer(
                Arc::new(Panicking(pending_panic)),
                socket,
                vec![0],
                "127.0.0.1:53".parse().unwrap(),
                Some(response),
                Some(Arc::clone(&stack)),
            );
            assert!(dispatch(future, &mut slot, &mut pending).await.is_none());
            if pending_panic {
                recycle(pending.join_next().await, &mut free);
            }
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
