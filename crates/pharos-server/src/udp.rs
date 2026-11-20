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

/// Apply the Listener's PROXY settings to one datagram: the payload offset and the client address.
pub(crate) fn proxied<H: Handler>(
    handler: &H,
    state: &mut crate::proxyproto::UdpState,
    datagram: &[u8],
    peer: SocketAddr,
) -> Option<(usize, SocketAddr)> {
    let client = crate::canonical_peer(peer);
    match handler.proxyproto() {
        None => {
            // Reload: a Listener without PROXY settings must not reuse the TLVs of an earlier datagram.
            state.tlv.clear();
            Some((0, client))
        }
        Some(config) => {
            if state.workers == 0 && config.udp_tracking.is_some() {
                state.workers = handler.udp_workers();
            }
            config.accept_datagram(state, datagram, client, state.workers)
        }
    }
}

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
    // PROXY protocol v2 TLVs, hex-encoded; empty when the datagram carried none.
    tlv: String,
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
            tlv: String::new(),
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
        (peer, client): (SocketAddr, SocketAddr),
        tlv: &str,
        response: Option<Vec<u8>>,
    ) {
        let mut data = self.data.lock().unwrap();
        debug_assert!(data.peer.is_none() && !data.done);
        data.query.clear();
        data.query.extend_from_slice(query);
        data.tlv.clear();
        data.tlv.push_str(tlv);
        // RFC 4007 §8: Retain the scoped peer address for processing and replies.
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
        let (query, tlv, response, peer, client) = poll_fn(|_| {
            let mut data = data.lock().unwrap();
            match data.peer.take() {
                Some((peer, client)) => Poll::Ready((
                    std::mem::take(&mut data.query),
                    std::mem::take(&mut data.tlv),
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
        let action = if tlv.is_empty() {
            H::handle_shared(&handler, &query, client, Protocol::Udp, body).await
        } else {
            H::handle_proxied(&handler, &query, client, Protocol::Udp, &tlv, body).await
        };
        // RFC 2136 §3.8: Send the UDP response to the requestor's source port.
        if action == Action::Respond {
            if let Some(stack) = response.stack {
                stack.push(response.data.take().unwrap(), peer);
            } else {
                // RFC 2181 §4.2: Send each UDP reply to the Query's source port.
                #[cfg(target_os = "linux")]
                let result = socket
                    .async_io(tokio::io::Interest::WRITABLE, || {
                        crate::udp_linux::send(&socket, response.data.as_ref().unwrap(), peer)
                    })
                    .await;
                // RFC 7766 §5: Send DNS responses over UDP when queries arrive over UDP.
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
        data.tlv = tlv;
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
        // RFC 3226 §3: DNSSEC-aware entities handle fragmented IPv4 and IPv6 UDP packets.
        let mut query = vec![0; 65535];
        let mut slot = None;
        let mut pending = JoinSet::new();
        let mut free = Vec::new();
        let mut scratch = None;
        let mut proxy = crate::proxyproto::UdpState::default();
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
            let Some((start, client)) = proxied(&*handler, &mut proxy, &query[..length], peer)
            else {
                continue;
            };
            if should_shed(&stack, &*handler, &query[start..length], client) {
                continue;
            }
            if let Some(cancelled) = handler.parallel_query(&query[start..length], client) {
                spawn_parallel(
                    Arc::clone(&socket),
                    Arc::clone(&handler),
                    &query[start..length],
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
            slot.as_mut().unwrap().prepare(
                &query[start..length],
                (peer, client),
                &proxy.tlv,
                Some(response),
            );
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
        let mut proxy = crate::proxyproto::UdpState::default();
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
                    let Some((start, client)) = proxied(&*handler, &mut proxy, &query[..length], peer) else { continue };
                    if let Some(cancelled) = handler.parallel_query(&query[start..length], client) {
                        spawn_parallel(Arc::clone(&socket), Arc::clone(&handler), &query[start..length], peer, shutdown.clone(), cancelled, None);
                        continue;
                    }
                    if !capacity(&mut pending, &mut free, &mut shutdown, &socket, &handler, None, &mut scratch).await { break 'read; }
                    take_slot(&mut slot, &mut free, &handler, &socket, None);
                    slot.as_mut().unwrap().prepare(&query[start..length], (peer, client), &proxy.tlv, None);
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
mod tests;
