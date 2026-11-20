//! PROXY protocol for QUIC Listeners: a socket wrapper that applies the Listener's PROXY settings
//! to every datagram before quinn reads it.
//!
//! quinn identifies a peer by the address of its datagrams, so a datagram whose header (or cached
//! session) names a client reaches quinn with that client as its source, and everything quinn sends
//! to the client is addressed to the proxy that carried the flow. The wrapper keeps the reverse map.

use std::{
    collections::VecDeque,
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    time::{Duration, Instant},
};

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};

use super::{
    Config, UdpState,
    session::{DEFAULT_MAX_SESSIONS, Sessions},
};
use crate::Handler;

/// One datagram split off a batch that the kernel coalesced (UDP GRO), waiting for its turn.
struct Datagram {
    data: Vec<u8>,
    meta: RecvMeta,
}

/// What reading datagrams needs: the session cache and the datagrams split off a coalesced batch.
#[derive(Default)]
struct Recv {
    udp: UdpState,
    pending: VecDeque<Datagram>,
}

/// Client address to the proxy address that carried it, and the client's TLV hex.
#[derive(Default)]
struct Routes {
    sessions: Option<Sessions>,
    scratch: String,
}

pub(crate) struct Socket<H> {
    inner: Arc<dyn AsyncUdpSocket>,
    handler: Arc<H>,
    /// Set once `routes` holds an entry, so a Listener without PROXY traffic never locks to send.
    used: AtomicBool,
    /// Set while `recv.pending` may hold datagrams, so a read without any skips the lock.
    queued: AtomicBool,
    recv: Mutex<Recv>,
    routes: Mutex<Routes>,
}

impl<H> fmt::Debug for Socket<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Socket").finish_non_exhaustive()
    }
}

impl<H: Handler> Socket<H> {
    pub(crate) fn new(inner: Arc<dyn AsyncUdpSocket>, handler: Arc<H>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            handler,
            used: AtomicBool::new(false),
            queued: AtomicBool::new(false),
            recv: Mutex::default(),
            routes: Mutex::default(),
        })
    }

    /// How long a client's proxy address is remembered without traffic: as long as a quiet connection lives.
    fn route_ttl(&self) -> Duration {
        let tracking = self
            .handler
            .proxyproto()
            .and_then(|config| config.udp_tracking)
            .map_or(Duration::ZERO, |tracking| tracking.ttl);
        tracking.max(self.handler.tcp_options().idle)
    }

    /// The PROXY v2 TLVs, hex-encoded, of the flow `client` arrived on; none when it carried none.
    pub(crate) fn tlv(&self, client: SocketAddr) -> Option<Arc<str>> {
        if !self.used.load(Ordering::Relaxed) {
            return None;
        }
        let ttl = self.route_ttl();
        let mut routes = lock(&self.routes);
        let Routes { sessions, scratch } = &mut *routes;
        sessions
            .as_mut()?
            .lookup(client, Instant::now(), ttl, scratch)?;
        (!scratch.is_empty()).then(|| Arc::from(scratch.as_str()))
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Recv {
    /// Apply `config` to one received datagram in place: strip its header, name its client, or drop it.
    fn accept(
        &mut self,
        (config, routes, ttl): (&Config, &mut Routes, Duration),
        buffer: &mut [u8],
        meta: &mut RecvMeta,
        now: Instant,
    ) {
        let length = meta.len;
        let stride = if meta.stride == 0 {
            length
        } else {
            meta.stride
        };
        if length == 0 {
            return;
        }
        // A datagram behind a split batch waits in line too, so one flow's packets keep their order.
        if length <= stride && self.pending.is_empty() {
            match self.strip(
                (config, &mut *routes, ttl),
                &buffer[..length],
                meta.addr,
                now,
            ) {
                None => meta.len = 0,
                Some((start, client)) => {
                    if start > 0 {
                        buffer.copy_within(start..length, 0);
                    }
                    meta.len = length - start;
                    meta.stride = meta.len;
                    meta.addr = client;
                }
            }
            return;
        }
        // GRO: several datagrams share the buffer, but each may name a different client, so they are
        // delivered one by one on later reads.
        for segment in buffer[..length].chunks(stride) {
            let Some((start, client)) =
                self.strip((config, &mut *routes, ttl), segment, meta.addr, now)
            else {
                continue;
            };
            let data = segment[start..].to_vec();
            self.pending.push_back(Datagram {
                meta: RecvMeta {
                    addr: client,
                    len: data.len(),
                    stride: data.len(),
                    ..*meta
                },
                data,
            });
        }
        meta.len = 0;
    }

    /// The payload offset and client address of one datagram from `proxy`, or `None` to drop it.
    fn strip(
        &mut self,
        (config, routes, ttl): (&Config, &mut Routes, Duration),
        datagram: &[u8],
        proxy: SocketAddr,
        now: Instant,
    ) -> Option<(usize, SocketAddr)> {
        let seen = crate::canonical_peer(proxy);
        // One driver task reads the socket, so the session cache is a single worker's share.
        let (start, client) = config.accept_datagram(&mut self.udp, datagram, seen, 1)?;
        if client == seen {
            return Some((start, proxy));
        }
        let capacity = config
            .udp_tracking
            .map_or(DEFAULT_MAX_SESSIONS, |tracking| tracking.max_sessions);
        let sessions = routes
            .sessions
            .get_or_insert_with(|| Sessions::new(capacity));
        // A live route belongs to the proxy that opened it: another proxy cannot take over the client.
        if sessions
            .peek(client, now, ttl)
            .is_some_and(|held| held != proxy)
        {
            return None;
        }
        sessions.store(client, (proxy, &self.udp.tlv), now);
        Some((start, client))
    }

    /// Fill `meta` with as many waiting datagrams as `buffers` has room for.
    fn deliver(&mut self, buffers: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> usize {
        let mut count = 0;
        while count < buffers.len()
            && let Some(datagram) = self.pending.pop_front()
        {
            buffers[count][..datagram.data.len()].copy_from_slice(&datagram.data);
            meta[count] = datagram.meta;
            count += 1;
        }
        count
    }
}

impl<H: Handler> AsyncUdpSocket for Socket<H> {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if self.used.load(Ordering::Relaxed) {
            let ttl = self.route_ttl();
            let mut routes = lock(&self.routes);
            let Routes { sessions, scratch } = &mut *routes;
            let proxy = sessions.as_mut().and_then(|sessions| {
                sessions.lookup(transmit.destination, Instant::now(), ttl, scratch)
            });
            drop(routes);
            if let Some(destination) = proxy {
                return self.inner.try_send(&Transmit {
                    destination,
                    ..*transmit
                });
            }
        }
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if self.queued.load(Ordering::Acquire) {
            let mut recv = lock(&self.recv);
            let count = recv.deliver(buffers, meta);
            if recv.pending.is_empty() {
                self.queued.store(false, Ordering::Release);
            }
            if count > 0 {
                return Poll::Ready(Ok(count));
            }
        }
        let Some(config) = self.handler.proxyproto() else {
            return self.inner.poll_recv(cx, buffers, meta);
        };
        let count = ready!(self.inner.poll_recv(cx, buffers, meta))?;
        let ttl = self.route_ttl();
        let mut recv = lock(&self.recv);
        let mut routes = lock(&self.routes);
        let now = Instant::now();
        for (buffer, meta) in buffers.iter_mut().zip(meta.iter_mut()).take(count) {
            recv.accept((&config, &mut routes, ttl), buffer, meta, now);
        }
        if routes.sessions.is_some() {
            self.used.store(true, Ordering::Relaxed);
        }
        if !recv.pending.is_empty() {
            self.queued.store(true, Ordering::Release);
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests;
