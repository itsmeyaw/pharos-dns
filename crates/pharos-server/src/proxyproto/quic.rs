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
mod tests {
    use super::*;
    use crate::proxyproto::Policy;

    // PROXY protocol §2.2: a PROXY command, IPv4, DGRAM, from `source` to 192.0.2.53:53.
    fn datagram(source: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut wire = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        wire.extend([0x21, 0x12, 0, 12]);
        wire.extend(source);
        wire.extend([192, 0, 2, 53]);
        wire.extend(12345u16.to_be_bytes());
        wire.extend(53u16.to_be_bytes());
        wire.extend(payload);
        wire
    }

    fn meta(length: usize, stride: usize) -> RecvMeta {
        RecvMeta {
            addr: "10.0.0.1:5000".parse().unwrap(),
            len: length,
            stride,
            ..RecvMeta::default()
        }
    }

    const TTL: Duration = Duration::from_secs(10);

    #[derive(Default)]
    struct Fixture {
        recv: Recv,
        routes: Routes,
    }

    impl Fixture {
        fn accept(&mut self, config: &Config, wire: &mut [u8], meta: &mut RecvMeta) {
            self.recv
                .accept((config, &mut self.routes, TTL), wire, meta, Instant::now());
        }
    }

    fn use_all() -> Config {
        Config::new(|_| Policy::Use)
    }

    fn proxy(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 1], port))
    }

    #[test]
    fn a_single_datagram_is_stripped_in_place_and_attributed_to_its_client() {
        let mut wire = datagram([192, 0, 2, 1], b"quic");
        let mut meta = meta(wire.len(), wire.len());
        Fixture::default().accept(&use_all(), &mut wire, &mut meta);
        assert_eq!(&wire[..meta.len], b"quic");
        assert_eq!((meta.len, meta.stride), (4, 4));
        assert_eq!(meta.addr, "192.0.2.1:12345".parse().unwrap());
    }

    #[test]
    fn a_malformed_header_drops_the_datagram() {
        let mut wire = datagram([192, 0, 2, 1], b"quic");
        wire[12] = 0x23;
        let mut meta = meta(wire.len(), wire.len());
        Fixture::default().accept(&use_all(), &mut wire, &mut meta);
        assert_eq!(meta.len, 0);
    }

    // UDP GRO: segments of one buffer may name different clients, so each is delivered on its own.
    #[test]
    fn coalesced_datagrams_are_split_and_each_keeps_its_client() {
        let mut wire = datagram([192, 0, 2, 1], b"aa");
        let stride = wire.len();
        wire.extend(datagram([192, 0, 2, 2], b"bb"));
        wire.extend(b"cc");
        let mut meta = meta(wire.len(), stride);
        let mut fixture = Fixture::default();
        fixture.accept(&use_all(), &mut wire, &mut meta);
        assert_eq!(meta.len, 0);
        let got = delivered(&mut fixture.recv);
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], ("192.0.2.1:12345".parse().unwrap(), b"aa".to_vec()));
        assert_eq!(got[1], ("192.0.2.2:12345".parse().unwrap(), b"bb".to_vec()));
        // The last segment is a headerless datagram of the proxy itself.
        assert_eq!(got[2], (proxy(5000), b"cc".to_vec()));
    }

    fn delivered(recv: &mut Recv) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut buffers = [vec![0; 2048], vec![0; 2048], vec![0; 2048], vec![0; 2048]];
        let mut slices: Vec<_> = buffers.iter_mut().map(|b| IoSliceMut::new(b)).collect();
        let mut metas = [RecvMeta::default(); 4];
        let count = recv.deliver(&mut slices, &mut metas);
        metas[..count]
            .iter()
            .zip(&slices)
            .map(|(meta, slice)| (meta.addr, slice[..meta.len].to_vec()))
            .collect()
    }

    // A datagram that follows a split batch in the same read waits behind it.
    #[test]
    fn a_datagram_after_a_split_batch_keeps_its_place_in_line() {
        let mut batch = datagram([192, 0, 2, 1], b"aa");
        let stride = batch.len();
        batch.extend(datagram([192, 0, 2, 1], b"bb"));
        let mut first = meta(batch.len(), stride);
        let mut next = datagram([192, 0, 2, 1], b"cc");
        let mut second = meta(next.len(), next.len());
        let mut fixture = Fixture::default();
        fixture.accept(&use_all(), &mut batch, &mut first);
        fixture.accept(&use_all(), &mut next, &mut second);
        assert_eq!((first.len, second.len), (0, 0));
        let payloads: Vec<_> = delivered(&mut fixture.recv)
            .into_iter()
            .map(|(_, payload)| payload)
            .collect();
        assert_eq!(payloads, [b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec()]);
    }

    #[test]
    fn a_client_is_remembered_with_its_proxy_and_tlvs() {
        let mut config = use_all();
        config.tlv_metadata = true;
        let mut wire = datagram([192, 0, 2, 1], b"quic");
        // PROXY protocol §2.2.7: one TLV of type 0xEA after the address block.
        wire.splice(wire.len() - 4..wire.len() - 4, [0xEA, 0, 1, 7]);
        wire[15] = 16;
        let mut meta = meta(wire.len(), wire.len());
        let mut fixture = Fixture::default();
        fixture.accept(&config, &mut wire, &mut meta);
        let client = "192.0.2.1:12345".parse().unwrap();
        let mut tlv = String::new();
        let route =
            fixture
                .routes
                .sessions
                .as_mut()
                .unwrap()
                .lookup(client, Instant::now(), TTL, &mut tlv);
        assert_eq!(route, Some(proxy(5000)));
        assert_eq!(tlv, "ea000107");
    }

    // A live route belongs to the proxy that opened it, so a second proxy cannot take over the client.
    #[test]
    fn another_proxy_cannot_claim_a_client_with_a_live_route() {
        let mut fixture = Fixture::default();
        let mut wire = datagram([192, 0, 2, 1], b"one");
        let mut owner = meta(wire.len(), wire.len());
        fixture.accept(&use_all(), &mut wire, &mut owner);
        assert_eq!(&wire[..owner.len], b"one");
        let mut wire = datagram([192, 0, 2, 1], b"two");
        let mut thief = RecvMeta {
            addr: proxy(6000),
            ..meta(wire.len(), wire.len())
        };
        fixture.accept(&use_all(), &mut wire, &mut thief);
        assert_eq!(thief.len, 0);
        let mut wire = datagram([192, 0, 2, 1], b"three");
        let mut again = meta(wire.len(), wire.len());
        fixture.accept(&use_all(), &mut wire, &mut again);
        assert_eq!(&wire[..again.len], b"three");
    }
}
