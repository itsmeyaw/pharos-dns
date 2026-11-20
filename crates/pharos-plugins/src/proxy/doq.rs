//! DNS-over-QUIC Upstream (RFC 9250): one QUIC connection shared by every Query, one stream each.
//!
//! The connection is dialed on first use and replaced when it closes, idles past `expire` or
//! outlives `max_age`. Queries in flight keep a replaced connection alive until they finish.

use pharos_server::{
    doq_client::{DoqClient, DoqConnection, DoqError},
    metrics::ProxyConnectionCache,
};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, OnceLock, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{sync::watch, time::timeout};

use super::{Error, Tls};

// CoreDNS v1.15.0 plugin/pkg/proxy/doq.go: doqDialTimeout bounds the QUIC handshake.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
// CoreDNS v1.15.0 plugin/pkg/proxy/doq.go: doqDefaultIdleTimeout is the floor of the QUIC idle timeout.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
struct Settings {
    expire: Duration,
    max_age: Duration,
    read_timeout: Duration,
    source: Option<IpAddr>,
}

struct Slot {
    connection: DoqConnection,
    created: Instant,
    /// Nanoseconds from `created` to the last time a Query finished on this connection.
    used: AtomicU64,
    active: AtomicUsize,
}

impl Slot {
    fn idle(&self) -> Duration {
        self.created
            .elapsed()
            .saturating_sub(Duration::from_nanos(self.used.load(Ordering::Relaxed)))
    }
}

/// One Query's claim on a connection; dropping it records the connection's last use.
struct Lease(Arc<Slot>);

impl Drop for Lease {
    fn drop(&mut self) {
        let used = u64::try_from(self.0.created.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.0.used.store(used, Ordering::Relaxed);
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// What a DoQ exchange produced.
pub struct Reply {
    pub len: usize,
    pub local_addr: SocketAddr,
}

/// The shared DoQ connection of one Upstream.
pub struct Doq {
    address: SocketAddr,
    tls: Tls,
    settings: RwLock<Settings>,
    current: Mutex<Option<Arc<Slot>>>,
    /// The client socket, created at the first dial; holding the lock is the dial in progress.
    client: tokio::sync::Mutex<Option<DoqClient>>,
    stop: watch::Sender<bool>,
    stopped: AtomicBool,
    cache: OnceLock<ProxyConnectionCache>,
}

impl Doq {
    /// Prepare an Upstream at `address` whose certificate must match `tls.server_name`.
    #[must_use]
    pub fn new(address: SocketAddr, tls: Tls) -> Arc<Self> {
        Arc::new(Self {
            address,
            tls,
            settings: RwLock::new(Settings {
                expire: super::EXPIRE,
                max_age: Duration::ZERO,
                read_timeout: super::READ_TIMEOUT,
                source: None,
            }),
            current: Mutex::new(None),
            client: tokio::sync::Mutex::new(None),
            stop: watch::channel(false).0,
            stopped: AtomicBool::new(false),
            cache: OnceLock::new(),
        })
    }

    fn update(&self, change: impl FnOnce(&mut Settings)) {
        change(&mut self.settings.write().unwrap());
    }

    /// Set how long an idle connection lives.
    pub fn set_expire(&self, expire: Duration) {
        self.update(|settings| settings.expire = expire);
    }

    /// Set the maximum connection age; zero means unlimited.
    pub fn set_max_age(&self, max_age: Duration) {
        self.update(|settings| settings.max_age = max_age);
    }

    /// Set how long one Query may wait for its Response.
    pub fn set_read_timeout(&self, read_timeout: Duration) {
        self.update(|settings| settings.read_timeout = read_timeout);
    }

    /// Bind the client socket to this local IP; applies to connections dialed afterwards.
    pub fn set_source_address(&self, source: Option<IpAddr>) {
        self.update(|settings| settings.source = source);
    }

    /// Count connection reuse under `cache`, once.
    pub(super) fn set_cache(&self, cache: ProxyConnectionCache) {
        let _ = self.cache.set(cache);
    }

    /// Close the connection and fail every dial in progress.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.stop.send_replace(true);
        if let Some(slot) = self.current.lock().unwrap().take() {
            slot.connection.close();
        }
        // A dial in progress holds the lock; it notices the stop itself.
        if let Ok(client) = self.client.try_lock()
            && let Some(client) = client.as_ref()
        {
            client.close();
        }
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Claim the current connection unless it ended, idled out or aged out.
    fn reuse(&self, settings: Settings) -> Option<Lease> {
        let mut current = self.current.lock().unwrap();
        let slot = current.as_ref()?;
        // CoreDNS v1.15.0 plugin/pkg/proxy/doq.go cleanup: a dead, expired or too old connection is replaced.
        let idle_out = slot.active.load(Ordering::Relaxed) == 0
            && (settings.expire.is_zero() || slot.idle() >= settings.expire);
        let aged_out = !settings.max_age.is_zero() && slot.created.elapsed() >= settings.max_age;
        if slot.connection.is_closed() || idle_out || aged_out {
            *current = None;
            return None;
        }
        slot.active.fetch_add(1, Ordering::Relaxed);
        Some(Lease(Arc::clone(slot)))
    }

    fn retire(&self, slot: &Arc<Slot>) {
        let mut current = self.current.lock().unwrap();
        if current.as_ref().is_some_and(|c| Arc::ptr_eq(c, slot)) {
            *current = None;
        }
    }

    async fn acquire(&self, settings: Settings) -> Result<(Lease, bool), Error> {
        if self.stopped() {
            return Err(Error::Stopped);
        }
        if let Some(lease) = self.reuse(settings) {
            self.count(true);
            return Ok((lease, true));
        }
        // One Query dials; the rest wait here and then share its connection.
        let mut client = self.client.lock().await;
        if let Some(lease) = self.reuse(settings) {
            self.count(true);
            return Ok((lease, true));
        }
        self.count(false);
        if self.stopped() {
            return Err(Error::Stopped);
        }
        if client.is_none() {
            let idle = DEFAULT_IDLE_TIMEOUT
                .max(settings.expire)
                .max(settings.read_timeout);
            *client = Some(DoqClient::new(
                &self.tls.config,
                settings.source,
                self.address,
                idle,
            )?);
        }
        let client = client.as_ref().expect("created above");
        let name = self.tls.server_name.to_str();
        let mut stop = self.stop.subscribe();
        let connection = tokio::select! {
            biased;
            _ = stop.wait_for(|stopped| *stopped) => return Err(Error::Stopped),
            dialed = timeout(DIAL_TIMEOUT, client.connect(&name)) => {
                dialed.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??
            }
        };
        if self.stopped() {
            connection.close();
            return Err(Error::Stopped);
        }
        let slot = Arc::new(Slot {
            connection,
            created: Instant::now(),
            used: AtomicU64::new(0),
            active: AtomicUsize::new(1),
        });
        *self.current.lock().unwrap() = Some(Arc::clone(&slot));
        Ok((Lease(slot), false))
    }

    fn count(&self, hit: bool) {
        if let Some(cache) = self.cache.get() {
            if hit {
                cache.hit();
            } else {
                cache.miss();
            }
        }
    }

    /// Send `wire[..query_len]` (ID zero) on a new stream and read the Response into `wire`.
    ///
    /// `read_timeout` overrides the configured Response wait.
    pub async fn exchange(
        &self,
        wire: &mut [u8],
        query_len: usize,
        read_timeout: Option<Duration>,
    ) -> Result<Reply, Error> {
        let settings = *self.settings.read().unwrap();
        let (lease, cached) = self.acquire(settings).await?;
        let slot = &lease.0;
        let local_addr = slot.connection.local_addr();
        // CoreDNS v1.15.0 plugin/pkg/proxy/doq.go exchange: one timeout covers opening the stream, writing and reading.
        let result = timeout(
            read_timeout.unwrap_or(settings.read_timeout),
            slot.connection.exchange(wire, query_len),
        )
        .await;
        match result {
            Err(_) => Err(io::Error::from(io::ErrorKind::TimedOut).into()),
            Ok(Ok(len)) => Ok(Reply { len, local_addr }),
            Ok(Err(DoqError::Open(error))) => {
                self.retire(slot);
                // CoreDNS v1.15.0 plugin/forward/forward.go: the peer closed a cached connection before the Query was sent.
                Err(if cached {
                    Error::CachedClosed
                } else {
                    error.into()
                })
            }
            Ok(Err(error @ DoqError::Protocol(_))) => {
                // RFC 9250 §4.3.3: the connection was closed with DOQ_PROTOCOL_ERROR and must not be reused.
                self.retire(slot);
                Err(io::Error::new(io::ErrorKind::InvalidData, error).into())
            }
            Ok(Err(DoqError::Stream(error))) => {
                if slot.connection.is_closed() {
                    self.retire(slot);
                    // The peer closed a reused connection while this Query was starting; Queries are idempotent, so retry.
                    if cached {
                        return Err(Error::CachedClosed);
                    }
                }
                Err(error.into())
            }
        }
    }
}

impl Drop for Doq {
    fn drop(&mut self) {
        self.stop();
    }
}
