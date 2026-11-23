//! A bounded read-through view of the etcd keys the Plugin serves from.
//!
//! CoreDNS v1.15.0 plugin/etcd/etcd.go issues one etcd read for every Query and never watches.
//! Pharos keeps what it read, parsed and with its TTL resolved, and a watch on the key prefix
//! tells it when to forget. The view is exact except for these bounds:
//!
//! - an entry older than [`Limits::max_age`] is read again, because a record TTL derived from a
//!   lease is sampled when the entry is filled;
//! - a write is visible to Queries once its watch event arrives, so a Query that follows a write
//!   by less than the propagation delay may still see the old data (CoreDNS reads etcd every time
//!   and has no such window); a read that races an event is not stored;
//! - while the watch is not established (before the first Query, after an error, until it is
//!   re-established) every Query reads etcd, as CoreDNS does, and the view stores nothing.

use std::{
    collections::HashMap,
    fmt,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::OnceCell,
    task::AbortHandle,
    time::{Instant, sleep, timeout},
};

use super::{
    Config, DEFAULT_MAX_LEASE_TTL, DEFAULT_MIN_LEASE_TTL,
    client::{self, Client, RangeResponse},
    msg::{self, Service},
};

/// CoreDNS v1.15.0 plugin/etcd/etcd.go `defaultPriority`: the priority of a service that sets none.
const DEFAULT_PRIORITY: i64 = 10;

/// CoreDNS v1.15.0 plugin/etcd/etcd.go `defaultTTL`: the TTL of a record when neither the service nor a lease sets one.
const DEFAULT_TTL: u32 = 300;

/// What bounds the view.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Keys the view holds; when it is full, it is emptied and filled again from the Queries that follow.
    // shortcut: clear-on-full instead of LRU, which would take a lock on every hit; switch if a working set larger than this churns.
    pub max_entries: usize,
    /// The bytes of etcd keys and values the held entries come from, in all.
    pub max_bytes: usize,
    /// An entry whose etcd data is larger is served but not held.
    pub max_entry_bytes: usize,
    /// How long an entry is served before etcd is read again.
    pub max_age: Duration,
    /// The wait before the first reconnect of the watch; it doubles up to `reconnect_max`.
    pub reconnect_min: Duration,
    pub reconnect_max: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 4096,
            max_bytes: 32 << 20,
            max_entry_bytes: 1 << 20,
            max_age: Duration::from_secs(5),
            reconnect_min: Duration::from_millis(100),
            reconnect_max: Duration::from_secs(5),
        }
    }
}

/// Why a read produced no records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// CoreDNS v1.15.0 plugin/etcd/etcd.go `errKeyNotFound`: no key under the path, which is NXDOMAIN.
    KeyNotFound,
    Client(client::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyNotFound => f.write_str("key not found"),
            Self::Client(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for Error {}

/// One key under a path, parsed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Record {
    /// A service with its priority and TTL resolved, as CoreDNS `loopNodes` leaves it.
    Service(Service),
    /// The value is not a valid service: serving the key is an error, as in CoreDNS, `error` reads `KEY: REASON`.
    Invalid { key: String, error: String },
}

impl Record {
    #[must_use]
    pub fn key(&self) -> &str {
        match self {
            Self::Service(service) => &service.key,
            Self::Invalid { key, .. } => key,
        }
    }
}

/// What etcd holds under one path, in key order.
///
/// The filter that depends on the Query (CoreDNS `loopNodes` with a wildcard, and `shouldInclude`)
/// is the caller's, so one entry serves every name and type that reads the path.
#[derive(Debug)]
pub struct CachedRecords {
    pub records: Vec<Record>,
}

type Outcome = Result<Arc<CachedRecords>, Error>;

/// Reads in flight, by path and whether the read is recursive; the cell holds the result once it is in.
type Inflight = Mutex<HashMap<(String, bool), Arc<OnceCell<Outcome>>>>;

struct Entry {
    outcome: Outcome,
    filled: Instant,
    bytes: usize,
}

/// Entries by path, for an exact read (`0`) and a recursive one (`1`).
#[derive(Default)]
struct Cache {
    maps: [HashMap<Box<str>, Entry>; 2],
    bytes: usize,
}

impl Cache {
    fn len(&self) -> usize {
        self.maps[0].len() + self.maps[1].len()
    }

    fn clear(&mut self) {
        self.maps.iter_mut().for_each(HashMap::clear);
        self.bytes = 0;
    }
}

struct Fetched {
    outcome: Outcome,
    /// Whether the result may be stored: an error of the client or a failed lease lookup may not.
    cacheable: bool,
    bytes: usize,
}

struct Inner {
    client: Client,
    path_prefix: String,
    min_lease_ttl: u32,
    max_lease_ttl: u32,
    limits: Limits,
    cache: RwLock<Cache>,
    /// Changes whenever the cache is emptied; a read stores its result only if it did not change meanwhile.
    generation: AtomicU64,
    /// Whether the watch is established; the cache is used only then.
    healthy: AtomicBool,
    started: AtomicBool,
    stopped: AtomicBool,
    watch_task: Mutex<Option<AbortHandle>>,
    inflight: Inflight,
}

/// The view of one `etcd` Directive.
pub struct View {
    inner: Arc<Inner>,
}

impl fmt::Debug for View {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("View").finish_non_exhaustive()
    }
}

impl Drop for View {
    fn drop(&mut self) {
        self.stop();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl View {
    #[must_use]
    pub fn new(config: &Config) -> Self {
        Self::with(config, Client::new(config), Limits::default())
    }

    #[must_use]
    pub fn with(config: &Config, client: Client, limits: Limits) -> Self {
        Self {
            inner: Arc::new(Inner {
                client,
                path_prefix: config.path_prefix.clone(),
                min_lease_ttl: config.min_lease_ttl,
                max_lease_ttl: config.max_lease_ttl,
                limits,
                cache: RwLock::default(),
                generation: AtomicU64::new(0),
                healthy: AtomicBool::new(false),
                started: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
                watch_task: Mutex::new(None),
                inflight: Mutex::default(),
            }),
        }
    }

    /// The records under `path`, read as CoreDNS v1.15.0 plugin/etcd/etcd.go `get` does: with
    /// `recursive` the keys under `path/`, else (or when there are none) the key `path` alone.
    ///
    /// # Errors
    ///
    /// [`Error::KeyNotFound`] when etcd holds nothing there, [`Error::Client`] when it could not be read.
    pub async fn get(&self, path: &str, recursive: bool) -> Result<Arc<CachedRecords>, Error> {
        self.start_watch();
        let inner = &self.inner;
        if !inner.healthy.load(Ordering::Acquire) {
            return inner.fetch(path, recursive).await.outcome;
        }
        if let Some(outcome) = inner.lookup(path, recursive) {
            return outcome;
        }
        inner.fill(path, recursive).await
    }

    /// Close the etcd connections and stop the watch.
    pub fn stop(&self) {
        let inner = &self.inner;
        inner.stopped.store(true, Ordering::Release);
        if let Some(task) = lock(&inner.watch_task).take() {
            task.abort();
        }
        inner.client.stop();
        inner.reset(Some(false));
    }

    /// Whether the watch is established, so reads are served from the view.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.inner.healthy.load(Ordering::Acquire)
    }

    /// Entries held now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .cache
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Start the watch on the first Query: setup runs without a runtime and connects to nothing.
    fn start_watch(&self) {
        let inner = &self.inner;
        if inner.started.swap(true, Ordering::AcqRel) || inner.stopped.load(Ordering::Acquire) {
            return;
        }
        let task = tokio::spawn(watch_loop(inner.clone()));
        *lock(&inner.watch_task) = Some(task.abort_handle());
        if inner.stopped.load(Ordering::Acquire) {
            task.abort();
        }
    }
}

impl Inner {
    fn lookup(&self, path: &str, recursive: bool) -> Option<Outcome> {
        let cache = self.cache.read().unwrap_or_else(PoisonError::into_inner);
        let entry = cache.maps[usize::from(recursive)].get(path)?;
        (entry.filled.elapsed() < self.limits.max_age).then(|| entry.outcome.clone())
    }

    /// Read `path` from etcd once for every Query that misses it meanwhile, and store the result.
    async fn fill(&self, path: &str, recursive: bool) -> Outcome {
        let key = (path.to_owned(), recursive);
        let cell = Arc::clone(lock(&self.inflight).entry(key.clone()).or_default());
        let _slot = Slot {
            inflight: &self.inflight,
            key,
            cell: &cell,
        };
        cell.get_or_init(|| async {
            let generation = self.generation.load(Ordering::Acquire);
            let fetched = self.fetch(path, recursive).await;
            if fetched.cacheable {
                self.store(generation, path, recursive, &fetched);
            }
            fetched.outcome
        })
        .await
        .clone()
    }

    /// Hold `fetched` unless the cache was emptied since `generation`.
    fn store(&self, generation: u64, path: &str, recursive: bool, fetched: &Fetched) {
        if fetched.bytes > self.limits.max_entry_bytes {
            return;
        }
        let mut cache = self.cache.write().unwrap_or_else(PoisonError::into_inner);
        // The generation and the health are read under the lock that every invalidation holds, so no event slips between check and insert.
        if self.generation.load(Ordering::Acquire) != generation
            || !self.healthy.load(Ordering::Acquire)
        {
            return;
        }
        if cache.len() >= self.limits.max_entries
            || cache.bytes + fetched.bytes > self.limits.max_bytes
        {
            cache.clear();
        }
        let entry = Entry {
            outcome: fetched.outcome.clone(),
            filled: Instant::now(),
            bytes: fetched.bytes,
        };
        if let Some(old) = cache.maps[usize::from(recursive)].insert(path.into(), entry) {
            cache.bytes -= old.bytes;
        }
        cache.bytes += fetched.bytes;
    }

    /// Empty the cache and make reads that are in flight unfit to store; `healthy`, when given, is the state afterwards.
    fn reset(&self, healthy: Option<bool>) {
        let mut cache = self.cache.write().unwrap_or_else(PoisonError::into_inner);
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Some(healthy) = healthy {
            // A watch task that ran past `stop` must not make the view healthy again.
            self.healthy.store(
                healthy && !self.stopped.load(Ordering::Acquire),
                Ordering::Release,
            );
        }
        cache.clear();
    }

    /// CoreDNS v1.15.0 plugin/etcd/etcd.go `get`, then `loopNodes` for every key found.
    async fn fetch(&self, path: &str, recursive: bool) -> Fetched {
        let failed = |error: Error| Fetched {
            cacheable: error == Error::KeyNotFound,
            outcome: Err(error),
            bytes: path.len(),
        };
        // CoreDNS v1.15.0 plugin/etcd/etcd.go `get`: one `etcdTimeout` covers the reads of a path, and here the lease lookups too.
        let fill = async {
            let reply = self.read(path, recursive).await?;
            Ok(self.records(reply).await)
        };
        match timeout(self.client.timeouts().call, fill).await {
            Ok(Ok(fetched)) => fetched,
            Ok(Err(error)) => failed(error),
            Err(_) => failed(Error::Client(client::Error::Timeout)),
        }
    }

    async fn read(&self, path: &str, recursive: bool) -> Result<RangeResponse, Error> {
        let found = |reply: RangeResponse| {
            if reply.count == 0 {
                Err(Error::KeyNotFound)
            } else {
                Ok(reply)
            }
        };
        if recursive {
            // CoreDNS v1.15.0 plugin/etcd/etcd.go `get`: a recursive read lists the keys under `path/`.
            let prefix = if path.ends_with('/') {
                path.to_owned()
            } else {
                format!("{path}/")
            };
            let reply = self
                .client
                .range(prefix.as_bytes(), true)
                .await
                .map_err(Error::Client)?;
            if reply.count != 0 {
                return Ok(reply);
            }
            // CoreDNS v1.15.0 plugin/etcd/etcd.go `get`: with none, the key itself, without the trailing slash.
            let exact = prefix.strip_suffix('/').unwrap_or(&prefix);
            let reply = self
                .client
                .range(exact.as_bytes(), false)
                .await
                .map_err(Error::Client)?;
            return found(reply);
        }
        let reply = self
            .client
            .range(path.as_bytes(), false)
            .await
            .map_err(Error::Client)?;
        found(reply)
    }

    async fn records(&self, reply: RangeResponse) -> Fetched {
        let mut bytes = 0;
        let mut cacheable = true;
        // CoreDNS asks etcd once for every key with a lease; keys that share one need a single answer here.
        let mut leases: Vec<(i64, Option<i64>)> = Vec::new();
        let mut records = Vec::with_capacity(reply.kvs.len());
        for kv in &reply.kvs {
            bytes += kv.key.len() + kv.value.len();
            let key = String::from_utf8_lossy(&kv.key).into_owned();
            let mut service = match Service::from_json(&key, &kv.value) {
                Ok(service) => service,
                Err(error) => {
                    records.push(Record::Invalid {
                        key,
                        error: error.to_string(),
                    });
                    continue;
                }
            };
            let lease_ttl = if kv.lease == 0 {
                None
            } else if let Some((_, ttl)) = leases.iter().find(|(id, _)| *id == kv.lease) {
                *ttl
            } else {
                // CoreDNS v1.15.0 plugin/etcd/etcd.go `TTL`: a failed lookup leaves the lease out of the TTL.
                let ttl = self.client.lease_ttl(kv.lease).await.ok();
                cacheable &= ttl.is_some();
                leases.push((kv.lease, ttl));
                ttl
            };
            service.ttl = record_ttl(
                lease_ttl,
                service.ttl,
                self.min_lease_ttl,
                self.max_lease_ttl,
            );
            // CoreDNS v1.15.0 plugin/etcd/etcd.go `loopNodes`: a priority of zero is the default.
            if service.priority == 0 {
                service.priority = DEFAULT_PRIORITY;
            }
            records.push(Record::Service(service));
        }
        Fetched {
            outcome: Ok(Arc::new(CachedRecords { records })),
            cacheable,
            bytes,
        }
    }
}

/// Takes the in-flight slot of a read back when its last waiter is done or gone.
struct Slot<'a> {
    inflight: &'a Inflight,
    key: (String, bool),
    cell: &'a Arc<OnceCell<Outcome>>,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut inflight = lock(self.inflight);
        if inflight
            .get(&self.key)
            .is_some_and(|cell| Arc::ptr_eq(cell, self.cell))
        {
            inflight.remove(&self.key);
        }
    }
}

/// CoreDNS v1.15.0 plugin/etcd/etcd.go `TTL`: the smaller of the lease TTL, held within
/// `[min, max]`, and the service's own, with 300 when neither is set.
fn record_ttl(lease_ttl: Option<i64>, service_ttl: u32, min: u32, max: u32) -> u32 {
    let min = i64::from(if min == 0 { DEFAULT_MIN_LEASE_TTL } else { min });
    let max = i64::from(if max == 0 { DEFAULT_MAX_LEASE_TTL } else { max });
    let lease_ttl = match lease_ttl {
        // CoreDNS v1.15.0 plugin/etcd/etcd.go `TTL`: only a lease with time left counts, and `else if` keeps the minimum when it exceeds the maximum.
        Some(ttl) if ttl > 0 => {
            if ttl < min {
                min
            } else if ttl > max {
                max
            } else {
                ttl
            }
        }
        _ => 0,
    } as u32;
    match (lease_ttl, service_ttl) {
        (0, 0) => DEFAULT_TTL,
        (0, ttl) | (ttl, 0) => ttl,
        (lease, service) => lease.min(service),
    }
}

/// Watch the keys under the Directive's path and keep the cache true to them.
async fn watch_loop(inner: Arc<Inner>) {
    // The path of the zone root is the key of the prefix itself, so the watch starts there.
    let key = msg::path(".", &inner.path_prefix);
    let mut delay = inner.limits.reconnect_min;
    loop {
        if watch_once(&inner, key.as_bytes()).await {
            delay = inner.limits.reconnect_min;
        }
        // The watch is gone, so events may be missed from here until a new one is established.
        inner.reset(Some(false));
        sleep(delay).await;
        delay = (delay * 2).min(inner.limits.reconnect_max);
    }
}

/// One watch stream, to its end; whether it got as far as being established.
async fn watch_once(inner: &Inner, key: &[u8]) -> bool {
    let Ok(mut watch) = inner.client.watch(key, true).await else {
        return false;
    };
    let mut established = false;
    loop {
        let Ok(Some(response)) = watch.next().await else {
            return established;
        };
        // etcd v3 rpc.proto WatchResponse: `created` acknowledges the watcher, so later events are seen.
        if response.created && !established {
            established = true;
            inner.reset(Some(true));
        }
        // etcd v3 rpc.proto WatchResponse: a canceled watcher or one behind a compaction gets no more events.
        if response.canceled || response.compact_revision != 0 {
            return established;
        }
        if !response.events.is_empty() {
            inner.reset(None);
        }
    }
}

#[cfg(test)]
mod tests;
