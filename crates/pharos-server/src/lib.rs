#![forbid(unsafe_code)]
//! Plugin Chain contract. A Plugin returns an Outcome rather than writing to a
//! Listener; earlier Plugins may inspect and modify the caller-owned Response
//! buffer after awaiting Next. The Listener handles unanswered codes and errors.

use std::{
    any::Any,
    collections::{HashMap, HashSet},
    fmt,
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use pharos_proto::{BuildError, Message, Name, Rcode, Type};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::watch,
    task::JoinHandle,
};

mod admission;
pub mod http;
mod lifecycle;
pub mod logging;
pub mod metrics;
mod outcome;
mod panic;
mod process_metrics;
mod quota;
pub use admission::{Admission, admit};
pub use lifecycle::{Lifecycle, Phase};
pub use outcome::{finish_outcome, response_limit};
pub use panic::{contain_panic, panics_total};
mod router;
mod server;
mod shed;
mod startup;
pub use router::{Router, ServerBlock, ViewFilter};
pub use server::{Chain, Server};
pub use startup::startup_domains;
mod tcp;
mod udp;
#[cfg(target_os = "linux")]
mod udp_linux;

/// A statically dispatched continuation of the Plugin Chain.
pub trait Next {
    fn run(self, cx: &mut Context<'_, '_>) -> impl Future<Output = Outcome> + Send;
}

/// A Plugin may await Next and inspect or modify its outcome and Response.
pub trait Plugin {
    fn serve<N: Next + Send>(
        &self,
        cx: &mut Context<'_, '_>,
        next: N,
    ) -> impl Future<Output = Outcome> + Send;

    /// Return a readiness check when this Plugin participates in readiness.
    fn readiness(&self) -> Option<&dyn Readiness> {
        None
    }
}

/// A Plugin's readiness, evaluated outside the Query hot path.
pub trait Readiness: Send + Sync {
    fn ready(&self) -> bool;
}

/// Transport named by a Server Block Key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Transport {
    Dns,
    Tls,
    Quic,
    Grpc,
    Https,
    Https3,
}

/// Protocol used by a Query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Udp,
    Tcp,
}

/// A placeholder for a future Zone Transfer stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stream;

/// Explicit result of running a Plugin Chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Response,
    Stream(Stream),
    Drop,
    Unanswered(Rcode),
    Error(Error),
}

/// Errors for the Listener to log and answer with SERVFAIL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Build(BuildError),
    InvalidQuery,
    ResponseBufferTooSmall,
    NotImplemented,
    NoNextPlugin,
    PluginPanic,
    SelfLookupDepth,
    SelfLookupUnavailable,
    SelfLookupDropped,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(error) => write!(f, "{error}"),
            Self::InvalidQuery => f.write_str("invalid Query"),
            Self::ResponseBufferTooSmall => f.write_str("Response buffer too small"),
            Self::NotImplemented => f.write_str("plugin is not implemented"),
            Self::NoNextPlugin => f.write_str("no next plugin found"),
            Self::PluginPanic => f.write_str("plugin panicked"),
            Self::SelfLookupDepth => f.write_str("Self Lookup depth exceeded"),
            Self::SelfLookupUnavailable => f.write_str("no Server available for Self Lookup"),
            Self::SelfLookupDropped => f.write_str("Self Lookup produced no Response"),
        }
    }
}

impl std::error::Error for Error {}

/// Caller-provided, fixed-capacity Metadata slots.
pub struct Metadata<'a> {
    slots: &'a mut [Option<(&'a str, &'a str)>],
    inline_name: Option<&'static str>,
    inline_value: [u8; 64],
    inline_len: usize,
    // shortcut: 12 copied labels and 1 KiB suffice for Kubernetes; expand for more providers.
    copied: [Option<(&'static str, usize, usize)>; 12],
    copied_data: [u8; 1024],
    copied_len: usize,
    source: Option<Arc<dyn MetadataSource>>,
    enabled: bool,
    self_lookup: Option<SelfLookupState<'a>>,
}

impl<'a> Metadata<'a> {
    pub fn new(slots: &'a mut [Option<(&'a str, &'a str)>]) -> Self {
        Self {
            slots,
            inline_name: None,
            inline_value: [0; 64],
            inline_len: 0,
            copied: [None; 12],
            copied_data: [0; 1024],
            copied_len: 0,
            source: None,
            enabled: true,
            self_lookup: None,
        }
    }

    /// Retain an existing shared source of Metadata without allocating per Query.
    pub fn set_source(&mut self, source: Arc<dyn MetadataSource>) {
        self.source = Some(source);
    }

    /// Enable public Plugin Metadata for the current Server Block.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Construct fresh Metadata while retaining detached Self Lookup routing.
    pub fn with_self_lookup(
        slots: &'a mut [Option<(&'a str, &'a str)>],
        handle: Option<&'a SelfLookupHandle>,
    ) -> Self {
        let mut metadata = Self::new(slots);
        metadata.self_lookup = handle.map(|handle| SelfLookupState {
            server: handle,
            depth: handle.depth,
            siit: handle.siit,
            autopath: handle.autopath,
        });
        metadata
    }

    /// Insert or replace a named value; returns false when no slot is free.
    pub fn insert(&mut self, name: &'a str, value: &'a str) -> bool {
        let slot = self
            .slots
            .iter()
            .position(|slot| slot.is_some_and(|(existing, _)| existing == name))
            .or_else(|| self.slots.iter().position(Option::is_none));
        let Some(slot) = slot else { return false };
        self.remove_copied(name);
        if self.inline_name == Some(name) {
            self.inline_name = None;
        }
        self.slots[slot] = Some((name, value));
        true
    }

    /// Copy a short value whose lifetime is shorter than the Query's.
    pub fn insert_inline(&mut self, name: &'static str, value: &str) -> bool {
        if value.len() > self.inline_value.len()
            || self.inline_name.is_some_and(|existing| existing != name)
        {
            return false;
        }
        self.remove_copied(name);
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|(key, _)| key == name) {
                *slot = None;
            }
        }
        // shortcut: one copied value suffices for forward; add slots for other producers.
        self.inline_name = Some(name);
        self.inline_len = value.len();
        self.inline_value[..value.len()].copy_from_slice(value.as_bytes());
        true
    }

    /// Copy a value from a temporary Plugin buffer without allocating.
    pub fn insert_copied(&mut self, name: &'static str, value: &str) -> bool {
        let previous = self
            .copied
            .iter()
            .flatten()
            .find(|(key, _, _)| *key == name)
            .map_or(0, |(_, start, end)| end - start);
        if value.len() > self.copied_data.len() - (self.copied_len - previous) {
            return false;
        }
        let Some(index) = self
            .copied
            .iter()
            .position(|slot| slot.is_none_or(|(key, _, _)| key == name))
        else {
            return false;
        };
        self.remove_copied(name);
        if self.inline_name == Some(name) {
            self.inline_name = None;
        }
        for slot in self.slots.iter_mut() {
            if slot.is_some_and(|(key, _)| key == name) {
                *slot = None;
            }
        }
        let end = self.copied_len + value.len();
        self.copied_data[self.copied_len..end].copy_from_slice(value.as_bytes());
        self.copied[index] = Some((name, self.copied_len, end));
        self.copied_len = end;
        true
    }

    fn remove_copied(&mut self, name: &str) {
        let Some(index) = self
            .copied
            .iter()
            .position(|slot| slot.is_some_and(|(key, _, _)| key == name))
        else {
            return;
        };
        let (_, start, end) = self.copied[index].take().unwrap();
        self.copied_data.copy_within(end..self.copied_len, start);
        self.copied_len -= end - start;
        for (_, other_start, other_end) in self.copied.iter_mut().flatten() {
            if *other_start >= end {
                *other_start -= end - start;
                *other_end -= end - start;
            }
        }
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        if let Some((_, start, end)) = self
            .copied
            .iter()
            .flatten()
            .find(|(key, _, _)| *key == name)
        {
            return std::str::from_utf8(&self.copied_data[*start..*end]).ok();
        }
        if self.inline_name == Some(name) {
            return std::str::from_utf8(&self.inline_value[..self.inline_len]).ok();
        }
        self.slots
            .iter()
            .flatten()
            .find_map(|(key, value)| (*key == name).then_some(*value))
            .or_else(|| self.source.as_ref().and_then(|source| source.get(name)))
    }
}

/// A shared source whose values remain valid for a Query.
pub trait MetadataSource: Send + Sync {
    fn get(&self, label: &str) -> Option<&str>;
}

/// Borrowed Query state and reusable, preallocated Response buffer.
pub struct Context<'q, 'a> {
    pub query: Message<'q>,
    pub client: SocketAddr,
    /// Listener address; wildcard addresses are not resolved per Query.
    pub local: SocketAddr,
    pub transport: Transport,
    pub protocol: Protocol,
    pub domain: &'q Name,
    pub metadata: Metadata<'a>,
    pub response: &'q mut Vec<u8>,
    pub max_response_size: usize,
}

struct NestedContext<'s, 'q, 'a> {
    parent_query: &'s mut Message<'q>,
    parent_metadata: &'s mut Metadata<'a>,
    child: Context<'s, 'a>,
}

struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Drop for NestedContext<'_, '_, '_> {
    fn drop(&mut self) {
        let mut query = self.parent_query.with_flags(self.child.query.flags());
        if let (Some(parent), Some(child)) = (
            self.parent_query.questions().next(),
            self.child.query.questions().next(),
        ) {
            if !parent.name.labels().eq(child.name.labels()) {
                query = query.with_question_name(child.name);
            }
            if parent.qtype != child.qtype {
                query = query.with_question_type(child.qtype);
            }
            if parent.qclass != child.qclass {
                query = query.with_question_class(child.qclass);
            }
        }
        if let Some(opt) = self.child.query.opt() {
            query = query.with_udp_payload_limit(opt.udp_payload_size());
        }
        *self.parent_query = query;
        std::mem::swap(self.parent_metadata, &mut self.child.metadata);
    }
}

/// The Listener state and depth associated with a Query.
struct SelfLookupState<'a> {
    server: &'a dyn SelfLookupServer,
    depth: u8,
    siit: bool,
    autopath: bool,
}

// Type erasure keeps Context nongeneric without allocating on ordinary Queries.
trait SelfLookupServer: Sync {
    fn lookup<'a>(
        &'a self,
        wire: &'a [u8],
        peer: SocketAddr,
        protocol: Protocol,
        depth: u8,
        flags: (bool, bool),
        response: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Action> + Send + 'a>>;

    fn owned(&self) -> Option<Arc<dyn OwnedSelfLookupServer>> {
        None
    }
}

trait OwnedSelfLookupServer: Send + Sync {
    fn lookup<'a>(
        self: Arc<Self>,
        wire: &'a [u8],
        peer: SocketAddr,
        protocol: Protocol,
        depth: u8,
        flags: (bool, bool),
        response: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Action> + Send + 'a>>;
}

/// Owned Listener state for a detached Query, including its Self Lookup depth.
pub struct SelfLookupHandle {
    server: Arc<dyn OwnedSelfLookupServer>,
    depth: u8,
    siit: bool,
    autopath: bool,
}

impl SelfLookupServer for SelfLookupHandle {
    fn lookup<'a>(
        &'a self,
        wire: &'a [u8],
        peer: SocketAddr,
        protocol: Protocol,
        depth: u8,
        flags: (bool, bool),
        response: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Action> + Send + 'a>> {
        Arc::clone(&self.server).lookup(wire, peer, protocol, depth, flags, response)
    }

    fn owned(&self) -> Option<Arc<dyn OwnedSelfLookupServer>> {
        Some(Arc::clone(&self.server))
    }
}

impl Context<'_, '_> {
    /// Return the nesting depth of this Query's Self Lookup, or zero for an external Query.
    #[must_use]
    pub fn self_lookup_depth(&self) -> u8 {
        self.metadata
            .self_lookup
            .as_ref()
            .map_or(0, |state| state.depth)
    }

    /// Run Next with temporary Query bytes while preserving Metadata and Response state.
    pub async fn run_with_query<N: Next + Send>(&mut self, wire: &[u8], next: N) -> Outcome {
        let Ok(query) = Message::parse(wire) else {
            return Outcome::Error(Error::InvalidQuery);
        };
        self.run_with_message(query, next).await
    }

    /// Run Next with a modified Query view while preserving Metadata and Response state.
    pub async fn run_with_message<N: Next + Send>(
        &mut self,
        query: Message<'_>,
        next: N,
    ) -> Outcome {
        let metadata = std::mem::replace(&mut self.metadata, Metadata::new(&mut []));
        let mut nested = NestedContext {
            parent_query: &mut self.query,
            parent_metadata: &mut self.metadata,
            child: Context {
                query,
                client: self.client,
                local: self.local,
                transport: self.transport,
                protocol: self.protocol,
                domain: self.domain,
                metadata,
                response: self.response,
                max_response_size: self.max_response_size,
            },
        };
        next.run(&mut nested.child).await
    }
    /// Retain this Query's Listener state for a detached task, if available.
    pub fn self_lookup_handle(&self) -> Option<SelfLookupHandle> {
        let state = self.metadata.self_lookup.as_ref()?;
        Some(SelfLookupHandle {
            server: state.server.owned()?,
            depth: state.depth,
            siit: state.siit,
            autopath: state.autopath,
        })
    }

    /// Route a new Query through this Query's Listener and capture its Response.
    pub async fn self_lookup(&self, name: &Name, qtype: Type) -> Result<Vec<u8>, Error> {
        self.self_lookup_inner(self.query, name, qtype, false, false)
            .await
    }

    /// Route a Self Lookup using a temporary Query's fields and options.
    pub async fn self_lookup_with_query(
        &self,
        query: Message<'_>,
        name: &Name,
        qtype: Type,
    ) -> Result<Vec<u8>, Error> {
        self.self_lookup_inner(query, name, qtype, false, false)
            .await
    }

    /// Re-enter for SIIT synthesis, preventing recursive SIIT interception.
    pub async fn siit_lookup(&self, name: &Name, qtype: Type) -> Result<Vec<u8>, Error> {
        self.self_lookup_inner(self.query, name, qtype, true, false)
            .await
    }

    /// Re-enter for search-path completion without recursively restarting it.
    pub async fn autopath_lookup(&self, name: &Name, qtype: Type) -> Result<Vec<u8>, Error> {
        self.self_lookup_inner(self.query, name, qtype, false, true)
            .await
    }

    /// Whether this Query descends from a search-path lookup.
    pub fn autopath_lookup_active(&self) -> bool {
        self.metadata
            .self_lookup
            .as_ref()
            .is_some_and(|state| state.autopath)
    }

    /// Whether this Query descends from a SIIT synthesis lookup.
    pub fn siit_lookup_active(&self) -> bool {
        self.metadata
            .self_lookup
            .as_ref()
            .is_some_and(|state| state.siit)
    }

    async fn self_lookup_inner(
        &self,
        source: Message<'_>,
        name: &Name,
        qtype: Type,
        siit: bool,
        autopath: bool,
    ) -> Result<Vec<u8>, Error> {
        let state = self
            .metadata
            .self_lookup
            .as_ref()
            .ok_or(Error::SelfLookupUnavailable)?;
        if state.depth >= 10 {
            return Err(Error::SelfLookupDepth);
        }
        let query = source.with_question(name, qtype).map_err(Error::Build)?;
        if let Some(server) = state.server.owned()
            && tokio::runtime::Handle::try_current().is_ok()
        {
            let peer = self.client;
            let protocol = self.protocol;
            let depth = state.depth + 1;
            let siit = siit || state.siit;
            let autopath = autopath || state.autopath;
            // shortcut: Self Lookup spawns an allocated task to bound recursive stack use; remove with #86.
            let mut task = AbortOnDrop(tokio::spawn(async move {
                let mut response = Vec::with_capacity(usize::from(u16::MAX));
                let action = server
                    .lookup(
                        &query,
                        peer,
                        protocol,
                        depth,
                        (siit, autopath),
                        &mut response,
                    )
                    .await;
                (action, response)
            }));
            return match (&mut task.0).await {
                Ok((Action::Respond, response)) => Ok(response),
                Ok((Action::Drop, _)) => Err(Error::SelfLookupDropped),
                Err(_) => Err(Error::PluginPanic),
            };
        }
        let mut response = Vec::with_capacity(usize::from(u16::MAX));
        match state
            .server
            .lookup(
                &query,
                self.client,
                self.protocol,
                state.depth + 1,
                (siit || state.siit, autopath || state.autopath),
                &mut response,
            )
            .await
        {
            Action::Respond => Ok(response),
            Action::Drop => Err(Error::SelfLookupDropped),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ListenerKey {
    pub transport: Transport,
    pub address: SocketAddr,
}

fn canonical_peer(mut peer: SocketAddr) -> SocketAddr {
    let ip = peer.ip().to_canonical();
    if ip != peer.ip() {
        peer.set_ip(ip);
    }
    peer
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Respond,
    Drop,
}

/// TCP connection limits selected by the Listener configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpOptions {
    pub read: std::time::Duration,
    pub write: std::time::Duration,
    pub idle: std::time::Duration,
    pub max_queries: Option<usize>,
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            read: std::time::Duration::from_secs(3),
            write: std::time::Duration::from_secs(5),
            idle: std::time::Duration::from_secs(10),
            max_queries: None,
        }
    }
}

/// Async, statically dispatched Query handling. Clear and reuse the supplied
/// Response buffer; return `Drop` to suppress a Response.
/// Handlers must not block the runtime; TCP Queries on a connection may run
/// concurrently.
pub trait Handler: Send + Sync + 'static {
    fn shed_metrics(&self) -> Option<metrics::ShedMetrics> {
        None
    }
    fn shed_query(&self, _query: &[u8], _peer: SocketAddr) -> bool {
        false
    }
    fn tcp_options(&self) -> TcpOptions {
        TcpOptions::default()
    }
    /// Number of UDP worker sockets for this Listener.
    fn udp_workers(&self) -> usize {
        quota::worker_count()
    }
    /// Whether this HINFO Query must run concurrently with UDP reception.
    fn parallel_query(&self, _query: &[u8], _peer: SocketAddr) -> Option<watch::Receiver<bool>> {
        None
    }
    fn handle(
        &self,
        query: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> impl Future<Output = Action> + Send;

    /// Handle a Query while retaining access to the Listener's owned state.
    fn handle_shared(
        self: &Arc<Self>,
        query: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> impl Future<Output = Action> + Send {
        self.handle(query, peer, protocol, response)
    }
}

/// A DNS Listener serving UDP and TCP on the same address.
pub struct Listener {
    address: SocketAddr,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<io::Result<()>>>,
    udp_stop: watch::Sender<bool>,
    udp_tasks: Vec<JoinHandle<io::Result<()>>>,
    shed: bool,
}

impl Listener {
    pub async fn bind<H: Handler>(address: SocketAddr, handler: H) -> io::Result<Self> {
        let workers = handler.udp_workers();
        Self::bind_with_ipv6(address, handler, workers, bind_ipv6_dual, udp::bind).await
    }

    async fn bind_with_ipv6<H: Handler>(
        address: SocketAddr,
        handler: H,
        workers: usize,
        bind_ipv6: fn(SocketAddr) -> io::Result<TcpListener>,
        bind_udp: fn(SocketAddr) -> io::Result<std::net::UdpSocket>,
    ) -> io::Result<Self> {
        let wildcard = address.is_ipv6() && address.ip().is_unspecified();
        let mut ipv4_only = false;
        // Port 0 picks a free TCP port; the same UDP port may be taken, so retry.
        let mut attempts = if address.port() == 0 { 16 } else { 1 };
        // RFC 7766 §5: general-purpose DNS implementations support both UDP and TCP.
        let (tcp, address, sockets) = loop {
            let tcp = if wildcard && !ipv4_only {
                match optional_ipv6(bind_ipv6(address)) {
                    Ok(Some(tcp)) => tcp,
                    Ok(None) => {
                        ipv4_only = true;
                        continue;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse && attempts > 1 => {
                        attempts -= 1;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            } else if ipv4_only {
                TcpListener::bind((Ipv4Addr::UNSPECIFIED, address.port())).await?
            } else {
                TcpListener::bind(address).await?
            };
            let bound = tcp.local_addr()?;
            let sockets = (0..workers)
                .map(|_| bind_udp(bound))
                .collect::<io::Result<Vec<_>>>();
            match sockets {
                Ok(sockets) => break (tcp, bound, sockets),
                Err(error) if wildcard && bound.is_ipv6() && ipv6_unavailable(&error) => {
                    ipv4_only = true;
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse && attempts > 1 => {
                    attempts -= 1;
                }
                Err(error) => return Err(error),
            }
        };
        let (stop, receiver) = watch::channel(false);
        let (udp_stop, udp_receiver) = watch::channel(false);
        let handler = Arc::new(handler);
        let shed = handler.shed_metrics().is_some();
        let udp_tasks = sockets
            .into_iter()
            .map(|socket| {
                let socket = UdpSocket::from_std(socket)?;
                Ok(udp::spawn(
                    socket,
                    Arc::clone(&handler),
                    udp_receiver.clone(),
                ))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let tasks = vec![tcp::spawn(tcp, handler, receiver)];
        Ok(Self {
            address,
            stop,
            tasks,
            udp_stop,
            udp_tasks,
            shed,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Stop accepting Queries and drain for at most five seconds.
    pub async fn shutdown(mut self) -> io::Result<()> {
        self.stop.send_replace(true);
        self.udp_stop.send_replace(true);
        self.tasks.append(&mut self.udp_tasks);
        let mut result = Ok(());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while let Some(mut task) = self.tasks.pop() {
            match tokio::time::timeout_at(deadline, &mut task).await {
                Ok(next) => {
                    let next = next.map_err(io::Error::other).and_then(|v| v);
                    if result.is_ok() {
                        result = next;
                    }
                }
                Err(_) => {
                    task.abort();
                    for task in &self.tasks {
                        task.abort();
                    }
                    let _ = task.await;
                    for task in self.tasks.drain(..) {
                        let _ = task.await;
                    }
                    break;
                }
            }
        }
        result
    }
}

fn bind_ipv6_dual(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

fn optional_ipv6<T>(result: io::Result<T>) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if ipv6_unavailable(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn ipv6_unavailable(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AddrNotAvailable
        || error.raw_os_error() == Some(libc::EAFNOSUPPORT)
}

#[cfg(test)]
mod wildcard_tests {
    use super::{
        Action, Handler, Listener, Protocol, bind_ipv6_dual, canonical_peer, optional_ipv6, udp,
    };
    use std::{
        io,
        net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    };

    #[test]
    fn canonical_peer_preserves_native_ipv6_scope() {
        let scoped = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse::<Ipv6Addr>().unwrap(),
            53,
            7,
            3,
        ));
        assert_eq!(canonical_peer(scoped), scoped);
        assert_eq!(
            canonical_peer("[::ffff:127.0.0.1]:53".parse().unwrap()),
            "127.0.0.1:53".parse().unwrap()
        );
    }

    #[test]
    fn unavailable_ipv6_falls_back_but_other_errors_remain_errors() {
        assert_eq!(
            optional_ipv6::<()>(Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT))).unwrap(),
            None
        );
        assert_eq!(
            optional_ipv6::<()>(Err(io::Error::from(io::ErrorKind::AddrNotAvailable))).unwrap(),
            None
        );
        assert_eq!(optional_ipv6(Ok(7)).unwrap(), Some(7));
        assert!(
            optional_ipv6::<()>(Err(io::Error::new(io::ErrorKind::AddrInUse, "occupied"))).is_err()
        );
    }

    struct Echo;
    impl Handler for Echo {
        async fn handle(
            &self,
            query: &[u8],
            _: SocketAddr,
            _: Protocol,
            response: &mut Vec<u8>,
        ) -> Action {
            response.extend_from_slice(query);
            Action::Respond
        }
    }

    #[tokio::test]
    async fn listener_binds_the_requested_number_of_udp_sockets() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static BINDS: AtomicUsize = AtomicUsize::new(0);
        fn counting_bind(address: SocketAddr) -> io::Result<std::net::UdpSocket> {
            BINDS.fetch_add(1, Ordering::SeqCst);
            udp::bind(address)
        }
        let listener = Listener::bind_with_ipv6(
            "127.0.0.1:0".parse().unwrap(),
            Echo,
            3,
            bind_ipv6_dual,
            counting_bind,
        )
        .await
        .unwrap();
        assert_eq!(BINDS.load(Ordering::SeqCst), 3);
        listener.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn reload_replaces_only_changed_udp_workers_and_keeps_tcp() {
        use std::collections::HashMap;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        struct Counted(usize, u8);
        impl Handler for Counted {
            fn udp_workers(&self) -> usize {
                self.0
            }
            async fn handle(
                &self,
                _: &[u8],
                _: SocketAddr,
                _: Protocol,
                response: &mut Vec<u8>,
            ) -> Action {
                response.push(self.1);
                Action::Respond
            }
        }
        let key = super::ListenerKey {
            transport: super::Transport::Dns,
            address: "127.0.0.1:0".parse().unwrap(),
        };
        let mut registry = super::ListenerRegistry::default();
        registry
            .apply(HashMap::from([(key, Counted(2, 1))]))
            .await
            .unwrap();
        let listener = registry.get(&key).unwrap();
        let address = listener.local_addr();
        let ids: Vec<_> = listener
            .udp_tasks
            .iter()
            .map(tokio::task::JoinHandle::id)
            .collect();
        assert_eq!(ids.len(), 2);
        let mut tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        registry
            .apply(HashMap::from([(key, Counted(2, 2))]))
            .await
            .unwrap();
        assert_eq!(
            registry
                .get(&key)
                .unwrap()
                .udp_tasks
                .iter()
                .map(tokio::task::JoinHandle::id)
                .collect::<Vec<_>>(),
            ids
        );
        registry
            .apply(HashMap::from([(key, Counted(3, 3))]))
            .await
            .unwrap();
        let listener = registry.get(&key).unwrap();
        assert_eq!(listener.local_addr(), address);
        let new_ids: Vec<_> = listener
            .udp_tasks
            .iter()
            .map(tokio::task::JoinHandle::id)
            .collect();
        assert_eq!(new_ids.len(), 3);
        assert!(new_ids.iter().all(|id| !ids.contains(id)));
        tcp.write_all(&[0, 1, 42]).await.unwrap();
        let mut response = [0; 3];
        tcp.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0, 1, 3]);
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(b"q", address).await.unwrap();
        let mut byte = [0];
        tokio::time::timeout(std::time::Duration::from_secs(2), udp.recv(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(byte, [3]);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while registry
                .get(&key)
                .unwrap()
                .tasks
                .iter()
                .skip(1)
                .any(|task| !task.is_finished())
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        registry
            .apply(HashMap::from([(key, Counted(1, 4))]))
            .await
            .unwrap();
        let listener = registry.get(&key).unwrap();
        assert_eq!(listener.udp_tasks.len(), 1);
        assert_eq!(
            listener.tasks.len(),
            4,
            "completed workers should be reaped"
        );
        drop(tcp);
        registry.shutdown().await.unwrap();
    }

    async fn assert_ipv4_fallback(listener: Listener) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        assert!(listener.local_addr().is_ipv4());
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(b"query", ("127.0.0.1", listener.local_addr().port()))
            .await
            .unwrap();
        let mut response = [0; 16];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response[..len], b"query");
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", listener.local_addr().port()))
            .await
            .unwrap();
        tcp.write_u16(5).await.unwrap();
        tcp.write_all(b"query").await.unwrap();
        let len = tokio::time::timeout(std::time::Duration::from_secs(2), tcp.read_u16())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(len, 5);
        let mut response = [0; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            tcp.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&response, b"query");
        drop(tcp);
        listener.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn wildcard_falls_back_to_ipv4_when_ipv6_tcp_is_unavailable() {
        fn unavailable(_: SocketAddr) -> io::Result<tokio::net::TcpListener> {
            Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT))
        }
        let listener =
            Listener::bind_with_ipv6("[::]:0".parse().unwrap(), Echo, 1, unavailable, udp::bind)
                .await
                .unwrap();
        assert_ipv4_fallback(listener).await;
    }

    #[tokio::test]
    async fn wildcard_falls_back_to_ipv4_when_ipv6_udp_is_unavailable() {
        use std::sync::atomic::{AtomicBool, Ordering};

        static TRIED_IPV6_UDP: AtomicBool = AtomicBool::new(false);
        if std::net::TcpListener::bind("[::1]:0").is_err() {
            return;
        }
        fn unavailable(address: SocketAddr) -> io::Result<std::net::UdpSocket> {
            if address.is_ipv6() {
                TRIED_IPV6_UDP.store(true, Ordering::Relaxed);
                Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
            } else {
                udp::bind(address)
            }
        }
        let listener = Listener::bind_with_ipv6(
            "[::]:0".parse().unwrap(),
            Echo,
            1,
            bind_ipv6_dual,
            unavailable,
        )
        .await
        .unwrap();
        assert!(TRIED_IPV6_UDP.load(Ordering::Relaxed));
        assert_ipv4_fallback(listener).await;
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        self.udp_stop.send_replace(true);
    }
}

#[derive(Default)]
pub struct ListenerRegistry {
    listeners: HashMap<ListenerKey, Listener>,
    handlers: HashMap<ListenerKey, Box<dyn Any + Send + Sync>>,
}

impl ListenerRegistry {
    pub fn insert(&mut self, key: ListenerKey, listener: Listener) -> Option<Listener> {
        self.handlers.remove(&key);
        self.listeners.insert(key, listener)
    }

    pub fn remove(&mut self, key: &ListenerKey) -> Option<Listener> {
        self.handlers.remove(key);
        self.listeners.remove(key)
    }

    pub fn get(&self, key: &ListenerKey) -> Option<&Listener> {
        self.listeners.get(key)
    }

    /// Stop and drain every Listener.
    pub async fn shutdown(mut self) -> io::Result<()> {
        let mut result = Ok(());
        for (_, listener) in self.listeners.drain() {
            if let Err(error) = listener.shutdown().await
                && result.is_ok()
            {
                result = Err(error);
            }
        }
        result
    }

    /// Bind new Listeners before changing handlers; return replaced states for draining.
    pub async fn apply<H: Handler>(
        &mut self,
        mut servers: HashMap<ListenerKey, H>,
    ) -> io::Result<Vec<Arc<H>>> {
        let desired: HashSet<_> = servers.keys().copied().collect();
        if desired.iter().any(|key| key.transport != Transport::Dns) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported Listener transport",
            ));
        }
        for key in servers
            .keys()
            .filter(|key| self.listeners.contains_key(key))
        {
            if self
                .handlers
                .get(key)
                .and_then(|handler| handler.downcast_ref::<Arc<ArcSwap<H>>>())
                .is_none()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Listener handler type mismatch",
                ));
            }
        }
        let mut added: Vec<(ListenerKey, Listener, Arc<ArcSwap<H>>)> = Vec::new();
        let new_keys: Vec<_> = servers
            .keys()
            .filter(|key| !self.listeners.contains_key(key))
            .copied()
            .collect();
        for key in new_keys {
            let handler = Arc::new(ArcSwap::from_pointee(
                servers.remove(&key).expect("new Listener"),
            ));
            let listener = match Listener::bind(key.address, Swappable(Arc::clone(&handler))).await
            {
                Ok(listener) => listener,
                Err(error) => {
                    for (_, listener, _) in added {
                        let _: io::Result<()> = listener.shutdown().await;
                    }
                    return Err(io::Error::new(
                        error.kind(),
                        format!("{}: {error}", key.address),
                    ));
                }
            };
            added.push((key, listener, handler));
        }
        let mut replacements = Vec::new();
        for (key, server) in &servers {
            let listener = &self.listeners[key];
            let count = server.udp_workers();
            if count == listener.udp_tasks.len() && listener.shed == server.shed_metrics().is_some()
            {
                continue;
            }
            let sockets = (0..count)
                .map(|_| udp::bind(listener.address).and_then(UdpSocket::from_std))
                .collect::<io::Result<Vec<_>>>();
            match sockets {
                Ok(sockets) => replacements.push((*key, sockets)),
                Err(error) => {
                    for (_, listener, _) in added {
                        let _: io::Result<()> = listener.shutdown().await;
                    }
                    return Err(io::Error::new(
                        error.kind(),
                        format!("{}: {error}", key.address),
                    ));
                }
            }
        }
        let mut retired = Vec::new();
        for (key, server) in servers {
            retired.push(
                self.handlers[&key]
                    .downcast_ref::<Arc<ArcSwap<H>>>()
                    .expect("validated handler")
                    .swap(Arc::new(server)),
            );
        }
        for (key, sockets) in replacements {
            let handler = self.handlers[&key]
                .downcast_ref::<Arc<ArcSwap<H>>>()
                .expect("validated handler");
            let handler = Arc::new(Swappable(Arc::clone(handler)));
            let listener = self.listeners.get_mut(&key).expect("existing Listener");
            listener.shed = handler.shed_metrics().is_some();
            for task in listener.tasks.split_off(1) {
                if task.is_finished() {
                    if let Err(error) = task.await.map_err(io::Error::other).and_then(|v| v) {
                        logging::log("ERROR", "", &format!("UDP worker shutdown: {error}"));
                    }
                } else {
                    listener.tasks.push(task);
                }
            }
            let (stop, receiver) = watch::channel(false);
            let tasks = sockets
                .into_iter()
                .map(|socket| udp::spawn(socket, Arc::clone(&handler), receiver.clone()))
                .collect();
            listener.udp_stop.send_replace(true);
            listener.tasks.append(&mut listener.udp_tasks);
            listener.udp_stop = stop;
            listener.udp_tasks = tasks;
        }
        let removed: Vec<_> = self
            .listeners
            .keys()
            .filter(|key| !desired.contains(key))
            .copied()
            .collect();
        for (key, listener, handler) in added {
            self.listeners.insert(key, listener);
            self.handlers.insert(key, Box::new(handler));
        }
        for key in removed {
            if let Some(handler) = self
                .handlers
                .get(&key)
                .and_then(|handler| handler.downcast_ref::<Arc<ArcSwap<H>>>())
            {
                retired.push(handler.load_full());
            }
            if let Some(listener) = self.remove(&key)
                && let Err(error) = listener.shutdown().await
            {
                logging::log("ERROR", "", &format!("Listener shutdown: {error}"));
            }
        }
        Ok(retired)
    }
}

struct Swappable<H>(Arc<ArcSwap<H>>);

impl<H: Handler> Handler for Swappable<H> {
    fn shed_metrics(&self) -> Option<metrics::ShedMetrics> {
        self.0.load().shed_metrics()
    }
    fn shed_query(&self, query: &[u8], peer: SocketAddr) -> bool {
        self.0.load().shed_query(query, peer)
    }
    fn tcp_options(&self) -> TcpOptions {
        self.0.load().tcp_options()
    }
    fn udp_workers(&self) -> usize {
        self.0.load().udp_workers()
    }
    fn parallel_query(&self, query: &[u8], peer: SocketAddr) -> Option<watch::Receiver<bool>> {
        self.0.load().parallel_query(query, peer)
    }
    async fn handle(
        &self,
        query: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        let handler = self.0.load();
        H::handle_shared(&handler, query, peer, protocol, response).await
    }
}
