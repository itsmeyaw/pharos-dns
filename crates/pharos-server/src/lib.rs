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
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
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
    fn run(self, cx: &mut Context<'_>) -> impl Future<Output = Outcome> + Send;
}

/// A Plugin may await Next and inspect or modify its outcome and Response.
pub trait Plugin {
    fn serve<N: Next + Send>(
        &self,
        cx: &mut Context<'_>,
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
    self_lookup: Option<SelfLookupState<'a>>,
}

impl<'a> Metadata<'a> {
    pub fn new(slots: &'a mut [Option<(&'a str, &'a str)>]) -> Self {
        Self {
            slots,
            inline_name: None,
            inline_value: [0; 64],
            inline_len: 0,
            self_lookup: None,
        }
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
        });
        metadata
    }

    /// Insert or replace a named value; returns false when no slot is free.
    pub fn insert(&mut self, name: &'a str, value: &'a str) -> bool {
        if let Some(slot) = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_some_and(|(existing, _)| existing == name))
        {
            *slot = Some((name, value));
            if self.inline_name == Some(name) {
                self.inline_name = None;
            }
            return true;
        }
        if let Some(slot) = self.slots.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some((name, value));
            if self.inline_name == Some(name) {
                self.inline_name = None;
            }
            return true;
        }
        false
    }

    /// Copy a short value whose lifetime is shorter than the Query's.
    pub fn insert_inline(&mut self, name: &'static str, value: &str) -> bool {
        if value.len() > self.inline_value.len()
            || self.inline_name.is_some_and(|existing| existing != name)
        {
            return false;
        }
        // shortcut: one copied value suffices for forward; add slots for other producers.
        self.inline_name = Some(name);
        self.inline_len = value.len();
        self.inline_value[..value.len()].copy_from_slice(value.as_bytes());
        true
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        if self.inline_name == Some(name) {
            return std::str::from_utf8(&self.inline_value[..self.inline_len]).ok();
        }
        self.slots
            .iter()
            .flatten()
            .find_map(|(key, value)| (*key == name).then_some(*value))
    }
}

/// Borrowed Query state and reusable, preallocated Response buffer.
pub struct Context<'a> {
    pub query: Message<'a>,
    pub client: SocketAddr,
    /// Listener address; wildcard addresses are not resolved per Query.
    pub local: SocketAddr,
    pub transport: Transport,
    pub protocol: Protocol,
    pub domain: &'a Name,
    pub metadata: Metadata<'a>,
    pub response: &'a mut Vec<u8>,
    pub max_response_size: usize,
}

/// The Listener state and depth associated with a Query.
struct SelfLookupState<'a> {
    server: &'a dyn SelfLookupServer,
    depth: u8,
}

// Type erasure keeps Context nongeneric without allocating on ordinary Queries.
trait SelfLookupServer: Sync {
    fn lookup<'a>(
        &'a self,
        wire: &'a [u8],
        peer: SocketAddr,
        protocol: Protocol,
        depth: u8,
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
        response: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Action> + Send + 'a>>;
}

/// Owned Listener state for a detached Query, including its Self Lookup depth.
pub struct SelfLookupHandle {
    server: Arc<dyn OwnedSelfLookupServer>,
    depth: u8,
}

impl SelfLookupServer for SelfLookupHandle {
    fn lookup<'a>(
        &'a self,
        wire: &'a [u8],
        peer: SocketAddr,
        protocol: Protocol,
        depth: u8,
        response: &'a mut Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Action> + Send + 'a>> {
        Arc::clone(&self.server).lookup(wire, peer, protocol, depth, response)
    }

    fn owned(&self) -> Option<Arc<dyn OwnedSelfLookupServer>> {
        Some(Arc::clone(&self.server))
    }
}

impl Context<'_> {
    /// Retain this Query's Listener state for a detached task, if available.
    pub fn self_lookup_handle(&self) -> Option<SelfLookupHandle> {
        let state = self.metadata.self_lookup.as_ref()?;
        Some(SelfLookupHandle {
            server: state.server.owned()?,
            depth: state.depth,
        })
    }

    /// Route a new Query through this Query's Listener and capture its Response.
    pub async fn self_lookup(&self, name: &Name, qtype: Type) -> Result<Vec<u8>, Error> {
        let state = self
            .metadata
            .self_lookup
            .as_ref()
            .ok_or(Error::SelfLookupUnavailable)?;
        if state.depth >= 10 {
            return Err(Error::SelfLookupDepth);
        }
        let query = self
            .query
            .with_question(name, qtype)
            .map_err(Error::Build)?;
        let mut response = Vec::with_capacity(usize::from(u16::MAX));
        match state
            .server
            .lookup(
                &query,
                self.client,
                self.protocol,
                state.depth + 1,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Respond,
    Drop,
}

/// Async, statically dispatched Query handling. Clear and reuse the supplied
/// Response buffer; return `Drop` to suppress a Response.
/// Handlers must not block the runtime; TCP Queries on a connection may run
/// concurrently.
pub trait Handler: Send + Sync + 'static {
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
}

impl Listener {
    pub async fn bind<H: Handler>(address: SocketAddr, handler: H) -> io::Result<Self> {
        if address.is_ipv6() && address.ip().is_unspecified() {
            return Self::bind_wildcard(address.port(), handler).await;
        }
        // Port 0 picks a free TCP port; the same UDP port may be taken, so retry.
        let mut attempts = if address.port() == 0 { 16 } else { 1 };
        let (tcp, address, first) = loop {
            let tcp = TcpListener::bind(address).await?;
            let bound = tcp.local_addr()?;
            match udp::bind(bound) {
                Ok(udp) => break (tcp, bound, udp),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse && attempts > 1 => {
                    attempts -= 1;
                }
                Err(error) => return Err(error),
            }
        };
        let mut sockets = Vec::new();
        sockets.push(first);
        for _ in 1..quota::worker_count() {
            sockets.push(udp::bind(address)?);
        }
        let (stop, receiver) = watch::channel(false);
        let handler = Arc::new(handler);
        let mut tasks = sockets
            .into_iter()
            .map(|socket| {
                let socket = UdpSocket::from_std(socket)?;
                Ok(udp::spawn(socket, Arc::clone(&handler), receiver.clone()))
            })
            .collect::<io::Result<Vec<_>>>()?;
        tasks.push(tcp::spawn(tcp, handler, receiver));
        Ok(Self {
            address,
            stop,
            tasks,
        })
    }

    async fn bind_wildcard<H: Handler>(port: u16, handler: H) -> io::Result<Self> {
        let mut attempts = if port == 0 { 16 } else { 1 };
        let (tcp4, tcp6, address, sockets) = loop {
            let tcp4 = TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).await?;
            let address = tcp4.local_addr()?;
            let address6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, address.port()));
            let tcp6 = match bind_ipv6_only(address6) {
                Ok(tcp) => Some(tcp),
                Err(error) if ipv6_unavailable(&error) => None,
                Err(error) if error.kind() == io::ErrorKind::AddrInUse && attempts > 1 => {
                    attempts -= 1;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let sockets = (|| {
                let mut sockets = Vec::new();
                for _ in 0..quota::worker_count() {
                    sockets.push(udp::bind(address)?);
                    if tcp6.is_some() {
                        sockets.push(udp::bind(address6)?);
                    }
                }
                Ok::<_, io::Error>(sockets)
            })();
            match sockets {
                Ok(sockets) => break (tcp4, tcp6, address, sockets),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse && attempts > 1 => {
                    attempts -= 1;
                }
                Err(error) => return Err(error),
            }
        };
        let (stop, receiver) = watch::channel(false);
        let handler = Arc::new(handler);
        let mut tasks = sockets
            .into_iter()
            .map(|socket| {
                let socket = UdpSocket::from_std(socket)?;
                Ok(udp::spawn(socket, Arc::clone(&handler), receiver.clone()))
            })
            .collect::<io::Result<Vec<_>>>()?;
        tasks.push(tcp::spawn(tcp4, Arc::clone(&handler), receiver.clone()));
        if let Some(tcp6) = tcp6 {
            tasks.push(tcp::spawn(tcp6, handler, receiver));
        }
        Ok(Self {
            address,
            stop,
            tasks,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Stop accepting Queries and drain for at most five seconds.
    pub async fn shutdown(mut self) -> io::Result<()> {
        self.stop.send_replace(true);
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

fn bind_ipv6_only(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

fn ipv6_unavailable(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AddrNotAvailable
        || error.raw_os_error() == Some(libc::EAFNOSUPPORT)
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.send_replace(true);
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
        let mut retired = Vec::new();
        for (key, server) in servers {
            retired.push(
                self.handlers[&key]
                    .downcast_ref::<Arc<ArcSwap<H>>>()
                    .expect("validated handler")
                    .swap(Arc::new(server)),
            );
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
