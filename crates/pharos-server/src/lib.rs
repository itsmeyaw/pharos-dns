#![forbid(unsafe_code)]
//! Plugin Chain contract. A Plugin returns an Outcome rather than writing to a
//! Listener; earlier Plugins may inspect and modify the caller-owned Response
//! buffer after awaiting Next. The Listener handles unanswered codes and errors.

use std::{
    collections::HashMap, fmt, future::Future, io, net::SocketAddr, sync::Arc, time::Duration,
};

use pharos_proto::{BuildError, Message, Name, Rcode};
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
}

impl<'a> Metadata<'a> {
    pub fn new(slots: &'a mut [Option<(&'a str, &'a str)>]) -> Self {
        Self {
            slots,
            inline_name: None,
            inline_value: [0; 64],
            inline_len: 0,
        }
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
    fn handle(
        &self,
        query: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> impl Future<Output = Action> + Send;
}

/// A DNS Listener serving UDP and TCP on the same address.
pub struct Listener {
    address: SocketAddr,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<io::Result<()>>>,
}

impl Listener {
    pub async fn bind<H: Handler>(address: SocketAddr, handler: H) -> io::Result<Self> {
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

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

#[derive(Default)]
pub struct ListenerRegistry {
    listeners: HashMap<ListenerKey, Listener>,
}

impl ListenerRegistry {
    pub fn insert(&mut self, key: ListenerKey, listener: Listener) -> Option<Listener> {
        self.listeners.insert(key, listener)
    }

    pub fn remove(&mut self, key: &ListenerKey) -> Option<Listener> {
        self.listeners.remove(key)
    }

    pub fn get(&self, key: &ListenerKey) -> Option<&Listener> {
        self.listeners.get(key)
    }
}
