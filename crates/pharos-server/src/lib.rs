#![forbid(unsafe_code)]

mod quota;
mod tcp;
mod udp;
#[cfg(target_os = "linux")]
mod udp_linux;

use std::{collections::HashMap, io, net::SocketAddr, sync::Arc};

use tokio::{
    net::{TcpListener, UdpSocket},
    sync::watch,
    task::JoinHandle,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Transport {
    Dns,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ListenerKey {
    pub transport: Transport,
    pub address: SocketAddr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Respond,
    Drop,
}

/// Synchronous, statically dispatched Query handling. Clear and reuse the
/// supplied Response buffer; return `Drop` to suppress a Response.
///
/// UDP handlers must not block the runtime worker. TCP handlers run on Tokio's
/// blocking pool and may execute concurrently for a single connection.
pub trait Handler: Send + Sync + 'static {
    fn handle(
        &self,
        query: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action;
}

/// A DNS Listener serving UDP and TCP on the same address.
pub struct Listener {
    address: SocketAddr,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<io::Result<()>>>,
}

impl Listener {
    pub async fn bind<H: Handler>(address: SocketAddr, handler: H) -> io::Result<Self> {
        let tcp = TcpListener::bind(address).await?;
        let address = tcp.local_addr()?;
        let mut sockets = Vec::new();
        let first = udp::bind(address)?;
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

    /// Stop accepting Queries and wait for accepted Queries to finish.
    pub async fn shutdown(mut self) -> io::Result<()> {
        self.stop.send_replace(true);
        let mut result = Ok(());
        for task in self.tasks.drain(..) {
            let next = task.await.map_err(io::Error::other).and_then(|v| v);
            if result.is_ok() {
                result = next;
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
