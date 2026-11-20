//! Connection lifecycle shared by the Listeners that run HTTP over TLS (`https://` and `grpc://`).
//!
//! The module owns what does not depend on the application protocol: the connection limit and
//! accept loop, the TLS handshake, idle detection with graceful close, and reusable buffers.

use std::{
    io,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Buf;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep_until, timeout},
};
use tokio_rustls::server::TlsStream;

use crate::{Action, Handler, Protocol, TcpOptions, proxyproto::Prefixed};

// Buffers kept for reuse are bounded in count and size so a burst of large Responses cannot pin memory.
const POOL_BUFFERS: usize = 128;
const POOL_BUFFER_CAPACITY: usize = 16 * 1024;

/// Reusable Query and Response buffers, so a Query allocates only while the pool is still filling.
#[derive(Default)]
pub(crate) struct Pool(Mutex<Vec<Vec<u8>>>);

impl Pool {
    pub(crate) fn take(self: &Arc<Self>) -> Pooled {
        let buffer = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .unwrap_or_default();
        Pooled {
            buffer,
            position: 0,
            pool: Arc::clone(self),
        }
    }
}

/// A pooled buffer that returns itself on drop; as a [`Buf`] it reads from its first octet.
pub(crate) struct Pooled {
    buffer: Vec<u8>,
    position: usize,
    pool: Arc<Pool>,
}

impl Deref for Pooled {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.buffer
    }
}

impl DerefMut for Pooled {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buffer
    }
}

impl Buf for Pooled {
    fn remaining(&self) -> usize {
        self.buffer.len() - self.position
    }
    fn chunk(&self) -> &[u8] {
        &self.buffer[self.position..]
    }
    fn advance(&mut self, count: usize) {
        assert!(count <= self.remaining(), "advance past the buffer");
        self.position += count;
    }
}

impl Drop for Pooled {
    fn drop(&mut self) {
        let mut buffer = std::mem::take(&mut self.buffer);
        if buffer.capacity() > POOL_BUFFER_CAPACITY {
            return;
        }
        buffer.clear();
        let mut pool = self.pool.0.lock().unwrap_or_else(PoisonError::into_inner);
        if pool.len() < POOL_BUFFERS {
            pool.push(buffer);
        }
    }
}

/// Connection activity, so a connection with no request in flight can be closed after `idle`.
pub(crate) struct Activity {
    epoch: Instant,
    in_flight: AtomicUsize,
    last_millis: AtomicU64,
}

impl Activity {
    pub(crate) fn new() -> Self {
        Self {
            epoch: Instant::now(),
            in_flight: AtomicUsize::new(0),
            last_millis: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let millis = self.epoch.elapsed().as_millis() as u64;
        self.last_millis.store(millis, Ordering::Relaxed);
    }

    /// When the connection becomes idle for `idle`, assuming no request starts before then.
    fn idle_deadline(&self, idle: Duration) -> Instant {
        if self.in_flight.load(Ordering::Acquire) > 0 {
            return Instant::now() + idle;
        }
        self.epoch + Duration::from_millis(self.last_millis.load(Ordering::Relaxed)) + idle
    }
}

/// Marks one request in flight until dropped.
pub(crate) struct InFlight<'a>(&'a Activity);

impl<'a> InFlight<'a> {
    pub(crate) fn new(activity: &'a Activity) -> Self {
        activity.in_flight.fetch_add(1, Ordering::AcqRel);
        Self(activity)
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.touch();
        self.0.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A freshly accepted TCP connection and the state its task needs.
pub(crate) struct Accepted<H> {
    pub(crate) stream: TcpStream,
    pub(crate) peer: SocketAddr,
    pub(crate) handler: Arc<H>,
    pub(crate) pool: Arc<Pool>,
    pub(crate) stopped: watch::Receiver<bool>,
    /// Holds the connection's slot of the limit until the connection ends.
    pub(crate) permit: Option<OwnedSemaphorePermit>,
}

// RFC 1034 §2.4: Name servers concurrently process resolver queries.
pub(crate) fn spawn<H, F, Fut>(
    listener: TcpListener,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
    max_connections: fn(&H) -> usize,
    serve: F,
) -> JoinHandle<io::Result<()>>
where
    H: Handler,
    F: Fn(Accepted<H>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let pool = Arc::new(Pool::default());
        let mut connections = JoinSet::new();
        let mut limiter: Option<(usize, Arc<Semaphore>)> = None;
        let result = loop {
            if *shutdown.borrow() {
                break Ok(());
            }
            let limit = max_connections(&handler);
            // CoreDNS v1.15.0 server_https.go and server_grpc.go Serve: netutil.LimitListener takes a
            // slot before Accept, so connections over the limit wait in the kernel backlog.
            let permit = if limit == 0 {
                limiter = None;
                None
            } else {
                let semaphore = match &limiter {
                    Some((current, semaphore)) if *current == limit => Arc::clone(semaphore),
                    _ => {
                        let semaphore = Arc::new(Semaphore::new(limit));
                        limiter = Some((limit, Arc::clone(&semaphore)));
                        semaphore
                    }
                };
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => break Ok(()),
                    _ = connections.join_next(), if !connections.is_empty() => continue,
                    permit = semaphore.acquire_owned() => permit.ok(),
                }
            };
            tokio::select! {
                biased;
                _ = shutdown.changed() => break Ok(()),
                _ = connections.join_next(), if !connections.is_empty() => {},
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        connections.spawn(serve(Accepted {
                            stream,
                            peer: crate::canonical_peer(peer),
                            handler: Arc::clone(&handler),
                            pool: Arc::clone(&pool),
                            stopped: shutdown.clone(),
                            permit,
                        }));
                    }
                    Err(error) => {
                        crate::logging::log("ERROR", "server", &format!("TCP accept failed: {error}"));
                        tokio::select! {
                            _ = shutdown.changed() => break Ok(()),
                            _ = tokio::time::sleep(Duration::from_millis(100)) => {},
                        }
                    }
                },
            }
        };
        drop(listener);
        // Connections watch the same shutdown signal and finish their in-flight requests.
        while connections.join_next().await.is_some() {}
        result
    })
}

/// A connection whose PROXY header, if any, was consumed and whose TLS handshake completed.
pub(crate) struct Secured {
    pub(crate) stream: TlsStream<Prefixed<TcpStream>>,
    /// The client address: the PROXY header's source when the Listener uses one, else the TCP peer.
    pub(crate) peer: SocketAddr,
    /// The PROXY v2 TLV vector, hex-encoded, for every Query of the connection.
    pub(crate) tlv: Option<Arc<str>>,
}

/// Read the PROXY header, then complete the TLS handshake within the read timeout, or give up when the Listener stops.
pub(crate) async fn handshake<H: Handler>(
    stream: TcpStream,
    peer: SocketAddr,
    handler: &H,
    limits: TcpOptions,
    stopped: &mut watch::Receiver<bool>,
) -> Option<Secured> {
    crate::tcp::disable_nagle(&stream);
    let Some(tls) = handler.tls() else {
        crate::logging::log("ERROR", "server", "HTTP Listener has no TLS identity");
        return None;
    };
    let (stream, peer, tlv) = match handler.proxyproto() {
        // PROXY protocol §2: the header precedes the TLS ClientHello.
        Some(proxy) => tokio::select! {
            biased;
            _ = stopped.changed() => return None,
            accepted = proxy.accept_stream(stream, peer) => match accepted {
                Ok(accepted) => (accepted.stream, accepted.peer, accepted.tlv),
                Err(error) => {
                    crate::logging::log("DEBUG", "proxyproto", &format!("closing connection from {peer}: {error}"));
                    return None;
                }
            },
        },
        None => (Prefixed::new(stream), peer, None),
    };
    // CoreDNS v1.15.0 server_https.go: net/http's ReadTimeout bounds the handshake as well.
    let stream = tokio::select! {
        biased;
        _ = stopped.changed() => return None,
        result = timeout(limits.read, tls.acceptor().accept(stream)) => result.ok()?.ok()?,
    };
    Some(Secured { stream, peer, tlv })
}

/// Run a Query through the Plugin Chain, with the PROXY TLVs of its connection when it has any.
pub(crate) async fn handle<H: Handler>(
    handler: &Arc<H>,
    tlv: Option<&str>,
    query: &[u8],
    peer: SocketAddr,
    response: &mut Vec<u8>,
) -> Action {
    match tlv {
        Some(tlv) => H::handle_proxied(handler, query, peer, Protocol::Tcp, tlv, response).await,
        None => H::handle_shared(handler, query, peer, Protocol::Tcp, response).await,
    }
}

/// Run a connection until it ends, goes idle for `limits.idle` or the Listener stops.
// RFC 9112 §9.8, RFC 9113 §6.8: graceful shutdown lets in-flight requests finish before the close.
pub(crate) async fn drive<C: Future<Output = hyper::Result<()>>>(
    mut connection: Pin<&mut C>,
    graceful: impl Fn(Pin<&mut C>),
    activity: &Activity,
    mut stopped: watch::Receiver<bool>,
    limits: TcpOptions,
) {
    let mut closing: Option<Instant> = None;
    loop {
        let wake = closing.unwrap_or_else(|| activity.idle_deadline(limits.idle));
        tokio::select! {
            _ = connection.as_mut() => return,
            _ = stopped.changed(), if closing.is_none() => {
                graceful(connection.as_mut());
                closing = Some(Instant::now() + limits.write);
            }
            _ = sleep_until(wake) => {
                if closing.is_some() {
                    // The grace period ended; dropping the connection closes the socket.
                    return;
                }
                // A request that started after `wake` was computed keeps the connection open.
                if activity.idle_deadline(limits.idle) <= Instant::now() {
                    graceful(connection.as_mut());
                    closing = Some(Instant::now() + limits.write);
                }
            }
        }
    }
}
