//! DNS over HTTPS Listener (RFC 8484): TLS with ALPN, then hyper serves HTTP/2 or HTTP/1.1.
//!
//! The request rules live in [`crate::doh`]; this module owns the connection lifecycle: the
//! connection limit, the TLS handshake, idle connections and the per-request buffers.

use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    ops::{Deref, DerefMut},
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Buf;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::{
    Request, Response, StatusCode,
    body::Incoming,
    header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue, X_CONTENT_TYPE_OPTIONS},
    http::request::Parts,
    server::conn::{http1, http2},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep_until, timeout},
};

use crate::{
    Action, Handler, Protocol, TcpOptions,
    doh::{self, Source},
};

/// Connection limits and response counters of an `https://` Listener.
#[derive(Clone)]
pub struct HttpsOptions {
    /// Concurrent TCP connections; zero means unlimited.
    pub max_connections: usize,
    /// Concurrent HTTP/2 streams per connection; zero keeps hyper's default.
    pub max_streams: u32,
    pub status: Option<Arc<doh::Status>>,
}

impl Default for HttpsOptions {
    fn default() -> Self {
        Self {
            max_connections: doh::DEFAULT_MAX_CONNECTIONS,
            max_streams: doh::DEFAULT_MAX_STREAMS,
            status: None,
        }
    }
}

// Buffers kept for reuse are bounded in count and size so a burst of large Responses cannot pin memory.
const POOL_BUFFERS: usize = 128;
const POOL_BUFFER_CAPACITY: usize = 16 * 1024;

/// Reusable Query and Response buffers, so a Query allocates only while the pool is still filling.
#[derive(Default)]
struct Pool(Mutex<Vec<Vec<u8>>>);

impl Pool {
    fn take(self: &Arc<Self>) -> Pooled {
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
struct Pooled {
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

enum Chunk {
    Text(&'static [u8]),
    Message(Pooled),
}

impl Buf for Chunk {
    fn remaining(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::Message(message) => message.len() - message.position,
        }
    }
    fn chunk(&self) -> &[u8] {
        match self {
            Self::Text(text) => text,
            Self::Message(message) => &message.buffer[message.position..],
        }
    }
    fn advance(&mut self, count: usize) {
        match self {
            Self::Text(text) => *text = &text[count..],
            Self::Message(message) => message.position += count,
        }
    }
}

/// A single-chunk response body whose length is known up front.
struct Reply(Option<Chunk>);

impl Body for Reply {
    type Data = Chunk;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Chunk>, Infallible>>> {
        Poll::Ready(self.0.take().map(|chunk| Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.0.as_ref().map_or(0, |chunk| chunk.remaining() as u64))
    }
}

/// Connection activity, so a connection with no request in flight can be closed after `idle`.
struct Activity {
    epoch: Instant,
    in_flight: AtomicUsize,
    last_millis: AtomicU64,
}

impl Activity {
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

struct InFlight<'a>(&'a Activity);

impl<'a> InFlight<'a> {
    fn new(activity: &'a Activity) -> Self {
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

struct Connection<H> {
    handler: Arc<H>,
    peer: SocketAddr,
    status: Option<Arc<doh::Status>>,
    pool: Arc<Pool>,
    activity: Arc<Activity>,
    read: Duration,
}

// RFC 1034 §2.4: Name servers concurrently process resolver queries.
pub(crate) fn spawn<H: Handler>(
    listener: TcpListener,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let pool = Arc::new(Pool::default());
        let mut connections = JoinSet::new();
        let mut limiter: Option<(usize, Arc<Semaphore>)> = None;
        let result = loop {
            if *shutdown.borrow() {
                break Ok(());
            }
            let options = handler.https();
            // CoreDNS v1.15.0 server_https.go Serve: netutil.LimitListener takes a slot before Accept,
            // so connections over the limit wait in the kernel backlog.
            let permit = if options.max_connections == 0 {
                limiter = None;
                None
            } else {
                let semaphore = match &limiter {
                    Some((limit, semaphore)) if *limit == options.max_connections => {
                        Arc::clone(semaphore)
                    }
                    _ => {
                        let semaphore = Arc::new(Semaphore::new(options.max_connections));
                        limiter = Some((options.max_connections, Arc::clone(&semaphore)));
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
                        connections.spawn(serve(
                            stream,
                            crate::canonical_peer(peer),
                            Arc::clone(&handler),
                            options,
                            Arc::clone(&pool),
                            shutdown.clone(),
                            permit,
                        ));
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

async fn serve<H: Handler>(
    stream: TcpStream,
    peer: SocketAddr,
    handler: Arc<H>,
    options: HttpsOptions,
    pool: Arc<Pool>,
    mut stopped: watch::Receiver<bool>,
    _permit: Option<OwnedSemaphorePermit>,
) {
    crate::tcp::disable_nagle(&stream);
    let Some(tls) = handler.tls() else {
        crate::logging::log("ERROR", "server", "HTTPS Listener has no TLS identity");
        return;
    };
    let limits = handler.tcp_options();
    // CoreDNS v1.15.0 server_https.go: net/http's ReadTimeout bounds the handshake as well.
    let stream = tokio::select! {
        biased;
        _ = stopped.changed() => return,
        result = timeout(limits.read, tls.acceptor().accept(stream)) => match result {
            Ok(Ok(stream)) => stream,
            _ => return,
        },
    };
    // RFC 7301 §3.2: the protocol the handshake selected decides the HTTP version.
    let http2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
    let activity = Arc::new(Activity {
        epoch: Instant::now(),
        in_flight: AtomicUsize::new(0),
        last_millis: AtomicU64::new(0),
    });
    let connection = Arc::new(Connection {
        handler,
        peer,
        status: options.status,
        pool,
        activity: Arc::clone(&activity),
        read: limits.read,
    });
    let service = service_fn(move |request| {
        let connection = Arc::clone(&connection);
        async move { Ok::<_, Infallible>(respond(&connection, request).await) }
    });
    let io = TokioIo::new(stream);
    if http2 {
        let mut builder = http2::Builder::new(TokioExecutor::new());
        // RFC 9113 §6.5.2: SETTINGS_MAX_CONCURRENT_STREAMS bounds the peer's open streams.
        if options.max_streams != 0 {
            builder.max_concurrent_streams(options.max_streams);
        }
        let connection = builder.serve_connection(io, service);
        tokio::pin!(connection);
        drive(
            connection,
            |connection| connection.graceful_shutdown(),
            &activity,
            stopped,
            limits,
        )
        .await;
    } else {
        let connection = http1::Builder::new().serve_connection(io, service);
        tokio::pin!(connection);
        drive(
            connection,
            |connection| connection.graceful_shutdown(),
            &activity,
            stopped,
            limits,
        )
        .await;
    }
}

/// Run a connection until it ends, goes idle for `limits.idle` or the Listener stops.
// RFC 9112 §9.8, RFC 9113 §6.8: graceful shutdown lets in-flight requests finish before the close.
async fn drive<C: Future<Output = hyper::Result<()>>>(
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
                if wake <= Instant::now() {
                    graceful(connection.as_mut());
                    closing = Some(Instant::now() + limits.write);
                }
            }
        }
    }
}

async fn respond<H: Handler>(
    connection: &Connection<H>,
    request: Request<Incoming>,
) -> Response<Reply> {
    let _active = InFlight::new(&connection.activity);
    let (parts, body) = request.into_parts();
    let mut query = connection.pool.take();
    let result = answer(connection, &parts, body, &mut query).await;
    let status = result
        .as_ref()
        .map_or_else(|status| *status, |_| StatusCode::OK);
    if let Some(counters) = &connection.status {
        counters.count(status);
    }
    let mut response = Response::new(Reply(None));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    match result {
        Ok(message) => {
            // RFC 8484 §4.2.2: a DNS Response is application/dns-message with an explicit freshness lifetime.
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs() as i64);
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(doh::MEDIA_TYPE));
            headers.insert(
                CACHE_CONTROL,
                doh::cache_control(doh::max_age(&message, now)),
            );
            *response.body_mut() = Reply(Some(Chunk::Message(message)));
        }
        Err(status) => {
            // CoreDNS v1.15.0 server_https.go: net/http's http.Error text for each failure.
            let text: &'static [u8] = match status {
                StatusCode::NOT_FOUND => b"\n",
                StatusCode::BAD_REQUEST => b"invalid request\n",
                _ => b"No response\n",
            };
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
            *response.body_mut() = Reply(Some(Chunk::Text(text)));
        }
    }
    response
}

async fn answer<H: Handler>(
    connection: &Connection<H>,
    parts: &Parts,
    body: Incoming,
    query: &mut Pooled,
) -> Result<Pooled, StatusCode> {
    match doh::locate(&parts.method, &parts.uri)? {
        Source::Get(value) => doh::decode_get(value, query)?,
        Source::Post => read_body(body, query, connection.read).await?,
    }
    // CoreDNS v1.15.0 server_https.go ServeHTTP: an unparsable or rejected Message is a 400.
    if !doh::accept(query) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut response = connection.pool.take();
    // RFC 8484 §4.2.1: every DNS Response, including SERVFAIL, travels in a 2xx response; no Response is a 500.
    match H::handle_shared(
        &connection.handler,
        query,
        connection.peer,
        Protocol::Tcp,
        &mut response,
    )
    .await
    {
        Action::Respond => Ok(response),
        Action::Drop | Action::Stream(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Append a POST body to `out`, failing when it exceeds the Message limit or arrives too slowly.
async fn read_body(
    mut body: Incoming,
    out: &mut Vec<u8>,
    limit: Duration,
) -> Result<(), StatusCode> {
    let read = async {
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| StatusCode::BAD_REQUEST)?;
            if let Some(data) = frame.data_ref() {
                // CoreDNS v1.15.0 plugin/pkg/doh requestToMsgPost: http.MaxBytesReader(65536).
                if out.len() + data.len() > doh::MAX_QUERY_LEN {
                    return Err(StatusCode::BAD_REQUEST);
                }
                out.extend_from_slice(data);
            }
        }
        Ok(())
    };
    timeout(limit, read)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?
}
