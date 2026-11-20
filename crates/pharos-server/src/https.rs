//! DNS over HTTPS Listener (RFC 8484): TLS with ALPN, then hyper serves HTTP/2 or HTTP/1.1.
//!
//! The request rules live in [`crate::doh`]; this module owns the connection lifecycle: the
//! connection limit, the TLS handshake, idle connections and the per-request buffers.

use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
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
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle, time::timeout};

use crate::{
    Action, Handler, Protocol,
    conn::{Accepted, Activity, InFlight, Pool, Pooled, drive},
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

pub(crate) enum Chunk {
    Text(&'static [u8]),
    Message(Pooled),
}

impl Buf for Chunk {
    fn remaining(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::Message(message) => message.remaining(),
        }
    }
    fn chunk(&self) -> &[u8] {
        match self {
            Self::Text(text) => text,
            Self::Message(message) => message.chunk(),
        }
    }
    fn advance(&mut self, count: usize) {
        match self {
            Self::Text(text) => *text = &text[count..],
            Self::Message(message) => message.advance(count),
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

struct Connection<H> {
    handler: Arc<H>,
    peer: SocketAddr,
    status: Option<Arc<doh::Status>>,
    pool: Arc<Pool>,
    activity: Arc<Activity>,
    read: Duration,
}

pub(crate) fn spawn<H: Handler>(
    listener: TcpListener,
    handler: Arc<H>,
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<io::Result<()>> {
    crate::conn::spawn(
        listener,
        handler,
        shutdown,
        |handler| handler.https().max_connections,
        serve,
    )
}

async fn serve<H: Handler>(accepted: Accepted<H>) {
    let Accepted {
        stream,
        peer,
        handler,
        pool,
        mut stopped,
        permit: _permit,
    } = accepted;
    let options = handler.https();
    let limits = handler.tcp_options();
    let Some(stream) = crate::conn::handshake(stream, &*handler, limits, &mut stopped).await else {
        return;
    };
    // RFC 7301 §3.2: the protocol the handshake selected decides the HTTP version.
    let http2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
    let activity = Arc::new(Activity::new());
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
        // RFC 9113 §6.5.2: a GET target of up to the 64 KiB URI limit must fit in the header list.
        builder.max_header_list_size(doh::MAX_HEADER_LIST);
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
        let mut builder = http1::Builder::new();
        // RFC 9112 §2.2: a request line and headers that never complete must not hold the connection.
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(limits.read);
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
    let (head, chunk) = reply(result);
    if let Some(counters) = &connection.status {
        counters.count(head.status());
    }
    head.map(|()| Reply(Some(chunk)))
}

/// The status, header fields and body of the HTTP response to a DoH request, shared by every HTTP Transport.
pub(crate) fn reply(result: Result<Pooled, StatusCode>) -> (Response<()>, Chunk) {
    let status = result
        .as_ref()
        .map_or_else(|status| *status, |_| StatusCode::OK);
    let mut response = Response::new(());
    *response.status_mut() = status;
    let headers = response.headers_mut();
    let chunk = match result {
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
            Chunk::Message(message)
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
            Chunk::Text(text)
        }
    };
    (response, chunk)
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
    dispatch(
        &connection.handler,
        connection.peer,
        &connection.pool,
        query,
    )
    .await
}

/// Run a DNS Query received over HTTP through the Plugin Chain, or name the status that rejects it.
pub(crate) async fn dispatch<H: Handler>(
    handler: &Arc<H>,
    peer: SocketAddr,
    pool: &Arc<Pool>,
    query: &[u8],
) -> Result<Pooled, StatusCode> {
    // CoreDNS v1.15.0 server_https.go ServeHTTP: an unparsable or rejected Message is a 400.
    if !doh::accept(query) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut response = pool.take();
    // RFC 8484 §4.2.1: every DNS Response, including SERVFAIL, travels in a 2xx response; no Response is a 500.
    match H::handle_shared(handler, query, peer, Protocol::Tcp, &mut response).await {
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
