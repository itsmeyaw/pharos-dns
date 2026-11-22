//! One etcd endpoint: a lazily dialled HTTP/2 connection that carries unary calls and streams.

use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Buf, Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::{
    HeaderMap, Request, Response, StatusCode, Uri,
    body::{Frame, Incoming},
    client::conn::http2,
    header::{CONTENT_TYPE, HeaderName, HeaderValue},
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use pharos_server::{
    grpc::{self, Code},
    tls::{ClientConfig, ServerName, TlsConnector},
};
use tokio::{net::TcpStream, sync::mpsc, time::Instant};

use super::Error;

/// The largest gRPC message accepted from etcd: a prefix read of a whole zone is far below it,
/// and a bigger one is an error instead of an allocation.
// shortcut: a fixed 16 MiB bound where etcd clientv3 allows 2 GiB; make it configurable if a zone outgrows it.
pub(super) const MAX_MESSAGE_LEN: usize = 16 << 20;

// RFC 9113 §6.7: pings find a connection that died without a FIN or RST, which a watch would never notice.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(5);

type Sender = http2::SendRequest<Body>;

/// What an endpoint reaches the server with.
pub(super) enum Security {
    Plain,
    Tls {
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
    },
    /// TLS was needed and could not be set up; every call reports why.
    Broken(String),
}

/// A request body: one message, or messages a stream sends as they come.
pub(super) enum Body {
    Unary(Option<Bytes>),
    Stream(mpsc::Receiver<Bytes>),
}

impl hyper::body::Body for Body {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        match &mut *self {
            Self::Unary(message) => Poll::Ready(message.take().map(|data| Ok(Frame::data(data)))),
            Self::Stream(messages) => messages
                .poll_recv(cx)
                .map(|message| message.map(|data| Ok(Frame::data(data)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self, Self::Unary(None))
    }
}

/// PROTOCOL-HTTP2 "Length-Prefixed-Message": an uncompressed message.
pub(super) fn frame(payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(grpc::HEADER_LEN + payload.len());
    out.extend_from_slice(&[0]);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.freeze()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a call is: one request and one reply, or a stream of replies.
pub(super) enum Op<'a> {
    Unary {
        path: &'static str,
        message: &'a Bytes,
    },
    Stream {
        path: &'static str,
        first: &'a Bytes,
    },
}

pub(super) enum Reply {
    Unary(Bytes),
    Stream(Streaming),
}

/// The connection closed before the server could have acted on the request.
struct Stale;

pub(super) struct Connection {
    host: String,
    port: u16,
    base: String,
    security: Security,
    sender: Mutex<Option<Sender>>,
    dial: tokio::sync::Mutex<()>,
    down_until: Mutex<Option<Instant>>,
}

impl Connection {
    pub(super) fn new(host: &str, port: u16, security: Security) -> Self {
        // RFC 3986 §3.2.2: an IPv6 address in a URI authority is in brackets.
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        Self {
            host: host.to_owned(),
            port,
            base: format!(
                "{}://{authority}",
                if matches!(security, Security::Plain) {
                    "http"
                } else {
                    "https"
                }
            ),
            security,
            sender: Mutex::new(None),
            dial: tokio::sync::Mutex::new(()),
            down_until: Mutex::new(None),
        }
    }

    /// Whether a failure marked this endpoint down and the back-off has not passed.
    pub(super) fn is_down(&self, now: Instant) -> bool {
        lock(&self.down_until).is_some_and(|until| until > now)
    }

    pub(super) fn failed(&self, backoff: Duration) {
        *lock(&self.down_until) = Some(Instant::now() + backoff);
    }

    pub(super) fn recovered(&self) {
        *lock(&self.down_until) = None;
    }

    /// Drop the connection; the next call dials again. Open streams end.
    pub(super) fn reset(&self) {
        lock(&self.sender).take();
    }

    fn cached(&self) -> Option<Sender> {
        lock(&self.sender)
            .as_ref()
            .filter(|sender| !sender.is_closed())
            .cloned()
    }

    /// A usable connection, and whether it was open already.
    async fn connection(&self) -> Result<(Sender, bool), Error> {
        if let Some(sender) = self.cached() {
            return Ok((sender, true));
        }
        // RFC 9113 §9.1: calls that arrive together share the connection the first one opens.
        let _dialing = self.dial.lock().await;
        if let Some(sender) = self.cached() {
            return Ok((sender, true));
        }
        let sender = self
            .connect()
            .await
            .map_err(|error| Error::Unavailable(format!("{}:{}: {error}", self.host, self.port)))?;
        *lock(&self.sender) = Some(sender.clone());
        Ok((sender, false))
    }

    async fn connect(&self) -> io::Result<Sender> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port)).await?;
        // grpc-go sets TCP_NODELAY on every connection.
        tcp.set_nodelay(true)?;
        match &self.security {
            Security::Plain => handshake(tcp).await,
            Security::Broken(reason) => Err(io::Error::other(reason.clone())),
            Security::Tls { config, name } => {
                // RFC 8446 §4.4.3: the server proves its certificate for the host the endpoint names.
                let stream = TlsConnector::from(config.clone())
                    .connect(name.clone(), tcp)
                    .await?;
                // RFC 7301 §3.1: gRPC runs on HTTP/2 only; grpc-go refuses a connection that did not negotiate `h2`.
                if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "server did not negotiate h2",
                    ));
                }
                handshake(stream).await
            }
        }
    }

    fn request(
        &self,
        path: &str,
        body: Body,
        token: Option<&str>,
        deadline: Instant,
    ) -> Result<Request<Body>, Error> {
        let uri: Uri = format!("{}{path}", self.base)
            .parse()
            .map_err(|_| Error::Protocol(format!("invalid endpoint {}", self.base)))?;
        // PROTOCOL-HTTP2 "Timeout": whole milliseconds, at most eight digits; the call context carries the deadline.
        let millis = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .clamp(1, 99_999_999);
        let mut request = Request::post(uri)
            .header(CONTENT_TYPE, HeaderValue::from_static(grpc::CONTENT_TYPE))
            // PROTOCOL-HTTP2 "Request-Headers": `te: trailers` is required.
            .header("te", HeaderValue::from_static("trailers"))
            .header(
                HeaderName::from_static("grpc-timeout"),
                HeaderValue::from_str(&format!("{millis}m")).expect("digits and a unit"),
            )
            .body(body)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if let Some(token) = token {
            // etcd v3 server/etcdserver/api/v3rpc/interceptor.go: the auth token travels in the `token` metadata key.
            let value = HeaderValue::from_str(token)
                .map_err(|_| Error::Protocol("auth token is not a valid header value".into()))?;
            request.headers_mut().insert("token", value);
        }
        Ok(request)
    }

    /// Run `op` on this endpoint; the reply has its status checked.
    pub(super) async fn execute(
        &self,
        op: &Op<'_>,
        token: Option<&str>,
        deadline: Instant,
    ) -> Result<Reply, Error> {
        match *op {
            Op::Unary { path, message } => {
                let mut retried = false;
                loop {
                    let (mut sender, reused) = self.connection().await?;
                    let request =
                        self.request(path, Body::Unary(Some(message.clone())), token, deadline)?;
                    match exchange(&mut sender, request).await {
                        Ok(response) => return read_unary(response).await.map(Reply::Unary),
                        // grpc-go retries a call transparently when the transport closed before the server saw it; reads are idempotent.
                        Err(Stale) if reused && !std::mem::replace(&mut retried, true) => {}
                        Err(Stale) => return Err(Error::Unavailable("connection closed".into())),
                    }
                }
            }
            Op::Stream { path, first } => {
                let (messages, queue) = mpsc::channel(4);
                messages.try_send(first.clone()).expect("an empty queue");
                let (mut sender, _) = self.connection().await?;
                let request = self.request(path, Body::Stream(queue), token, deadline)?;
                let response = exchange(&mut sender, request)
                    .await
                    .map_err(|Stale| Error::Unavailable("connection closed".into()))?;
                let (parts, body) = response.into_parts();
                check_head(&parts)?;
                // PROTOCOL-HTTP2 "Responses": a status in the initial headers means no message follows.
                if let Some(status) = parts.headers.get("grpc-status") {
                    return Err(status_error(&parts.headers, status));
                }
                Ok(Reply::Stream(Streaming {
                    body,
                    buffer: BytesMut::new(),
                    _requests: messages,
                }))
            }
        }
    }
}

async fn handshake<T>(stream: T) -> io::Result<Sender>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .keep_alive_interval(KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(KEEP_ALIVE_TIMEOUT)
        .keep_alive_while_idle(true)
        .handshake(TokioIo::new(stream))
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(connection);
    Ok(sender)
}

/// Send `request` and wait for the response head.
async fn exchange(
    sender: &mut Sender,
    request: Request<Body>,
) -> Result<Response<Incoming>, Stale> {
    // RFC 9113 §8.7: no response head yet, so the caller may send a call that used a dead connection again.
    sender.ready().await.map_err(|_| Stale)?;
    sender.send_request(request).await.map_err(|_| Stale)
}

fn check_head(parts: &hyper::http::response::Parts) -> Result<(), Error> {
    // PROTOCOL-HTTP2 "Responses": a gRPC response is HTTP 200, with the status in the headers or trailers.
    if parts.status != StatusCode::OK {
        return Err(Error::Protocol(format!("HTTP status {}", parts.status)));
    }
    // PROTOCOL-HTTP2 "Responses": every response, Trailers-Only included, carries an application/grpc content-type.
    if !parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(grpc::is_content_type)
    {
        return Err(Error::Protocol("missing or unexpected content-type".into()));
    }
    Ok(())
}

/// The error for a non-OK `grpc-status`; `Ok` is not an error and gives `Protocol`.
fn status_error(headers: &HeaderMap, status: &HeaderValue) -> Error {
    let code = Code::from_header(status.as_bytes());
    let message = headers
        .get("grpc-message")
        .and_then(|value| value.to_str().ok())
        .map(grpc::unescape_message)
        .unwrap_or_default();
    Error::Status { code, message }
}

async fn read_unary(response: Response<Incoming>) -> Result<Bytes, Error> {
    let (parts, mut body) = response.into_parts();
    check_head(&parts)?;
    let mut data = BytesMut::new();
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| Error::Unavailable(error.to_string()))?;
        match frame.into_data() {
            Ok(chunk) => {
                if data.len() + chunk.len() > grpc::HEADER_LEN + MAX_MESSAGE_LEN {
                    return Err(Error::Protocol("response message too large".into()));
                }
                data.extend_from_slice(&chunk);
            }
            Err(frame) => trailers = frame.into_trailers().ok(),
        }
    }
    let headers = trailers.as_ref().unwrap_or(&parts.headers);
    // PROTOCOL-HTTP2 "Responses": a stream that ends without `grpc-status` is Unknown.
    let status = headers
        .get("grpc-status")
        .ok_or_else(|| Error::Protocol("stream ended without grpc-status".into()))?;
    if status.as_bytes() != b"0" {
        return Err(status_error(headers, status));
    }
    // A unary call carries exactly one message.
    match (next_message(&mut data)?, data.is_empty()) {
        (Some(message), true) => Ok(message),
        _ => Err(Error::Protocol(
            "response is not exactly one message".into(),
        )),
    }
}

/// Take the next whole length-prefixed gRPC message off `buffer`, or `None` while it has not all arrived.
fn next_message(buffer: &mut BytesMut) -> Result<Option<Bytes>, Error> {
    let Some(header) = grpc::parse_header(buffer) else {
        return Ok(None);
    };
    let header = header.map_err(|status| Error::Protocol(status.message.into_owned()))?;
    // PROTOCOL-HTTP2 "Compressed-Flag": no `grpc-accept-encoding` is sent, so a compressed message is unexpected.
    if header.compressed || header.len > MAX_MESSAGE_LEN {
        return Err(Error::Protocol(
            "unexpected compressed or oversized message".into(),
        ));
    }
    if buffer.len() < grpc::HEADER_LEN + header.len {
        return Ok(None);
    }
    buffer.advance(grpc::HEADER_LEN);
    Ok(Some(buffer.split_to(header.len).freeze()))
}

/// The replies of a server-streaming or bidirectional call. Dropping it cancels the call.
pub(super) struct Streaming {
    body: Incoming,
    buffer: BytesMut,
    /// Keeps the request stream open, so the server does not see the end of the client's messages.
    _requests: mpsc::Sender<Bytes>,
}

impl Streaming {
    /// The next message, or `None` when the server ended the call with status OK.
    pub(super) async fn message(&mut self) -> Result<Option<Bytes>, Error> {
        loop {
            if let Some(message) = next_message(&mut self.buffer)? {
                return Ok(Some(message));
            }
            let Some(frame) = self.body.frame().await else {
                return Ok(None);
            };
            let frame = frame.map_err(|error| Error::Unavailable(error.to_string()))?;
            match frame.into_data() {
                Ok(chunk) => {
                    if self.buffer.len() + chunk.len() > grpc::HEADER_LEN + MAX_MESSAGE_LEN {
                        return Err(Error::Protocol("response message too large".into()));
                    }
                    self.buffer.extend_from_slice(&chunk);
                }
                Err(frame) => {
                    let Ok(trailers) = frame.into_trailers() else {
                        continue;
                    };
                    return match trailers.get("grpc-status") {
                        Some(status) if status.as_bytes() == b"0" => Ok(None),
                        Some(status) => Err(status_error(&trailers, status)),
                        None => Err(Error::Protocol("stream ended without grpc-status".into())),
                    };
                }
            }
        }
    }
}
