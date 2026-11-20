//! The unary `coredns.dns.DnsService/Query` call to one Upstream over a shared HTTP/2 connection.

use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::{Buf, buf::Chain};
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, StatusCode, Uri,
    client::conn::http2,
    header::{CONTENT_TYPE, HeaderName, HeaderValue},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pharos_server::{
    grpc::{self, Code, FramePrefix},
    tls::{ClientConfig, ServerName, TlsConnector},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, UnixStream},
    time::Instant,
};

type Body = Full<Chain<FramePrefix, Wire>>;
type Sender = http2::SendRequest<Body>;

/// The most buffers a [`Pool`] keeps, and the largest capacity of one it keeps.
const POOL_BUFFERS: usize = 64;
const POOL_CAPACITY: usize = 4096;

/// A DNS Message queued for sending: a shared view of one [`Pool`] buffer, so a call needs no copy of it.
#[derive(Clone)]
pub(super) struct Wire {
    buffer: Arc<Vec<u8>>,
    position: usize,
}

impl Buf for Wire {
    fn remaining(&self) -> usize {
        self.buffer.len() - self.position
    }

    fn chunk(&self) -> &[u8] {
        &self.buffer[self.position..]
    }

    fn advance(&mut self, count: usize) {
        assert!(count <= self.remaining(), "advance past the end");
        self.position += count;
    }
}

/// Request buffers that outlive one call, so the warm path does not allocate for them.
#[derive(Default)]
pub(super) struct Pool(Mutex<Vec<Arc<Vec<u8>>>>);

impl Pool {
    pub(super) fn take(&self) -> Loan<'_> {
        Loan {
            pool: self,
            buffer: lock(&self.0).pop(),
        }
    }
}

/// A buffer taken from a [`Pool`]; it goes back when no [`Wire`] of it is still in flight.
pub(super) struct Loan<'a> {
    pool: &'a Pool,
    buffer: Option<Arc<Vec<u8>>>,
}

impl Loan<'_> {
    /// The buffer to fill, emptied; a copy if a [`Wire`] still shares it.
    pub(super) fn buffer(&mut self) -> &mut Vec<u8> {
        let buffer = Arc::make_mut(self.buffer.get_or_insert_default());
        buffer.clear();
        buffer
    }

    pub(super) fn contents(&self) -> &[u8] {
        self.buffer.as_deref().map_or(&[], Vec::as_slice)
    }

    pub(super) fn wire(&self) -> Wire {
        Wire {
            buffer: self.buffer.clone().unwrap_or_default(),
            position: 0,
        }
    }
}

impl Drop for Loan<'_> {
    fn drop(&mut self) {
        // The connection may still hold the request; a buffer someone else owns is theirs to free.
        if let Some(mut buffer) = self.buffer.take()
            && Arc::get_mut(&mut buffer).is_some_and(|buffer| buffer.capacity() <= POOL_CAPACITY)
        {
            let mut kept = lock(&self.pool.0);
            if kept.len() < POOL_BUFFERS {
                kept.push(buffer);
            }
        }
    }
}

/// Where an Upstream listens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Target {
    Tcp(SocketAddr),
    /// A name or scoped IPv6 address that getaddrinfo resolves at dial, as grpc-go's resolver does.
    Host {
        host: String,
        port: u16,
    },
    Unix(PathBuf),
    /// A target CoreDNS accepts at setup that grpc-go cannot dial; every call fails with this reason.
    Invalid(String),
}

/// How the Upstream is verified and the name its certificate must carry.
pub(super) struct Tls {
    pub config: Arc<ClientConfig>,
    pub server_name: ServerName<'static>,
}

/// What a call produced.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Reply {
    /// The DNS Message, now the whole content of the output buffer.
    Message,
    /// grpc-go status NotFound, which CoreDNS answers with NXDOMAIN.
    NotFound,
}

enum Failure {
    /// The connection closed before the Upstream could have acted on the request.
    Stale,
    Other(io::Error),
}

impl From<Failure> for io::Error {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Stale => io::ErrorKind::ConnectionAborted.into(),
            Failure::Other(error) => error,
        }
    }
}

fn invalid(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Failure {
    Failure::Other(io::Error::new(io::ErrorKind::InvalidData, message))
}

/// A `grpc-timeout` of `millis` milliseconds, formatted on the stack.
fn timeout_value(mut millis: u32) -> HeaderValue {
    // PROTOCOL-HTTP2 "Timeout": ASCII digits, then the unit `m`.
    let mut text = [b'm'; 9];
    let mut start = text.len() - 1;
    loop {
        start -= 1;
        text[start] = b'0' + (millis % 10) as u8;
        millis /= 10;
        if millis == 0 {
            break;
        }
    }
    HeaderValue::from_bytes(&text[start..]).expect("ASCII digits and a unit")
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One Upstream: dialled on first use, as `grpc.NewClient` does, and kept for later calls.
pub(super) struct Client {
    pub(super) target: Target,
    tls: Option<Tls>,
    uri: Uri,
    sender: Mutex<Option<Sender>>,
    dial: tokio::sync::Mutex<()>,
    stopped: AtomicBool,
}

impl Client {
    /// `authority` is the `:authority` of calls: the credentials' server name, else the address.
    pub(super) fn new(target: Target, tls: Option<Tls>, authority: &str) -> io::Result<Self> {
        let scheme = if tls.is_some() { "https" } else { "http" };
        let uri = format!("{scheme}://{authority}{}", grpc::PATH)
            .parse()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            target,
            tls,
            uri,
            sender: Mutex::new(None),
            dial: tokio::sync::Mutex::new(()),
            stopped: AtomicBool::new(false),
        })
    }

    /// Close the connection and refuse new calls.
    pub(super) fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        lock(&self.sender).take();
    }

    /// Call `Query` with the DNS Message `message`; `out` receives the reply Message or is left empty.
    pub(super) async fn call(
        &self,
        message: &Wire,
        deadline: Instant,
        out: &mut Vec<u8>,
    ) -> io::Result<Reply> {
        let mut retried = false;
        loop {
            let (mut sender, reused) = self.connection().await?;
            match round_trip(&mut sender, self.request(message, deadline), out).await {
                // grpc-go retries a call transparently when the transport closed before the server saw it.
                Err(Failure::Stale) if reused && !std::mem::replace(&mut retried, true) => {}
                result => return result.map_err(io::Error::from),
            }
        }
    }

    fn request(&self, message: &Wire, deadline: Instant) -> Request<Body> {
        // PROTOCOL-HTTP2 "Timeout": whole milliseconds, at most eight digits; the call context carries the deadline.
        let millis = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .clamp(1, 99_999_999);
        Request::post(self.uri.clone())
            .header(CONTENT_TYPE, HeaderValue::from_static(grpc::CONTENT_TYPE))
            // PROTOCOL-HTTP2 "Request-Headers": `te: trailers` is required.
            .header("te", HeaderValue::from_static("trailers"))
            .header(
                HeaderName::from_static("grpc-timeout"),
                timeout_value(millis as u32),
            )
            .body(Full::new(
                FramePrefix::new(message.remaining()).chain(message.clone()),
            ))
            .expect("constant header names and numeric values")
    }

    fn cached(&self) -> Option<Sender> {
        lock(&self.sender)
            .as_ref()
            .filter(|sender| !sender.is_closed())
            .cloned()
    }

    /// A usable connection, and whether it was already open.
    async fn connection(&self) -> io::Result<(Sender, bool)> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(io::ErrorKind::NotConnected.into());
        }
        if let Some(sender) = self.cached() {
            return Ok((sender, true));
        }
        // RFC 9113 §9.1: Queries that arrive together share the connection the first one opens.
        let _dialing = self.dial.lock().await;
        if let Some(sender) = self.cached() {
            return Ok((sender, true));
        }
        let sender = self.connect().await?;
        let mut slot = lock(&self.sender);
        // `stop` sets the flag before it clears the slot, so a check under the lock leaves no stray connection.
        if !self.stopped.load(Ordering::Acquire) {
            *slot = Some(sender.clone());
        }
        Ok((sender, false))
    }

    async fn connect(&self) -> io::Result<Sender> {
        match &self.target {
            Target::Tcp(address) => self.connect_tcp(TcpStream::connect(address).await?).await,
            Target::Host { host, port } => {
                self.connect_tcp(TcpStream::connect((host.as_str(), *port)).await?)
                    .await
            }
            Target::Unix(path) => self.start(UnixStream::connect(path).await?).await,
            Target::Invalid(reason) => {
                Err(io::Error::new(io::ErrorKind::InvalidInput, reason.as_str()))
            }
        }
    }

    async fn connect_tcp(&self, tcp: TcpStream) -> io::Result<Sender> {
        // grpc-go sets TCP_NODELAY on every connection.
        tcp.set_nodelay(true)?;
        self.start(tcp).await
    }

    async fn start<T>(&self, stream: T) -> io::Result<Sender>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Some(tls) = &self.tls else {
            return handshake(stream).await;
        };
        // RFC 8446 §4.4.3: the server proves its certificate for the name the Corefile gives, else its address.
        let stream = TlsConnector::from(tls.config.clone())
            .connect(tls.server_name.clone(), stream)
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

async fn handshake<T>(stream: T) -> io::Result<Sender>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(connection);
    Ok(sender)
}

/// Send `request` and read the reply into `out`, which holds the DNS Message when the call succeeds.
async fn round_trip(
    sender: &mut Sender,
    request: Request<Body>,
    out: &mut Vec<u8>,
) -> Result<Reply, Failure> {
    out.clear();
    let result = read_reply(sender, request, out).await;
    if !matches!(result, Ok(Reply::Message)) {
        out.clear();
    }
    result
}

async fn read_reply(
    sender: &mut Sender,
    request: Request<Body>,
    out: &mut Vec<u8>,
) -> Result<Reply, Failure> {
    // RFC 9113 §8.7: no response head yet, so the caller may send a call that used a dead connection again; DNS Queries are idempotent.
    sender.ready().await.map_err(|_| Failure::Stale)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| Failure::Stale)?;
    let (parts, mut body) = response.into_parts();
    // PROTOCOL-HTTP2 "Responses": a gRPC response is HTTP 200, with the status in the headers or trailers.
    if parts.status != StatusCode::OK {
        return Err(invalid(format!("HTTP status {}", parts.status)));
    }
    // PROTOCOL-HTTP2 "Responses": every response, Trailers-Only included, carries an application/grpc content-type.
    if !parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(grpc::is_content_type)
    {
        return Err(invalid("missing or unexpected content-type"));
    }
    let mut trailers = None;
    let mut framed = false;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| Failure::Other(io::Error::other(error)))?;
        framed = true;
        match frame.into_data() {
            Ok(data) => {
                // grpc-go MaxCallRecvMsgSize: a message over 65539 octets is ResourceExhausted.
                if out.len() + data.len() > grpc::HEADER_LEN + grpc::MAX_PAYLOAD_LEN {
                    return Err(invalid("received message larger than the limit"));
                }
                out.extend_from_slice(&data);
            }
            Err(frame) => trailers = frame.into_trailers().ok(),
        }
    }
    // PROTOCOL-HTTP2 "Responses": only the Trailers-Only form (no body at all) has `grpc-status` in the headers.
    if parts.headers.contains_key("grpc-status") && framed {
        return Err(invalid("grpc-status in headers of a response with a body"));
    }
    let headers = trailers.as_ref().unwrap_or(&parts.headers);
    // PROTOCOL-HTTP2 "Responses": a stream that ends without `grpc-status` is Unknown.
    let status = headers
        .get("grpc-status")
        .ok_or_else(|| invalid("stream ended without grpc-status"))?;
    match Code::from_header(status.as_bytes()) {
        Code::Ok => {}
        // CoreDNS v1.15.0 plugin/grpc/proxy.go query: NotFound means NXDOMAIN.
        Code::NotFound => return Ok(Reply::NotFound),
        code => return Err(invalid(format!("grpc status {code:?}"))),
    }
    let header = grpc::parse_header(out)
        .ok_or_else(|| invalid("no response message"))?
        .map_err(|status| invalid(status.message.into_owned()))?;
    // PROTOCOL-HTTP2 "Compressed-Flag": no `grpc-accept-encoding` is sent, so a compressed message is unexpected.
    if header.compressed || header.len > grpc::MAX_PAYLOAD_LEN {
        return Err(invalid("unexpected compressed or oversized message"));
    }
    // A unary call carries exactly one message.
    if out.len() != grpc::HEADER_LEN + header.len {
        return Err(invalid("response is not exactly one message"));
    }
    let message = grpc::decode_packet(&out[grpc::HEADER_LEN..]).map_err(invalid)?;
    // CoreDNS v1.15.0 plugin/grpc/proxy.go validateDNSSize: at most 65535 octets.
    if message.len() > grpc::MAX_MESSAGE_LEN {
        return Err(invalid("dns message exceeds size limit"));
    }
    let start = message.as_ptr() as usize - out.as_ptr() as usize;
    let end = start + message.len();
    out.copy_within(start..end, 0);
    out.truncate(end - start);
    Ok(Reply::Message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn timeouts_are_whole_milliseconds() {
        for (millis, text) in [(1, "1m"), (5000, "5000m"), (99_999_999, "99999999m")] {
            assert_eq!(timeout_value(millis), text);
        }
    }

    #[test]
    fn a_buffer_returns_to_the_pool_only_when_nothing_else_holds_it() {
        let pool = Pool::default();
        let mut loan = pool.take();
        loan.buffer().extend_from_slice(b"abc");
        let pointer = loan.wire().chunk().as_ptr();
        drop(loan);
        let mut again = pool.take();
        assert_eq!(again.buffer().as_ptr(), pointer);
        again.buffer().extend_from_slice(b"xyz");
        let wire = again.wire();
        drop(again);
        assert!(lock(&pool.0).is_empty());
        assert_eq!(wire.chunk(), b"xyz");
    }

    async fn reaches(bind: &str, host: &str) {
        let Ok(listener) = TcpListener::bind(bind).await else {
            return;
        };
        let port = listener.local_addr().unwrap().port();
        let target = Target::Host {
            host: host.into(),
            port,
        };
        let client = Client::new(target, None, "localhost").unwrap();
        let (accepted, connected) = tokio::join!(listener.accept(), client.connect());
        connected.unwrap();
        accepted.unwrap();
    }

    // Go net: a name is resolved when dialling.
    #[tokio::test]
    async fn a_host_name_is_resolved_at_dial() {
        reaches("127.0.0.1:0", "localhost").await;
    }

    // Go net: an IPv6 zone is resolved when dialling; interface index 1 is the loopback.
    #[tokio::test]
    async fn a_scoped_ipv6_address_is_dialled_with_its_zone() {
        reaches("[::1]:0", "::1%1").await;
    }

    #[tokio::test]
    async fn an_invalid_target_fails_every_dial() {
        let client = Client::new(Target::Invalid("bad".into()), None, "localhost").unwrap();
        let error = client.connect().await.err().unwrap();
        assert_eq!(error.to_string(), "bad");
    }
}
