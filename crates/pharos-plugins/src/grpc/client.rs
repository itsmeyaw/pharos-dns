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

use bytes::{Buf, Bytes, buf::Chain};
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode, Uri, client::conn::http2, header::CONTENT_TYPE};
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

type Body = Full<Chain<FramePrefix, Bytes>>;
type Sender = http2::SendRequest<Body>;

/// Where an Upstream listens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Target {
    Tcp(SocketAddr),
    Unix(PathBuf),
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

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One Upstream: dialled on first use, as `grpc.NewClient` does, and kept for later calls.
pub(super) struct Client {
    target: Target,
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
        message: &Bytes,
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

    fn request(&self, message: &Bytes, deadline: Instant) -> Request<Body> {
        // PROTOCOL-HTTP2 "Timeout": whole milliseconds, at most eight digits; the call context carries the deadline.
        let millis = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .clamp(1, 99_999_999);
        Request::post(self.uri.clone())
            .header(CONTENT_TYPE, grpc::CONTENT_TYPE)
            // PROTOCOL-HTTP2 "Request-Headers": `te: trailers` is required.
            .header("te", "trailers")
            .header("grpc-timeout", format!("{millis}m"))
            .body(Full::new(
                FramePrefix::new(message.len()).chain(message.clone()),
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
            Target::Tcp(address) => {
                let tcp = TcpStream::connect(address).await?;
                // grpc-go sets TCP_NODELAY on every connection.
                tcp.set_nodelay(true)?;
                self.start(tcp).await
            }
            Target::Unix(path) => self.start(UnixStream::connect(path).await?).await,
        }
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
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| Failure::Other(io::Error::other(error)))?;
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
