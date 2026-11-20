//! DNS over gRPC Listener: TLS with ALPN `h2`, then hyper serves one unary call per HTTP/2 stream.
//!
//! The wire rules live in [`crate::grpc`]; this module owns the call lifecycle: validating the
//! request headers, reading one length-prefixed message, running the Plugin Chain and answering
//! with a Response message or a gRPC status.

use std::{
    convert::Infallible,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Buf, buf::Chain};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode,
    body::Incoming,
    header::{CONTENT_TYPE, HeaderName, HeaderValue},
    http::request::Parts,
    server::conn::http2,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle, time::timeout};

use crate::{
    Action, Handler,
    conn::{Accepted, Activity, InFlight, Pool, Pooled, Secured, drive},
    doh,
    grpc::{self, Code, FramePrefix, Status},
};

const GRPC_STATUS: HeaderName = HeaderName::from_static("grpc-status");
const GRPC_MESSAGE: HeaderName = HeaderName::from_static("grpc-message");
const GRPC_ENCODING: HeaderName = HeaderName::from_static("grpc-encoding");
const GRPC_TIMEOUT: HeaderName = HeaderName::from_static("grpc-timeout");

/// Room for the pseudo-headers and the few metadata fields a unary call carries.
const MAX_HEADER_LIST: u32 = 64 * 1024;

/// Connection and stream limits of a `grpc://` Listener; zero means unbounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrpcOptions {
    /// Concurrent TCP connections.
    pub max_connections: usize,
    /// Concurrent HTTP/2 streams per connection.
    pub max_streams: u32,
}

impl Default for GrpcOptions {
    fn default() -> Self {
        Self {
            max_connections: grpc::DEFAULT_MAX_CONNECTIONS,
            max_streams: grpc::DEFAULT_MAX_STREAMS,
        }
    }
}

/// A gRPC Response: one message then the trailers, or no data for a Trailers-Only status.
struct Reply {
    data: Option<Chain<FramePrefix, Pooled>>,
    trailers: Option<HeaderMap>,
}

impl Body for Reply {
    type Data = Chain<FramePrefix, Pooled>;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Infallible>>> {
        let reply = &mut *self;
        // PROTOCOL-HTTP2: a Response is its message, if any, then the trailers carrying grpc-status.
        Poll::Ready(
            reply
                .data
                .take()
                .map(Frame::data)
                .or_else(|| reply.trailers.take().map(Frame::trailers))
                .map(Ok),
        )
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none() && self.trailers.is_none()
    }
}

struct Connection<H> {
    handler: Arc<H>,
    peer: SocketAddr,
    tlv: Option<Arc<str>>,
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
        |handler| handler.grpc().max_connections,
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
    let options = handler.grpc();
    let limits = handler.tcp_options();
    let Some(Secured { stream, peer, tlv }) =
        crate::conn::handshake(stream, peer, &*handler, limits, &mut stopped).await
    else {
        return;
    };
    // RFC 7301 §3.2: gRPC needs HTTP/2; grpc-go v1.84 refuses a handshake that did not select "h2".
    if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
        return;
    }
    let activity = Arc::new(Activity::new());
    let connection = Arc::new(Connection {
        handler,
        peer,
        tlv,
        pool,
        activity: Arc::clone(&activity),
        read: limits.read,
    });
    let service = service_fn(move |request| {
        let connection = Arc::clone(&connection);
        async move { Ok::<_, Infallible>(respond(&connection, request).await) }
    });
    let mut builder = http2::Builder::new(TokioExecutor::new());
    // RFC 9113 §6.5.2: SETTINGS_MAX_CONCURRENT_STREAMS bounds the peer's open streams; none means unbounded.
    builder.max_concurrent_streams((options.max_streams != 0).then_some(options.max_streams));
    builder.max_header_list_size(MAX_HEADER_LIST);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
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

async fn respond<H: Handler>(
    connection: &Connection<H>,
    request: Request<Incoming>,
) -> Response<Reply> {
    let _active = InFlight::new(&connection.activity);
    let (parts, body) = request.into_parts();
    let deadline = match check_headers(&parts) {
        Ok(deadline) => deadline,
        Err((http, status)) => return trailers_only(http, &status),
    };
    let call = call(connection, body);
    let outcome = match deadline {
        // PROTOCOL-HTTP2 "Timeout": the server ends a call that outlives its deadline.
        Some(deadline) => timeout(deadline, call).await.unwrap_or_else(|_| {
            Err(Status::new(
                Code::DeadlineExceeded,
                "context deadline exceeded",
            ))
        }),
        None => call.await,
    };
    match outcome {
        Ok(message) => {
            let mut response = Response::new(Reply {
                data: Some(FramePrefix::new(message.len()).chain(message)),
                trailers: Some(ok_trailers()),
            });
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static(grpc::CONTENT_TYPE));
            response
        }
        Err(status) => trailers_only(StatusCode::OK, &status),
    }
}

/// Check the request headers that decide whether the call is a DNS Query; return its deadline.
// CoreDNS v1.15.0 uses grpc-go v1.84.0 http2_server.go operateHeaders and server.go handleStream.
fn check_headers(parts: &Parts) -> Result<Option<Duration>, (StatusCode, Status)> {
    let content_type = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !grpc::is_content_type(content_type) {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Status::new(
                Code::InvalidArgument,
                format!("invalid gRPC request content-type {content_type:?}"),
            ),
        ));
    }
    if parts.method != Method::POST {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            Status::new(
                Code::Internal,
                format!("invalid gRPC request method {:?}", parts.method.as_str()),
            ),
        ));
    }
    let deadline = match parts.headers.get(GRPC_TIMEOUT) {
        None => None,
        Some(value) => Some(
            value
                .to_str()
                .ok()
                .and_then(grpc::parse_timeout)
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        Status::new(Code::Internal, "malformed grpc-timeout"),
                    )
                })?,
        ),
    };
    let path = parts.uri.path();
    let unimplemented =
        |message: String| (StatusCode::OK, Status::new(Code::Unimplemented, message));
    if path != grpc::PATH {
        // grpc-go server.go handleStream: the service, then the method, are looked up in turn.
        let Some((service, method)) = path.strip_prefix('/').and_then(|path| path.split_once('/'))
        else {
            return Err(unimplemented(format!("malformed method name: {path:?}")));
        };
        return Err(unimplemented(if service == "coredns.dns.DnsService" {
            format!("unknown method {method} for service {service}")
        } else {
            format!("unknown service {service}")
        }));
    }
    // PROTOCOL-HTTP2 "Message-Encoding": no compression algorithm is registered, as in CoreDNS.
    if let Some(encoding) = parts
        .headers
        .get(GRPC_ENCODING)
        .and_then(|value| value.to_str().ok())
        .filter(|encoding| !encoding.is_empty() && *encoding != "identity")
    {
        return Err(unimplemented(format!(
            "grpc: Decompressor is not installed for grpc-encoding {encoding:?}"
        )));
    }
    Ok(deadline)
}

/// Read the request message, run the Plugin Chain and return the DNS Response.
async fn call<H: Handler>(connection: &Connection<H>, body: Incoming) -> Result<Pooled, Status> {
    let mut request = connection.pool.take();
    timeout(connection.read, read_message(body, &mut request))
        .await
        .map_err(|_| Status::new(Code::DeadlineExceeded, "request message read timed out"))??;
    let message = grpc::decode_packet(&request[grpc::HEADER_LEN..]).map_err(|error| {
        // grpc-go rpc_util.go recvAndDecompress: an undecodable message is Internal.
        Status::new(
            Code::Internal,
            format!("grpc: error unmarshalling request: {error}"),
        )
    })?;
    // CoreDNS v1.15.0 server_grpc.go Query: a plain error becomes status Unknown; the payload limit
    // already keeps a Message within the 65535-octet check CoreDNS makes here.
    // CoreDNS v1.15.0 server_grpc.go Query: dnsutil.UnpackRequest rejects what miekg/dns would not accept.
    if !doh::accept(message) {
        return Err(Status::new(Code::Unknown, "dns: invalid request message"));
    }
    let mut response = connection.pool.take();
    match crate::conn::handle(
        &connection.handler,
        connection.tlv.as_deref(),
        message,
        connection.peer,
        &mut response,
    )
    .await
    {
        // grpc-go server.go sendResponse: ResourceExhausted above grpc.MaxSendMsgSize(maxProtobufPayloadBytes).
        Action::Respond if response.len() > grpc::MAX_MESSAGE_LEN => Err(Status::new(
            Code::ResourceExhausted,
            format!(
                "grpc: trying to send message larger than max ({} vs. {})",
                response.len() + 4,
                grpc::MAX_PAYLOAD_LEN
            ),
        )),
        Action::Respond => Ok(response),
        Action::Drop | Action::Stream(_) => Err(Status::new(Code::Internal, "no response")),
    }
}

/// Append the one request message, header included, to `out`.
async fn read_message(mut body: Incoming, out: &mut Vec<u8>) -> Result<(), Status> {
    let mut expected = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| Status::new(Code::Cancelled, "context canceled"))?;
        let Some(data) = frame.data_ref() else {
            continue;
        };
        out.extend_from_slice(data);
        if expected.is_none()
            && let Some(header) = grpc::parse_header(out)
        {
            let header = header?;
            // PROTOCOL-HTTP2 "Message-Encoding": a compressed message needs an algorithm, and none is installed.
            if header.compressed {
                return Err(Status::new(
                    Code::Internal,
                    "grpc: compressed flag set with identity or empty encoding",
                ));
            }
            // CoreDNS v1.15.0 server_grpc.go: grpc.MaxRecvMsgSize(maxProtobufPayloadBytes), checked on the header.
            if header.len > grpc::MAX_PAYLOAD_LEN {
                return Err(Status::new(
                    Code::ResourceExhausted,
                    format!(
                        "grpc: received message larger than max ({} vs. {})",
                        header.len,
                        grpc::MAX_PAYLOAD_LEN
                    ),
                ));
            }
            expected = Some(grpc::HEADER_LEN + header.len);
        }
        // PROTOCOL-HTTP2: a unary call carries exactly one request message.
        if expected.is_some_and(|total| out.len() > total) {
            return Err(Status::new(
                Code::Internal,
                "grpc: unexpected data after the request message",
            ));
        }
    }
    match expected {
        Some(total) if out.len() == total => Ok(()),
        _ if out.is_empty() => Err(Status::new(Code::Unknown, "EOF")),
        _ => Err(Status::new(Code::Internal, "unexpected EOF")),
    }
}

fn ok_trailers() -> HeaderMap {
    // Built once: a Response clones the map instead of rebuilding it.
    static TRAILERS: OnceLock<HeaderMap> = OnceLock::new();
    TRAILERS
        .get_or_init(|| {
            let mut trailers = HeaderMap::new();
            trailers.insert(GRPC_STATUS, HeaderValue::from_static("0"));
            trailers
        })
        .clone()
}

/// A Response with no message: the status travels in the headers, which end the stream.
// PROTOCOL-HTTP2 "Trailers-Only": grpc-status in the response headers, HTTP status 200 unless the request was not gRPC.
fn trailers_only(http: StatusCode, status: &Status) -> Response<Reply> {
    let mut response = Response::new(Reply {
        data: None,
        trailers: None,
    });
    *response.status_mut() = http;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(grpc::CONTENT_TYPE));
    headers.insert(GRPC_STATUS, HeaderValue::from(status.code as u16));
    if !status.message.is_empty() {
        let message = grpc::escape_message(&status.message);
        headers.insert(
            GRPC_MESSAGE,
            HeaderValue::from_str(&message).expect("escaped message is printable ASCII"),
        );
    }
    response
}
