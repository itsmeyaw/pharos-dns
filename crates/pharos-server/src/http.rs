//! Small HTTP listener for operational endpoints: HTTP/1 over TCP, or HTTP/1 and HTTP/2 over TLS.

use std::{
    borrow::Cow,
    convert::Infallible,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use aws_lc_rs::digest::{SHA256, digest};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    Request, Response, StatusCode,
    body::Incoming,
    header::{
        ALLOW, AUTHORIZATION, CONTENT_TYPE, ETAG, HeaderMap, HeaderName, HeaderValue, IF_MATCH,
        IF_NONE_MATCH, WWW_AUTHENTICATE, X_CONTENT_TYPE_OPTIONS,
    },
    server::conn::{http1, http2},
    service::{Service, service_fn},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::watch,
    task::{JoinHandle, JoinSet},
    time::Sleep,
};

use crate::{
    basic_auth::BasicAuth,
    tls::{ServerTls, TlsAcceptor},
};

const MAX_CONNECTIONS: usize = 1024;
const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HTTP1_BUFFER_SIZE: usize = 16 * 1024;

/// How a [`Listener`] protects its endpoints; the default is cleartext HTTP/1 without credentials.
#[derive(Clone, Default)]
pub struct Security {
    /// Serve HTTPS with this identity.
    pub tls: Option<ServerTls>,
    /// Offer HTTP/2 through ALPN next to HTTP/1.1; ignored without `tls`.
    pub http2: bool,
    /// Header fields set on every response, including errors.
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// Requests must carry credentials that match.
    pub basic_auth: Option<Arc<BasicAuth>>,
}

struct Guard {
    acceptor: Option<TlsAcceptor>,
    http2: bool,
    headers: Vec<(HeaderName, HeaderValue)>,
    basic_auth: Option<Arc<BasicAuth>>,
}

struct State<R> {
    route: R,
    guard: Guard,
    /// Longest time one connection may stay open.
    lifetime: Duration,
}

/// Maps one request to a response: `Plain` wraps the synchronous callbacks, `AsyncRoute` the asynchronous one.
trait Route: Send + Sync + 'static {
    fn call(
        &self,
        request: Request<Incoming>,
        secure: bool,
    ) -> impl Future<Output = Response<Full<Bytes>>> + Send;
}

struct Plain<F>(F);

impl<F> Route for Plain<F>
where
    F: Fn(&str, &str) -> Option<(u16, &'static str, String)> + Send + Sync + 'static,
{
    async fn call(&self, request: Request<Incoming>, secure: bool) -> Response<Full<Bytes>> {
        response_for_request(&self.0, request, secure)
    }
}

/// A request handed to an asynchronous route.
pub struct RouteRequest {
    /// Method token as sent, for example `GET`; HEAD is delivered as `GET` and its body is dropped.
    pub method: String,
    pub path: String,
    /// Raw query string without the leading `?`.
    pub query: Option<String>,
}

/// A complete response from an asynchronous route.
pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    /// Extra header fields as lowercase `(name, value)` pairs; an invalid status, content type or pair makes the response a 500.
    pub headers: Vec<(&'static str, &'static str)>,
    pub body: Bytes,
}

struct AsyncRoute<F>(F);

impl<F, Fut> Route for AsyncRoute<F>
where
    F: Fn(RouteRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Reply> + Send + 'static,
{
    async fn call(&self, request: Request<Incoming>, secure: bool) -> Response<Full<Bytes>> {
        if misdirected(&request, secure) {
            // RFC 9110 §7.4: Cleartext listeners reject absolute HTTPS targets.
            return text_response(StatusCode::MISDIRECTED_REQUEST, "Misdirected Request\n");
        }
        let method = request.method().as_str();
        if !recognized_method(method) {
            // RFC 9110 §9.1: Unsupported method tokens receive 501.
            return text_response(StatusCode::NOT_IMPLEMENTED, "Not Implemented\n");
        }
        // RFC 9110 §9.3.2: HEAD gets the selected GET representation; hyper drops the body.
        let method = if method == "HEAD" { "GET" } else { method }.to_owned();
        let reply = (self.0)(RouteRequest {
            method,
            path: request.uri().path().to_owned(),
            query: request.uri().query().map(str::to_owned),
        })
        .await;
        // RFC 9110 §15.6.1: A route reply that cannot be serialized is a server failure.
        reply_response(reply).unwrap_or_else(|| {
            text_response(StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error\n")
        })
    }
}

fn reply_response(reply: Reply) -> Option<Response<Full<Bytes>>> {
    // RFC 9110 §15: A status code is three digits.
    let status = StatusCode::from_u16(reply.status).ok()?;
    let mut response = Response::new(Full::new(reply.body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    // RFC 9110 §8.3: Content-Type describes the representation; a field value cannot hold control bytes.
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(reply.content_type).ok()?,
    );
    for (name, value) in reply.headers {
        // RFC 9110 §5.1, §5.5: Field names are tokens and field values are visible characters.
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).ok()?,
            HeaderValue::from_str(value).ok()?,
        );
    }
    Some(response)
}

/// RFC 9110 §7.4: A cleartext listener is not authoritative for an absolute `https` target.
fn misdirected(request: &Request<Incoming>, secure: bool) -> bool {
    !secure && request.uri().scheme_str() == Some("https")
}

fn text_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(body.as_bytes())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

/// HTTP listener whose callback maps GET paths to `(content_type, body)`.
/// The callback runs on a Tokio worker and must not block it.
pub struct Listener {
    address: SocketAddr,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<io::Result<()>>>,
}

/// Periodic health self-probe, cancelled on drop.
pub struct HealthProbe(JoinHandle<()>);

impl HealthProbe {
    pub fn start(address: &str, registry: crate::metrics::Registry) -> Self {
        let address = if address.starts_with(':') {
            format!("localhost{address}")
        } else {
            address.to_owned()
        };
        Self(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                let start = std::time::Instant::now();
                let result =
                    tokio::time::timeout(Duration::from_secs(3), health_request(&address)).await;
                let failed = !matches!(result, Ok(Ok(())));
                let elapsed = start.elapsed();
                registry.observe_health(elapsed.as_secs_f64(), failed);
                if failed {
                    crate::logging::log(
                        "WARN",
                        "health",
                        &format!("Local health request to http://{address}/health failed"),
                    );
                } else if elapsed > Duration::from_secs(1) {
                    crate::logging::log(
                        "WARN",
                        "health",
                        &format!(
                            "Local health request to http://{address}/health took more than 1s: {elapsed:?}"
                        ),
                    );
                }
            }
        }))
    }
}

impl Drop for HealthProbe {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn health_request(address: &str) -> io::Result<()> {
    // RFC 9110 §4.3.2: Connect to the configured host and port and request the target path.
    let stream = tokio::net::TcpStream::connect(address).await?;
    // RFC 9110 §6.2: Hyper sends the health probe using HTTP/1.1 control data.
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(io::Error::other)?;
    // RFC 9110 §10.1.3: The internal health probe sends no Referer field.
    let request = Request::builder()
        // RFC 9110 §9.3.1: The health probe sends GET without content.
        .uri("/health")
        // RFC 9110 §7.2: Send the target authority in the Host field.
        .header("host", address)
        // RFC 9110 §10.1.5: Identify this robotic user agent.
        .header("user-agent", "Pharos health probe")
        .body(Full::<Bytes>::default())
        .map_err(io::Error::other)?;
    let response = sender.send_request(request);
    tokio::pin!(connection, response);
    tokio::select! {
        biased;
        result = &mut response => result.map(|_| ()).map_err(io::Error::other),
        result = &mut connection => result.map_err(io::Error::other).and_then(|()| Err(io::Error::other("health connection closed"))),
    }
}

impl Listener {
    /// Bind an IP address or DNS hostname, then start accepting connections.
    pub async fn bind<F>(address: &str, route: F) -> io::Result<Self>
    where
        F: Fn(&str) -> Option<(&'static str, String)> + Send + Sync + 'static,
    {
        Self::bind_with_status(address, move |path| {
            // RFC 9110 §15.3.1: A 200 metrics response carries the requested representation.
            route(path).map(|(content_type, body)| (200, content_type, body))
        })
        .await
    }

    /// Bind an endpoint whose callback also selects the HTTP status.
    pub async fn bind_with_status<F>(address: &str, route: F) -> io::Result<Self>
    where
        F: Fn(&str) -> Option<(u16, &'static str, String)> + Send + Sync + 'static,
    {
        Self::bind_with_methods(address, move |method, path| {
            if method == "GET" {
                // RFC 9110 §9.3.1: GET retrieves the current representation for a metrics route.
                route(path)
            } else {
                // RFC 9110 §9.1: Existing resources reject recognized methods with 405.
                route(path).map(|_| {
                    (
                        405,
                        "text/plain; charset=utf-8",
                        "Method Not Allowed\n".into(),
                    )
                })
            }
        })
        .await
    }

    /// Bind an endpoint callback that receives a method and path; the listener only serves GET and HEAD.
    pub async fn bind_with_methods<F>(address: &str, route: F) -> io::Result<Self>
    where
        F: Fn(&str, &str) -> Option<(u16, &'static str, String)> + Send + Sync + 'static,
    {
        Self::bind_secured(address, route, Security::default()).await
    }

    /// [`Listener::bind_with_methods`] with TLS, response headers and basic authentication.
    pub async fn bind_secured<F>(address: &str, route: F, security: Security) -> io::Result<Self>
    where
        F: Fn(&str, &str) -> Option<(u16, &'static str, String)> + Send + Sync + 'static,
    {
        Self::bind_route(address, Plain(route), security, TIMEOUT).await
    }

    /// Bind an endpoint whose route is asynchronous and returns binary bodies, headers and any status.
    /// The route receives every recognized method and chooses 404 or 405 itself; it runs on a Tokio worker.
    /// `lifetime` caps each connection instead of the five seconds the other constructors use;
    /// shutdown still drains for five seconds, so a request running longer is cut off then.
    pub async fn bind_async<F, Fut>(address: &str, route: F, lifetime: Duration) -> io::Result<Self>
    where
        F: Fn(RouteRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Reply> + Send + 'static,
    {
        Self::bind_route(address, AsyncRoute(route), Security::default(), lifetime).await
    }

    async fn bind_route<R: Route>(
        address: &str,
        route: R,
        security: Security,
        lifetime: Duration,
    ) -> io::Result<Self> {
        let guard = Guard {
            // RFC 7301 §3.1: the server selects h2 or http/1.1 from the client's offer.
            acceptor: security.tls.as_ref().map(|tls| {
                let protocols: &[&[u8]] = if security.http2 {
                    &[b"h2", b"http/1.1"]
                } else {
                    &[b"http/1.1"]
                };
                tls.with_alpn(protocols).acceptor()
            }),
            http2: security.http2,
            headers: security.headers,
            basic_auth: security.basic_auth,
        };
        let address = if address.ends_with(':') {
            Cow::Owned(format!("{address}0"))
        } else {
            Cow::Borrowed(address)
        };
        let wildcard_port = address
            .strip_prefix(':')
            .and_then(|port| port.parse().ok())
            .or_else(|| match address.parse::<SocketAddr>() {
                Ok(SocketAddr::V6(addr)) if addr.ip().is_unspecified() => Some(addr.port()),
                _ => None,
            });
        let listener = if let Some(port) = wildcard_port {
            match dual_stack_listener(port)? {
                Some(listener) => TcpListener::from_std(listener)?,
                None => TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).await?,
            }
        } else {
            TcpListener::bind(address.as_ref()).await?
        };
        let address = listener.local_addr()?;
        let (stop, mut receiver) = watch::channel(false);
        let state = Arc::new(State {
            route,
            guard,
            lifetime,
        });
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            let result = loop {
                tokio::select! {
                    _ = receiver.changed() => break Ok(()),
                    Some(result) = connections.join_next(), if !connections.is_empty() => {
                        if let Err(error) = result {
                            crate::logging::log("ERROR", "http", &format!("HTTP connection failed: {error}"));
                        }
                    },
                    accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                        let (stream, _) = match accepted {
                            Ok(value) => value,
                            Err(error) => {
                                crate::logging::log("ERROR", "http", &format!("HTTP accept failed: {error}"));
                                tokio::select! {
                                    _ = receiver.changed() => break Ok(()),
                                    _ = tokio::time::sleep(Duration::from_millis(100)) => {},
                                }
                                continue;
                            }
                        };
                        let state = Arc::clone(&state);
                        let mut stop = receiver.clone();
                        connections.spawn(async move {
                            // shortcut: cap the connection lifetime until per-request read, write and idle deadlines are supported.
                            let deadline = tokio::time::sleep(state.lifetime);
                            tokio::pin!(deadline);
                            let Some(acceptor) = &state.guard.acceptor else {
                                serve_http1(stream, &state, &mut stop, deadline).await;
                                return;
                            };
                            let handshake = tokio::select! {
                                _ = stop.changed() => return,
                                () = &mut deadline => return,
                                handshake = acceptor.accept(stream) => handshake,
                            };
                            let Ok(stream) = handshake else { return };
                            // RFC 7301 §3.2: the protocol the handshake selected decides the HTTP version.
                            if state.guard.http2 && stream.get_ref().1.alpn_protocol() == Some(b"h2") {
                                serve_http2(stream, &state, &mut stop, deadline).await;
                            } else {
                                serve_http1(stream, &state, &mut stop, deadline).await;
                            }
                        });
                    }
                }
            };
            drop(listener);
            if tokio::time::timeout(TIMEOUT, async {
                while connections.join_next().await.is_some() {}
            })
            .await
            .is_err()
            {
                connections.shutdown().await;
            }
            result
        });
        Ok(Self {
            address,
            stop,
            task: Some(task),
        })
    }

    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Stop accepting and drain connections for at most five seconds.
    pub async fn shutdown(mut self) -> io::Result<()> {
        self.stop.send_replace(true);
        match self.task.take() {
            Some(task) => task.await.map_err(io::Error::other)?,
            None => Ok(()),
        }
    }
}

fn dual_stack_listener(port: u16) -> io::Result<Option<std::net::TcpListener>> {
    let socket = match Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)) {
        Ok(socket) => socket,
        Err(error) if ipv6_unavailable(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    if let Err(error) = socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into()) {
        if ipv6_unavailable(&error) {
            return Ok(None);
        }
        return Err(error);
    }
    socket.listen(1024)?;
    Ok(Some(socket.into()))
}

fn ipv6_unavailable(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AddrNotAvailable
        || error.raw_os_error() == Some(libc::EAFNOSUPPORT)
}

fn service<R: Route>(
    state: &Arc<State<R>>,
) -> impl Service<
    Request<Incoming>,
    Response = Response<Full<Bytes>>,
    Error = Infallible,
    Future: Send + 'static,
> + Send
+ 'static {
    let state = Arc::clone(state);
    service_fn(move |request: Request<Incoming>| {
        let state = Arc::clone(&state);
        async move { Ok::<_, Infallible>(respond(&state, request).await) }
    })
}

async fn serve_http1<S, R: Route>(
    stream: S,
    state: &Arc<State<R>>,
    stop: &mut watch::Receiver<bool>,
    deadline: Pin<&mut Sleep>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // RFC 9110 §5.6.7: Hyper emits dates in IMF-fixdate format.
    // RFC 9110 §17.5: Bound combined request-target and field buffering.
    let connection = http1::Builder::new()
        .max_buf_size(MAX_HTTP1_BUFFER_SIZE)
        .serve_connection(TokioIo::new(stream), service(state));
    tokio::pin!(connection);
    finish(
        connection.as_mut(),
        http1::Connection::graceful_shutdown,
        stop,
        deadline,
    )
    .await;
}

async fn serve_http2<S, R: Route>(
    stream: S,
    state: &Arc<State<R>>,
    stop: &mut watch::Receiver<bool>,
    deadline: Pin<&mut Sleep>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let connection = http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service(state));
    tokio::pin!(connection);
    finish(
        connection.as_mut(),
        http2::Connection::graceful_shutdown,
        stop,
        deadline,
    )
    .await;
}

// RFC 9112 §9.8, RFC 9113 §6.8: a stop lets the request in flight finish before the connection closes.
async fn finish<C: Future<Output = hyper::Result<()>>>(
    mut connection: Pin<&mut C>,
    graceful: impl FnOnce(Pin<&mut C>),
    stop: &mut watch::Receiver<bool>,
    deadline: Pin<&mut Sleep>,
) {
    tokio::select! {
        _ = connection.as_mut() => {},
        () = deadline => {},
        _ = stop.changed() => {
            graceful(connection.as_mut());
            let _ = connection.await;
        }
    }
}

async fn respond<R: Route>(state: &State<R>, request: Request<Incoming>) -> Response<Full<Bytes>> {
    let guard = &state.guard;
    let permitted = match &guard.basic_auth {
        // RFC 7617 §2: credentials travel in the Authorization request header field.
        Some(auth) => auth.permits(request.headers().get(AUTHORIZATION)).await,
        None => true,
    };
    let mut response = if permitted {
        state.route.call(request, guard.acceptor.is_some()).await
    } else {
        unauthorized()
    };
    for (name, value) in &guard.headers {
        response.headers_mut().insert(name.clone(), value.clone());
    }
    response
}

fn unauthorized() -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(b"Unauthorized\n")));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    let headers = response.headers_mut();
    // RFC 9110 §11.6.1: a 401 response carries a WWW-Authenticate challenge.
    headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static("Basic"));
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    // Go net/http http.Error sets nosniff on its plain-text errors.
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

fn response_for_request<F>(
    route: &F,
    request: Request<Incoming>,
    secure: bool,
) -> Response<Full<Bytes>>
where
    F: Fn(&str, &str) -> Option<(u16, &'static str, String)>,
{
    let method = request.method().as_str();
    let path = request.uri().path();
    let is_metrics = path == "/metrics";
    let response = if misdirected(&request, secure) {
        // RFC 9110 §7.4: Cleartext listeners reject absolute HTTPS targets.
        Some((
            421,
            "text/plain; charset=utf-8",
            "Misdirected Request\n".into(),
        ))
    } else if method == "PUT" && request.headers().contains_key("content-range") {
        // RFC 9110 §14.5: Reject partial PUT when this resource does not support it.
        Some((400, "text/plain; charset=utf-8", "Bad Request\n".into()))
    } else if matches!(method, "GET" | "HEAD") {
        // RFC 9110 §9.3.2: HEAD uses GET's selected representation metadata.
        route("GET", path)
    } else if recognized_method(method) {
        // RFC 9110 §9.1: Existing resources reject recognized methods with 405.
        route(method, path).map(|_| {
            (
                405,
                "text/plain; charset=utf-8",
                "Method Not Allowed\n".into(),
            )
        })
    } else {
        // RFC 9110 §9.1: Unsupported method tokens receive 501.
        Some((501, "text/plain; charset=utf-8", "Not Implemented\n".into()))
    };
    let headers = request.into_parts().0.headers;
    let has_preconditions = headers.contains_key(IF_MATCH) || headers.contains_key(IF_NONE_MATCH);
    let mut result = Response::new(Full::default());
    match response {
        Some((status, content_type, mut body)) => {
            match (
                StatusCode::from_u16(status),
                HeaderValue::from_str(content_type),
            ) {
                (Ok(status), Ok(content_type)) => {
                    *result.status_mut() = status;
                    // RFC 9110 §5.1: Content-Type is registered.
                    result.headers_mut().insert(CONTENT_TYPE, content_type);
                    if status == StatusCode::METHOD_NOT_ALLOWED {
                        // RFC 9110 §10.2.1: Advertise the methods allowed for this resource.
                        result
                            .headers_mut()
                            .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
                    }
                    if status == StatusCode::SERVICE_UNAVAILABLE {
                        // RFC 9110 §15.6.4: Explain that readiness failure is temporary.
                        body = format!("Service temporarily unavailable: {body}");
                    }
                    if status == StatusCode::OK && (!is_metrics || has_preconditions) {
                        // RFC 9110 §8.8.3.1 deviation: Defer metrics tags to avoid hashing every scrape.
                        if let Ok(tag) = entity_tag(&body) {
                            result.headers_mut().insert(ETAG, tag);
                        }
                    }
                    // RFC 9110 §6.4: Send endpoint content as body.
                    *result.body_mut() = Full::new(Bytes::from(body));
                    if status.is_success() || status == StatusCode::PRECONDITION_FAILED {
                        apply_preconditions(&mut result, &headers);
                    }
                }
                // RFC 9110 §15.6.1: 500 reports a server failure.
                _ => {
                    *result.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    *result.headers_mut() = [(
                        CONTENT_TYPE,
                        HeaderValue::from_static("text/plain; charset=utf-8"),
                    )]
                    .into_iter()
                    .collect();
                    *result.body_mut() = Full::new(Bytes::from_static(b"Internal Server Error\n"));
                }
            }
        }
        // RFC 9110 §15.5.5: Explain missing operational resources.
        None => {
            *result.status_mut() = StatusCode::NOT_FOUND;
            *result.headers_mut() = [(
                CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            )]
            .into_iter()
            .collect();
            *result.body_mut() = Full::new(Bytes::from_static(b"Not Found\n"));
        }
    }
    result
}

fn recognized_method(method: &str) -> bool {
    // RFC 9110 §9.1: These standard methods are recognized but not implemented by operational routes.
    matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH"
    )
}

fn entity_tag(body: &str) -> Result<HeaderValue, hyper::header::InvalidHeaderValue> {
    // RFC 9110 §8.8.3.1: Hash the exact selected representation bytes for a strong validator.
    let digest = digest(&SHA256, body.as_bytes());
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut tag = String::with_capacity(66);
    tag.push('"');
    for byte in digest.as_ref() {
        tag.push(char::from(HEX[usize::from(*byte >> 4)]));
        tag.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    tag.push('"');
    HeaderValue::from_str(&tag)
}

fn apply_preconditions(response: &mut Response<Full<Bytes>>, headers: &HeaderMap) {
    let Some(current) = response.headers().get(ETAG) else {
        return;
    };
    let current = current.as_bytes();
    let if_match = conditional_tag_matches(headers, &IF_MATCH, current, false);
    if if_match == Some(false) {
        // RFC 9110 §§13.1.1, 13.2.2: A failed strong If-Match precedes If-None-Match.
        *response.status_mut() = StatusCode::PRECONDITION_FAILED;
        response.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        *response.body_mut() = Full::new(Bytes::from_static(b"Precondition Failed\n"));
        return;
    }
    if conditional_tag_matches(headers, &IF_NONE_MATCH, current, true) == Some(true) {
        // RFC 9110 §§13.1.2, 15.4.5: Matching If-None-Match returns 304 for GET and HEAD.
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        response.headers_mut().remove(CONTENT_TYPE);
        *response.body_mut() = Full::default();
    }
}

fn conditional_tag_matches(
    headers: &HeaderMap,
    name: &HeaderName,
    current: &[u8],
    weak_comparison: bool,
) -> Option<bool> {
    let values = headers.get_all(name);
    let mut present = false;
    for value in values {
        present = true;
        let value = value.as_bytes();
        if trim_ows(value) == b"*" {
            // RFC 9110 §§13.1.1–13.1.2: A wildcard matches an existing selected representation.
            return Some(true);
        }
        let mut start = 0;
        let mut quoted = false;
        // RFC 9110 §5.6.1: Commas inside quoted entity-tags are not list delimiters.
        for (index, byte) in value.iter().enumerate() {
            if *byte == b'"' {
                quoted = !quoted;
            } else if *byte == b',' && !quoted {
                if entity_tag_matches(trim_ows(&value[start..index]), current, weak_comparison) {
                    return Some(true);
                }
                start = index + 1;
            }
        }
        if !quoted && entity_tag_matches(trim_ows(&value[start..]), current, weak_comparison) {
            return Some(true);
        }
    }
    present.then_some(false)
}

fn entity_tag_matches(candidate: &[u8], current: &[u8], weak_comparison: bool) -> bool {
    // RFC 9110 §§13.1.1–13.1.2: If-Match is strong; If-None-Match is weak.
    let candidate_is_weak = candidate.starts_with(b"W/");
    let candidate = candidate.strip_prefix(b"W/").unwrap_or(candidate);
    let current = current.strip_prefix(b"W/").unwrap_or(current);
    candidate.len() >= 2
        && candidate.first() == Some(&b'"')
        && candidate.last() == Some(&b'"')
        && candidate[1..candidate.len() - 1]
            .iter()
            .all(|byte| *byte == b'!' || (0x23..=0x7e).contains(byte) || *byte >= 0x80)
        && (weak_comparison || !candidate_is_weak)
        && candidate == current
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    // RFC 9110 §5.6.3: Optional whitespace around list members is SP or HTAB.
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

#[cfg(test)]
mod tests;
