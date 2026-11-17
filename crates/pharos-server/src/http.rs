//! Small HTTP/1 listener for operational endpoints.

use std::{
    borrow::Cow,
    convert::Infallible,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
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
        ALLOW, CONTENT_TYPE, ETAG, HeaderMap, HeaderName, HeaderValue, IF_MATCH, IF_NONE_MATCH,
    },
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::TcpListener,
    sync::watch,
    task::{JoinHandle, JoinSet},
};

const MAX_CONNECTIONS: usize = 1024;
const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HTTP1_BUFFER_SIZE: usize = 16 * 1024;

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
        let route = Arc::new(route);
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
                        let route = Arc::clone(&route);
                        let mut stop = receiver.clone();
                        connections.spawn(async move {
                            // RFC 9110 §6.5.1: Do not merge trailer fields into headers.
                            let service = service_fn(move |request: Request<Incoming>| {
                                std::future::ready(Ok::<_, Infallible>(response_for_request(
                                    route.as_ref(),
                                    request,
                                )))
                            });
                            // RFC 9110 §5.6.7: Hyper emits dates in IMF-fixdate format.
                            // RFC 9110 §17.5: Bound combined request-target and field buffering.
                            let connection = http1::Builder::new().max_buf_size(MAX_HTTP1_BUFFER_SIZE).serve_connection(TokioIo::new(stream), service);
                            tokio::pin!(connection);
                            tokio::select! {
                                _ = &mut connection => {},
                                // shortcut: cap the connection lifetime until per-request read, write and idle deadlines are supported.
                                _ = tokio::time::sleep(TIMEOUT) => {},
                                _ = stop.changed() => {
                                    connection.as_mut().graceful_shutdown();
                                    let _ = connection.await;
                                }
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

fn response_for_request<F>(route: &F, request: Request<Incoming>) -> Response<Full<Bytes>>
where
    F: Fn(&str, &str) -> Option<(u16, &'static str, String)>,
{
    let method = request.method().as_str();
    let path = request.uri().path();
    let is_metrics = path == "/metrics";
    let response = if request.uri().scheme_str() == Some("https") {
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
mod tests {
    use super::{Listener, MAX_HTTP1_BUFFER_SIZE, health_request};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn request(addr: std::net::SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    async fn operational_request(addr: std::net::SocketAddr, headers: &str) -> String {
        request(
            addr,
            &format!(
                "GET /ready HTTP/1.1\r\nHost: localhost\r\n{headers}Connection: close\r\n\r\n"
            ),
        )
        .await
    }

    #[tokio::test]
    async fn operational_etag_matches_sha256_known_answers() {
        let listener = Listener::bind("127.0.0.1:0", |path| match path {
            "/empty" => Some(("text/plain", "".into())),
            "/abc" => Some(("text/plain", "abc".into())),
            _ => None,
        })
        .await
        .unwrap();
        // NIST CAVP SHA-256 short-message vectors include the empty string and "abc".
        for (path, digest) in [
            (
                "/empty",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                "/abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
        ] {
            let response = request(
                listener.local_addr(),
                &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
            assert!(
                response.contains(&format!("\r\netag: \"{digest}\"\r\n")),
                "{response}"
            );
        }
        listener.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn health_probe_identifies_its_robotic_user_agent() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            loop {
                let count = stream.read(&mut chunk).await.unwrap();
                request.extend_from_slice(&chunk[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(
                request.contains("user-agent: pharos health probe"),
                "{request}"
            );
            // RFC 9110 §10.1.2: Do not send From when no user address is configured.
            assert!(!request.contains("from:"), "{request}");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let mut closed = [0];
            let _ = stream.read(&mut closed).await;
        });
        let probe_result = health_request(&address.to_string()).await;
        let server_result = server.await;
        assert!(server_result.is_ok(), "{server_result:?}");
        assert!(probe_result.is_ok(), "{probe_result:?}");
    }

    #[tokio::test]
    async fn routes_can_return_service_unavailable() {
        let listener = Listener::bind_with_status("127.0.0.1:0", |path| {
            (path == "/ready").then(|| (503, "text/plain", "not-ready".into()))
        })
        .await
        .unwrap();
        let response = request(
            listener.local_addr(),
            "GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(!response.contains("\netag: "), "{response}");
        assert!(response.ends_with("not-ready"));
        listener.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn routes_get_and_returns_not_found_for_other_requests() {
        let listener = Listener::bind("localhost:0", |path| {
            (path == "/metrics").then(|| ("text/plain; version=0.0.4", "metric 1\n".into()))
        })
        .await
        .unwrap();
        let address = listener.local_addr();
        let response = request(
            address,
            "GET /metrics?x=1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("content-type: text/plain; version=0.0.4\r\n"));
        assert!(response.ends_with("metric 1\n"));
        let response = request(
            address,
            "GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
        let response = request(
            address,
            "POST /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(response.contains("allow: GET, HEAD\r\n"));
        assert!(!response.contains("\netag: "), "{response}");
        listener.shutdown().await.unwrap();
        assert!(TcpStream::connect(address).await.is_err());
    }

    #[tokio::test]
    async fn operational_routes_apply_method_target_and_precondition_semantics() {
        let listener = Listener::bind_with_status("127.0.0.1:0", |path| {
            (path == "/ready").then(|| (200, "text/plain", "ready".into()))
        })
        .await
        .unwrap();
        let address = listener.local_addr();

        let response = operational_request(address, "").await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        // RFC 9110 §8.8.3.1: A 200 readiness representation carries a strong validator.
        let etag = response
            .lines()
            .find_map(|line| line.strip_prefix("etag: "))
            .unwrap();
        assert!(etag.starts_with('"') && etag.ends_with('"'), "{response}");
        let get_content_length = response
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .map(str::to_owned);
        assert_eq!(
            etag,
            "\"b24d6d33736ecd5604a4b17bc9c6481039fac362bb7df044ef1c10a2bfd21db6\""
        );

        let response = request(
            address,
            "HEAD /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(
            response.contains(&format!("etag: {etag}\r\n")),
            "{response}"
        );
        assert!(
            response.contains("content-type: text/plain\r\n"),
            "{response}"
        );
        let head_content_length = response
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .map(str::to_owned);
        assert_eq!(head_content_length, get_content_length);
        assert!(response.ends_with("\r\n\r\n"), "{response}");

        let response = request(
            address,
            "FROB /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 501 Not Implemented\r\n"),
            "{response}"
        );
        assert!(!response.contains("\netag: "), "{response}");

        let response = request(
            address,
            "POST /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
            "{response}"
        );
        assert!(response.contains("allow: GET, HEAD\r\n"), "{response}");
        assert!(response.ends_with("Method Not Allowed\n"), "{response}");
        assert!(!response.contains("\netag: "), "{response}");

        let response = operational_request(address, &format!("If-None-Match: {etag}\r\n")).await;
        assert!(
            response.starts_with("HTTP/1.1 304 Not Modified\r\n"),
            "{response}"
        );
        assert!(response.ends_with("\r\n\r\n"), "{response}");
        assert!(
            response.contains(&format!("etag: {etag}\r\n")),
            "{response}"
        );

        let response = request(
            address,
            "HEAD /ready HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: *\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 304 Not Modified\r\n"),
            "{response}"
        );
        assert!(
            response.contains(&format!("etag: {etag}\r\n")),
            "{response}"
        );
        assert!(response.ends_with("\r\n\r\n"), "{response}");

        let response = operational_request(address, "If-None-Match: *\r\n").await;
        assert!(
            response.starts_with("HTTP/1.1 304 Not Modified\r\n"),
            "{response}"
        );

        let response = operational_request(address, &format!("If-None-Match: W/{etag}\r\n")).await;
        assert!(
            response.starts_with("HTTP/1.1 304 Not Modified\r\n"),
            "{response}"
        );

        let response = operational_request(address, "If-Match: \"different\"\r\n").await;
        assert!(
            response.starts_with("HTTP/1.1 412 Precondition Failed\r\n"),
            "{response}"
        );
        assert!(
            response.contains(&format!("etag: {etag}\r\n")),
            "{response}"
        );
        assert!(response.ends_with("Precondition Failed\n"), "{response}");

        let response =
            operational_request(address, "If-Match: \"different\"\r\nIf-None-Match: *\r\n").await;
        assert!(
            response.starts_with("HTTP/1.1 412 Precondition Failed\r\n"),
            "{response}"
        );

        let response = operational_request(address, &format!("If-Match: W/{etag}\r\n")).await;
        assert!(
            response.starts_with("HTTP/1.1 412 Precondition Failed\r\n"),
            "{response}"
        );

        let response = operational_request(address, "If-Match: *\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");

        let response = operational_request(address, "Range: bytes=0-0\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.ends_with("\r\n\r\nready"), "{response}");

        let response = request(
            address,
            "GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "{response}"
        );
        assert!(response.ends_with("Not Found\n"), "{response}");
        assert!(!response.contains("\netag: "), "{response}");

        let response = request(
            address,
            "PUT /ready HTTP/1.1\r\nHost: localhost\r\nContent-Range: bytes 0-1/2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
            "{response}"
        );
        assert!(!response.contains("\netag: "), "{response}");

        for scheme in ["https", "HTTPS"] {
            let response = request(
                address,
                &format!("GET {scheme}://localhost/ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
            )
            .await;
            assert!(
                response.starts_with("HTTP/1.1 421 Misdirected Request\r\n"),
                "{response}"
            );
            assert!(!response.contains("\netag: "), "{response}");
        }

        listener.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn oversized_request_target_is_rejected_by_http1_buffer_limit() {
        let listener = Listener::bind("127.0.0.1:0", |_| None).await.unwrap();
        let mut stream = TcpStream::connect(listener.local_addr()).await.unwrap();
        let target = format!("/{}", "x".repeat(MAX_HTTP1_BUFFER_SIZE));
        let request =
            format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let _ = stream.write_all(request.as_bytes()).await;
        let mut response = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
            .await
            .expect("oversized request was not closed");
        // RFC 9110 §§17.5, 15.5.15: Bound request targets; 414 is defined for overlong URIs.
        if !response.is_empty() {
            assert!(!response.starts_with(b"HTTP/1.1 2"), "{response:?}");
        }
        if let Err(error) = read {
            assert!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                ),
                "{error}"
            );
        }
        listener.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn invalid_endpoint_responses_return_explanatory_server_error() {
        let listener = Listener::bind_with_status("127.0.0.1:0", |path| match path {
            "/status" => Some((99, "text/plain", String::new())),
            "/content-type" => Some((200, "invalid\r\nheader", String::new())),
            _ => None,
        })
        .await
        .unwrap();
        for path in ["/status", "/content-type"] {
            let response = request(
                listener.local_addr(),
                &format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
            )
            .await;
            assert!(
                response.starts_with("HTTP/1.1 500 Internal Server Error\r\n"),
                "{response}"
            );
            assert!(!response.contains("\netag: "), "{response}");
            assert!(response.ends_with("Internal Server Error\n"), "{response}");
        }
        listener.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn wildcard_listener_serves_ipv4_and_ipv6() {
        let ipv6_available = std::net::TcpListener::bind("[::1]:0").is_ok();
        for address in [":0", "[::]:0"] {
            let listener = Listener::bind(address, |path| {
                (path == "/metrics").then(|| ("text/plain", "metric 1\n".into()))
            })
            .await
            .unwrap();
            let port = listener.local_addr().port();
            let query = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            let response = request(([127, 0, 0, 1], port).into(), query).await;
            assert!(response.ends_with("metric 1\n"));
            if ipv6_available {
                let response = request((std::net::Ipv6Addr::LOCALHOST, port).into(), query).await;
                assert!(response.ends_with("metric 1\n"));
            }
            listener.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn wildcard_listener_does_not_fallback_when_port_is_occupied() {
        let occupied = Listener::bind(":0", |_| None).await.unwrap();
        let port = occupied.local_addr().port();
        let error = match Listener::bind(&format!(":{port}"), |_| None).await {
            Ok(_) => panic!("occupied wildcard port was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        occupied.shutdown().await.unwrap();
    }

    #[test]
    fn only_ipv6_unavailable_errors_allow_fallback() {
        use super::ipv6_unavailable;
        use std::io::{Error, ErrorKind};

        assert!(ipv6_unavailable(&Error::from_raw_os_error(
            libc::EAFNOSUPPORT
        )));
        assert!(ipv6_unavailable(&Error::from(ErrorKind::AddrNotAvailable)));
        assert!(!ipv6_unavailable(&Error::from(ErrorKind::AddrInUse)));
        assert!(!ipv6_unavailable(&Error::from(ErrorKind::PermissionDenied)));
    }

    #[tokio::test]
    async fn partial_request_times_out() {
        let listener = Listener::bind("127.0.0.1:0", |_| None).await.unwrap();
        let mut stream = TcpStream::connect(listener.local_addr()).await.unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        let mut bytes = Vec::new();
        let result =
            tokio::time::timeout(Duration::from_secs(6), stream.read_to_end(&mut bytes)).await;
        assert!(result.is_ok(), "partial HTTP request did not time out");
        listener.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_closes_idle_connections() {
        let listener = Listener::bind("127.0.0.1:0", |_| None).await.unwrap();
        let mut stream = TcpStream::connect(listener.local_addr()).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0; 1024];
        assert!(stream.read(&mut response).await.unwrap() > 0);
        stream.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        tokio::time::timeout(Duration::from_secs(6), listener.shutdown())
            .await
            .unwrap()
            .unwrap();
        let mut bytes = Vec::new();
        let result = stream.read_to_end(&mut bytes).await;
        assert!(
            result.is_ok() || result.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset
        );
    }

    #[tokio::test]
    async fn shutdown_drains_response_in_progress() {
        let body = "x".repeat(4 * 1024 * 1024);
        let length = body.len();
        let listener = Listener::bind("127.0.0.1:0", move |_| Some(("text/plain", body.clone())))
            .await
            .unwrap();
        let mut stream = TcpStream::connect(listener.local_addr()).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut first = [0; 1024];
        let n = stream.read(&mut first).await.unwrap();
        assert!(n > 0);
        let shutdown = tokio::spawn(listener.shutdown());
        let mut response = first[..n].to_vec();
        stream.read_to_end(&mut response).await.unwrap();
        shutdown.await.unwrap().unwrap();
        let header_end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!(response.len() - header_end, length);
    }
}
