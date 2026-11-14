//! Small HTTP/1 listener for operational endpoints.

use std::{
    borrow::Cow,
    convert::Infallible,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    Request, Response, StatusCode,
    body::Incoming,
    header::{CONTENT_TYPE, HeaderValue},
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
            // RFC 9110 §9.3.1: GET retrieves the current representation for a metrics route.
            (method == "GET").then(|| route(path)).flatten()
        })
        .await
    }

    /// Bind an endpoint that can route all HTTP methods.
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
                                // RFC 9110 §9.3.1: GET content does not change routing.
                                let response = route(request.method().as_str(), request.uri().path());
                                async move {
                                    // RFC 9110 §6.5.1: Do not generate trailer fields.
                                    let mut result = Response::new(Full::default());
                                    match response {
                                        Some((status, content_type, body)) => match (StatusCode::from_u16(status), HeaderValue::from_str(content_type)) {
                                            (Ok(status), Ok(content_type)) => {
                                                *result.status_mut() = status;
                                                // RFC 9110 §5.1: Content-Type is registered.
                                                result.headers_mut().insert(CONTENT_TYPE, content_type);
                                                // RFC 9110 §6.4: Send endpoint content as body.
                                                *result.body_mut() = Full::new(Bytes::from(body));
                                            }
                                            // RFC 9110 §15.6.1: 500 reports a server failure.
                                            _ => *result.status_mut() = StatusCode::INTERNAL_SERVER_ERROR,
                                        },
                                        // RFC 9110 §15.5: 4xx reports a client error.
                                        None => *result.status_mut() = StatusCode::NOT_FOUND,
                                    }
                                    Ok::<_, Infallible>(result)
                                }
                            });
                            // RFC 9110 §5.6.7: Hyper emits dates in IMF-fixdate format.
                            let connection = http1::Builder::new().serve_connection(TokioIo::new(stream), service);
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

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

#[cfg(test)]
mod tests {
    use super::Listener;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    async fn request(addr: std::net::SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
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
        for req in ["GET /missing", "POST /metrics"] {
            let response = request(
                address,
                &format!("{req} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
        }
        listener.shutdown().await.unwrap();
        assert!(TcpStream::connect(address).await.is_err());
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
