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
        &format!("GET /ready HTTP/1.1\r\nHost: localhost\r\n{headers}Connection: close\r\n\r\n"),
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
    // RFC 6234 §8.5: "abc"; NIST CAVP SHA-256 short-message vectors: empty input.
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
    let request = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
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
    let result = tokio::time::timeout(Duration::from_secs(6), stream.read_to_end(&mut bytes)).await;
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
    assert!(result.is_ok() || result.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset);
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
