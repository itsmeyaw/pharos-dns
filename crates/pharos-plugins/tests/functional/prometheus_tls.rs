#![cfg(all(feature = "plugin-prometheus", feature = "plugin-whoami"))]

// Derived from CoreDNS v1.15.0 plugin/metrics/metrics_test.go (TestMetricsTLS,
// TestMetricsTLSValidationErrorDoesNotClaimAddress, TestMetricsTLSServeErrorReleasesAddress) and
// Prometheus exporter-toolkit v0.20.0 web/tls_config_test.go.

use std::{io, net::SocketAddr, path::Path, sync::Arc};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::{
    Lifecycle, Phase,
    tls::{ClientConfig, ClientOptions, ServerName, TlsConnector, client_config},
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");
// `htpasswd -nbBC 4 u pw`: cost 4 keeps debug builds fast.
const HASH: &str = "$2y$04$rMNoGfh5s9sLzpV90fV9N.Q46UW8WIePlvnCWQkK2mshf8l00ODMu";

fn free_address() -> SocketAddr {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap()
}

fn identity() -> String {
    format!("  cert_file: {FIXTURES}/server.pem\n  key_file: {FIXTURES}/server.key.pem\n")
}

fn write_config(dir: &TempDir, text: &str) -> String {
    let path = dir.path().join("web.yml");
    std::fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_owned()
}

fn lifecycle(address: SocketAddr, config: &str) -> Lifecycle {
    let input = format!(".:0 {{\n prometheus {address} {{\n tls {config}\n }}\n whoami\n}}");
    let blocks = parse("Corefile", &input).unwrap();
    servers(configure::<Chain>(&blocks, directives()).unwrap())
        .unwrap()
        .1
}

async fn start(text: &str) -> (TempDir, SocketAddr, Lifecycle) {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(&dir, text);
    let address = free_address();
    let lifecycle = lifecycle(address, &config);
    lifecycle.run(Phase::Startup).await.unwrap();
    (dir, address, lifecycle)
}

async fn plain(address: SocketAddr, headers: &str) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!(
                "GET /metrics HTTP/1.1\r\nHost: localhost\r\n{headers}Connection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    // A TLS server answers cleartext HTTP with an alert, which may reset the connection.
    let _ = stream.read_to_end(&mut response).await;
    String::from_utf8_lossy(&response).into_owned()
}

fn trusting(client_certificate: bool, alpn: &[&[u8]]) -> ClientConfig {
    let config = client_config(&ClientOptions {
        ca: Some(format!("{FIXTURES}/ca.pem").into()),
        identity: client_certificate.then(|| {
            (
                format!("{FIXTURES}/client.pem").into(),
                format!("{FIXTURES}/client.key.pem").into(),
            )
        }),
    })
    .unwrap();
    let mut config = (*config).clone();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    config
}

// Status and body of `GET /metrics`, over HTTP/2 when the client offers only h2.
async fn https(
    address: SocketAddr,
    config: ClientConfig,
    authorization: Option<&str>,
) -> io::Result<(u16, String)> {
    let tcp = TcpStream::connect(address).await?;
    let name = ServerName::try_from("localhost").unwrap();
    let tls = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await?;
    let http2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    let mut request = Request::builder()
        .uri(if http2 {
            "https://localhost/metrics"
        } else {
            "/metrics"
        })
        .header("host", "localhost");
    if let Some(value) = authorization {
        request = request.header("authorization", value);
    }
    let request = request.body(Empty::<Bytes>::new()).unwrap();
    let response = if http2 {
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .map_err(io::Error::other)?;
        tokio::spawn(connection);
        sender.send_request(request).await
    } else {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(io::Error::other)?;
        tokio::spawn(connection);
        sender.send_request(request).await
    }
    .map_err(io::Error::other)?;
    let (parts, body) = response.into_parts();
    let body = body.collect().await.map_err(io::Error::other)?.to_bytes();
    Ok((
        parts.status.as_u16(),
        String::from_utf8(body.to_vec()).unwrap(),
    ))
}

#[tokio::test]
async fn empty_config_starts_a_plain_http_server() {
    let (_dir, address, lifecycle) = start("").await;
    let response = plain(address, "").await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn tls_config_serves_metrics_over_https_only() {
    let (_dir, address, lifecycle) = start(
        &(format!("tls_server_config:\n{}", identity())
            + "  client_auth_type: VerifyClientCertIfGiven\n"),
    )
    .await;
    let (status, body) = https(address, trusting(false, &[b"http/1.1"]), None)
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert!(body.contains("pharos_build_info{"), "{body}");
    // The default client's cleartext request is not served.
    let response = plain(address, "").await;
    assert!(!response.starts_with("HTTP/1.1 200"), "{response}");
    lifecycle.run(Phase::Shutdown).await.unwrap();
    assert!(TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn http2_is_negotiated_unless_disabled() {
    let (_dir, address, lifecycle) = start(&format!("tls_server_config:\n{}", identity())).await;
    let (status, _) = https(address, trusting(false, &[b"h2"]), None)
        .await
        .unwrap();
    assert_eq!(status, 200);
    lifecycle.run(Phase::Shutdown).await.unwrap();

    let (_dir, address, lifecycle) = start(&format!(
        "tls_server_config:\n{}http_server_config:\n  http2: false\n",
        identity()
    ))
    .await;
    // RFC 7301 §3.2: no common protocol is a fatal alert, so an h2-only client cannot connect.
    assert!(
        https(address, trusting(false, &[b"h2"]), None)
            .await
            .is_err()
    );
    let (status, _) = https(address, trusting(false, &[b"h2", b"http/1.1"]), None)
        .await
        .unwrap();
    assert_eq!(status, 200);
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn require_any_client_cert_needs_a_client_certificate() {
    let (_dir, address, lifecycle) = start(
        &(format!("tls_server_config:\n{}", identity())
            + "  client_auth_type: RequireAnyClientCert\n"),
    )
    .await;
    let (status, _) = https(address, trusting(true, &[b"http/1.1"]), None)
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert!(
        https(address, trusting(false, &[b"http/1.1"]), None)
            .await
            .is_err()
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn require_and_verify_client_cert_rejects_an_untrusted_certificate() {
    let (_dir, address, lifecycle) = start(&(format!("tls_server_config:\n{}", identity())
        + &format!(
            "  client_auth_type: RequireAndVerifyClientCert\n  client_ca_file: {FIXTURES}/other-ca.pem\n"
        )))
    .await;
    // The fixture client is signed by ca.pem, not other-ca.pem.
    assert!(
        https(address, trusting(true, &[b"http/1.1"]), None)
            .await
            .map_or_else(|_| true, |(status, _)| status != 200)
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn invalid_configs_fail_startup() {
    let key = format!("{FIXTURES}/server.key.pem");
    let cert = format!("{FIXTURES}/server.pem");
    let client_key = format!("{FIXTURES}/client.key.pem");
    for (name, text) in [
        (
            "junk",
            "hWkNKCp3fvIx3jKnsaBI\nTuEjdwNS8A2vYdFbiKqr\n".to_owned(),
        ),
        (
            "empty key",
            format!("tls_server_config:\n  cert_file: {cert}\n  key_file: \"\"\n"),
        ),
        (
            "empty cert",
            format!("tls_server_config:\n  cert_file: \"\"\n  key_file: {key}\n"),
        ),
        (
            "wrong key",
            format!("tls_server_config:\n  cert_file: {cert}\n  key_file: somefile\n"),
        ),
        (
            "wrong cert",
            format!("tls_server_config:\n  cert_file: somefile\n  key_file: {key}\n"),
        ),
        (
            "mismatched key",
            format!("tls_server_config:\n  cert_file: {cert}\n  key_file: {client_key}\n"),
        ),
        ("bad hash", "basic_auth_users:\n  john: doe\n".to_owned()),
        (
            "bad header",
            "http_server_config:\n  headers:\n    Content-Type: foo\n".to_owned(),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let config = write_config(&dir, &text);
        let lifecycle = lifecycle(free_address(), &config);
        assert!(lifecycle.run(Phase::Startup).await.is_err(), "{name}");
    }
    // The file does not exist.
    let lifecycle = lifecycle(free_address(), "/nonexistent/web.yml");
    assert!(lifecycle.run(Phase::Startup).await.is_err());
}

#[tokio::test]
async fn validation_error_does_not_claim_address() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(&dir, "hWkNKCp3fvIx3jKnsaBI\n");
    let address = free_address();
    assert!(
        lifecycle(address, &config)
            .run(Phase::Startup)
            .await
            .is_err()
    );
    std::net::TcpListener::bind(address).expect("failed startup kept the metrics address");
}

#[tokio::test]
async fn mismatched_key_does_not_claim_address() {
    // Pharos loads the identity before binding, so unlike CoreDNS no serve error can follow a bind.
    // Valid YAML and readable files, but the key does not belong to the certificate.
    let dir = tempfile::tempdir().unwrap();
    let config = write_config(
        &dir,
        &format!(
            "tls_server_config:\n  cert_file: {FIXTURES}/server.pem\n  key_file: {FIXTURES}/client.key.pem\n"
        ),
    );
    let address = free_address();
    assert!(
        lifecycle(address, &config)
            .run(Phase::Startup)
            .await
            .is_err()
    );
    std::net::TcpListener::bind(address).expect("failed startup kept the metrics address");
}

#[tokio::test]
async fn basic_auth_and_headers_apply_with_and_without_tls() {
    let users = format!("basic_auth_users:\n  u: {HASH}\n");
    let headers = "http_server_config:\n  headers:\n    X-Frame-Options: deny\n";
    // web_config_users_noTLS.good.yml: credentials work on plain HTTP.
    let (_dir, address, lifecycle) = start(&format!("{users}{headers}")).await;
    let denied = plain(address, "").await;
    assert!(denied.starts_with("HTTP/1.1 401"), "{denied}");
    assert!(denied.contains("www-authenticate: Basic\r\n"), "{denied}");
    assert!(denied.contains("x-frame-options: deny\r\n"), "{denied}");
    let allowed = plain(address, "Authorization: Basic dTpwdw==\r\n").await;
    assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");
    assert!(allowed.contains("x-frame-options: deny\r\n"), "{allowed}");
    lifecycle.run(Phase::Shutdown).await.unwrap();

    let (_dir, address, lifecycle) =
        start(&format!("tls_server_config:\n{}{users}", identity())).await;
    let (status, _) = https(address, trusting(false, &[b"h2"]), None)
        .await
        .unwrap();
    assert_eq!(status, 401);
    // exporter-toolkit v0.20.0 TestUsers: wrong password, then the right one (base64 "u:bad", "u:pw").
    let (status, _) = https(address, trusting(false, &[b"h2"]), Some("Basic dTpiYWQ="))
        .await
        .unwrap();
    assert_eq!(status, 401);
    let (status, _) = https(address, trusting(false, &[b"h2"]), Some("Basic dTpwdw=="))
        .await
        .unwrap();
    assert_eq!(status, 200);
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn relative_certificate_paths_resolve_next_to_the_config() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["server.pem", "server.key.pem"] {
        std::fs::copy(Path::new(FIXTURES).join(name), dir.path().join(name)).unwrap();
    }
    let config = write_config(
        &dir,
        "tls_server_config:\n  cert_file: server.pem\n  key_file: server.key.pem\n",
    );
    let address = free_address();
    let lifecycle = lifecycle(address, &config);
    lifecycle.run(Phase::Startup).await.unwrap();
    let (status, _) = https(address, trusting(false, &[b"http/1.1"]), None)
        .await
        .unwrap();
    assert_eq!(status, 200);
    lifecycle.run(Phase::Shutdown).await.unwrap();
}
