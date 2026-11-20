use std::{io, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{HeaderMap, Request, StatusCode, header::HeaderValue};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pharos_server::{
    basic_auth::BasicAuth,
    http::{Listener, Security},
    tls::{
        ClientAuth, ClientConfig, ClientOptions, Curve, Restrictions, ServerName, ServerOptions,
        ServerTls, TlsConnector, Version, client_config,
    },
};
use rustls::{
    RootCertStore,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, pem::PemObject},
    version,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");
// `htpasswd -nbBC 4 u pw`: cost 4 keeps debug builds fast.
const HASH: &str = "$2y$04$rMNoGfh5s9sLzpV90fV9N.Q46UW8WIePlvnCWQkK2mshf8l00ODMu";

fn options(client_auth: ClientAuth, ca: bool) -> ServerOptions {
    ServerOptions {
        cert: format!("{FIXTURES}/server.pem").into(),
        key: format!("{FIXTURES}/server.key.pem").into(),
        ca: ca.then(|| format!("{FIXTURES}/ca.pem").into()),
        client_auth,
        keylog: None,
    }
}

fn identity(restrictions: &Restrictions) -> ServerTls {
    ServerTls::load_restricted(&options(ClientAuth::NoCert, false), restrictions).unwrap()
}

fn route(method: &str, path: &str) -> Option<(u16, &'static str, String)> {
    (path == "/metrics").then(|| {
        if method == "GET" {
            (200, "text/plain", "metric 1\n".into())
        } else {
            (405, "text/plain", "no\n".into())
        }
    })
}

fn trusting(alpn: &[&[u8]]) -> ClientConfig {
    let config = client_config(&ClientOptions {
        ca: Some(format!("{FIXTURES}/ca.pem").into()),
        identity: None,
    })
    .unwrap();
    let mut config = (*config).clone();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    config
}

fn roots() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let ca = CertificateDer::from_pem_file(format!("{FIXTURES}/ca.pem")).unwrap();
    roots.add(ca).unwrap();
    roots
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
    alpn: Option<Vec<u8>>,
}

async fn https(address: SocketAddr, config: ClientConfig, path: &str) -> io::Result<Reply> {
    let tcp = TcpStream::connect(address).await?;
    let name = ServerName::try_from("localhost").unwrap();
    let tls = TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await?;
    let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let http2 = alpn.as_deref() == Some(b"h2");
    let request = Request::builder()
        .uri(if http2 {
            format!("https://localhost{path}")
        } else {
            path.to_owned()
        })
        .header("host", "localhost")
        .body(Empty::<Bytes>::new())
        .unwrap();
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
    Ok(Reply {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8(body.to_vec()).unwrap(),
        alpn,
    })
}

async fn plain(address: SocketAddr, authorization: Option<&str>) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let authorization = authorization
        .map(|value| format!("Authorization: {value}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\n{authorization}Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

// exporter-toolkit v0.20.0 web/testdata/web_config_headers.good.yml
fn headers() -> Vec<(hyper::header::HeaderName, HeaderValue)> {
    vec![
        (
            "x-frame-options".parse().unwrap(),
            HeaderValue::from_static("deny"),
        ),
        (
            "strict-transport-security".parse().unwrap(),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ),
    ]
}

#[tokio::test]
async fn configured_headers_are_set_on_every_response() {
    let security = Security {
        headers: headers(),
        basic_auth: Some(Arc::new(
            BasicAuth::new([("u".to_owned(), HASH.to_owned())]).unwrap(),
        )),
        ..Security::default()
    };
    let listener = Listener::bind_secured("127.0.0.1:0", route, security)
        .await
        .unwrap();
    // RFC 9110 §15.5.2: the 401 carries the headers too.
    let denied = plain(listener.local_addr(), None).await;
    assert!(
        denied.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
        "{denied}"
    );
    assert!(denied.contains("\r\nx-frame-options: deny\r\n"), "{denied}");
    assert!(
        denied.contains("\r\nstrict-transport-security: max-age=31536000; includeSubDomains\r\n"),
        "{denied}"
    );
    let ok = plain(listener.local_addr(), Some("Basic dTpwdw==")).await;
    assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
    assert!(ok.contains("\r\nx-frame-options: deny\r\n"), "{ok}");
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn basic_auth_challenges_missing_and_wrong_credentials() {
    let security = Security {
        basic_auth: Some(Arc::new(
            BasicAuth::new([("u".to_owned(), HASH.to_owned())]).unwrap(),
        )),
        ..Security::default()
    };
    let listener = Listener::bind_secured("127.0.0.1:0", route, security)
        .await
        .unwrap();
    let address = listener.local_addr();
    // RFC 7617 §2: the challenge names the Basic scheme.
    let missing = plain(address, None).await;
    assert!(
        missing.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
        "{missing}"
    );
    assert!(
        missing.contains("\r\nwww-authenticate: Basic\r\n"),
        "{missing}"
    );
    assert!(missing.ends_with("Unauthorized\n"), "{missing}");
    // base64("u:bad")
    let wrong = plain(address, Some("Basic dTpiYWQ=")).await;
    assert!(
        wrong.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
        "{wrong}"
    );
    let ok = plain(address, Some("Basic dTpwdw==")).await;
    assert!(ok.ends_with("metric 1\n"), "{ok}");
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn tls_serves_http2_when_enabled_and_http1_otherwise() {
    for (http2, alpn) in [(true, b"h2".as_slice()), (false, b"http/1.1".as_slice())] {
        let security = Security {
            tls: Some(identity(&Restrictions::default())),
            http2,
            ..Security::default()
        };
        let listener = Listener::bind_secured("127.0.0.1:0", route, security)
            .await
            .unwrap();
        let reply = https(
            listener.local_addr(),
            trusting(&[b"h2", b"http/1.1"]),
            "/metrics",
        )
        .await
        .unwrap();
        // RFC 7301 §3.1: the server picks from the client's offer, in its own order.
        assert_eq!(reply.alpn.as_deref(), Some(alpn));
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.body, "metric 1\n");
        // RFC 9110 §7.4: an https scheme is right on a TLS Listener, so HTTP/2 is not misdirected.
        let missing = https(
            listener.local_addr(),
            trusting(&[b"h2", b"http/1.1"]),
            "/nope",
        )
        .await
        .unwrap();
        assert_eq!(missing.status, StatusCode::NOT_FOUND);
        listener.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn tls_listener_does_not_answer_cleartext_http() {
    let security = Security {
        tls: Some(identity(&Restrictions::default())),
        http2: true,
        ..Security::default()
    };
    let listener = Listener::bind_secured("127.0.0.1:0", route, security)
        .await
        .unwrap();
    let mut stream = TcpStream::connect(listener.local_addr()).await.unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut bytes = Vec::new();
    // The handshake fails, so the server closes the socket without an HTTP response.
    let _ = stream.read_to_end(&mut bytes).await;
    assert!(!bytes.starts_with(b"HTTP/"), "{bytes:?}");
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn tls_basic_auth_and_headers_apply_over_http2() {
    let security = Security {
        tls: Some(identity(&Restrictions::default())),
        http2: true,
        headers: headers(),
        basic_auth: Some(Arc::new(
            BasicAuth::new([("u".to_owned(), HASH.to_owned())]).unwrap(),
        )),
    };
    let listener = Listener::bind_secured("127.0.0.1:0", route, security)
        .await
        .unwrap();
    let reply = https(listener.local_addr(), trusting(&[b"h2"]), "/metrics")
        .await
        .unwrap();
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.headers["x-frame-options"], "deny");
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn client_certificate_policy_is_enforced() {
    let tls = ServerTls::load(&options(ClientAuth::RequireAndVerify, true)).unwrap();
    let listener = Listener::bind_secured(
        "127.0.0.1:0",
        route,
        Security {
            tls: Some(tls),
            http2: true,
            ..Security::default()
        },
    )
    .await
    .unwrap();
    let address = listener.local_addr();
    // RFC 8446 §4.4.2: a server that requires a certificate aborts without one.
    assert!(
        https(address, trusting(&[b"http/1.1"]), "/metrics")
            .await
            .is_err()
    );
    let mut with_cert = trusting(&[b"http/1.1"]);
    let identity = client_config(&ClientOptions {
        ca: Some(format!("{FIXTURES}/ca.pem").into()),
        identity: Some((
            format!("{FIXTURES}/client.pem").into(),
            format!("{FIXTURES}/client.key.pem").into(),
        )),
    })
    .unwrap();
    with_cert.client_auth_cert_resolver = identity.client_auth_cert_resolver.clone();
    let reply = https(address, with_cert, "/metrics").await.unwrap();
    assert_eq!(reply.status, StatusCode::OK);
    listener.shutdown().await.unwrap();
}

fn client(
    versions: &[&'static rustls::SupportedProtocolVersion],
    provider: rustls::crypto::CryptoProvider,
) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

async fn listener_with(restrictions: Restrictions) -> Listener {
    Listener::bind_secured(
        "127.0.0.1:0",
        route,
        Security {
            tls: Some(identity(&restrictions)),
            http2: false,
            ..Security::default()
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn version_bounds_limit_what_clients_negotiate() {
    // exporter-toolkit v0.20.0 web/testdata/web_config_noAuth_someCiphers.good.yml: max_version TLS12.
    let tls12_only = listener_with(Restrictions {
        max_version: Version::Tls12,
        ..Restrictions::default()
    })
    .await;
    assert!(
        https(
            tls12_only.local_addr(),
            client(&[&version::TLS13], aws_lc_rs::default_provider()),
            "/metrics"
        )
        .await
        .is_err()
    );
    let reply = https(
        tls12_only.local_addr(),
        client(&[&version::TLS12], aws_lc_rs::default_provider()),
        "/metrics",
    )
    .await
    .unwrap();
    assert_eq!(reply.status, StatusCode::OK);
    tls12_only.shutdown().await.unwrap();

    // web_config_noAuth_someCurves.good.yml: min_version TLS13.
    let tls13_only = listener_with(Restrictions {
        min_version: Version::Tls13,
        ..Restrictions::default()
    })
    .await;
    assert!(
        https(
            tls13_only.local_addr(),
            client(&[&version::TLS12], aws_lc_rs::default_provider()),
            "/metrics"
        )
        .await
        .is_err()
    );
    tls13_only.shutdown().await.unwrap();
}

#[tokio::test]
async fn cipher_suites_limit_tls12_negotiation() {
    let listener = listener_with(Restrictions {
        max_version: Version::Tls12,
        cipher_suites: vec!["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into()],
        ..Restrictions::default()
    })
    .await;
    let only = |name: &str| {
        let mut provider = aws_lc_rs::default_provider();
        provider
            .cipher_suites
            .retain(|suite| suite.suite().as_str() == Some(name));
        client(&[&version::TLS12], provider)
    };
    // web_config_noAuth_someCiphers.good.yml: "no common cipher" fails the handshake.
    assert!(
        https(
            listener.local_addr(),
            only("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
            "/metrics"
        )
        .await
        .is_err()
    );
    let reply = https(
        listener.local_addr(),
        only("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
        "/metrics",
    )
    .await
    .unwrap();
    assert_eq!(reply.status, StatusCode::OK);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn tls13_only_cipher_list_leaves_tls13_alone() {
    // Go's CipherSuites do not apply to TLS 1.3, so a list of TLS 1.3 names drops TLS 1.2 only.
    let listener = listener_with(Restrictions {
        cipher_suites: vec!["TLS_AES_128_GCM_SHA256".into()],
        ..Restrictions::default()
    })
    .await;
    assert!(
        https(
            listener.local_addr(),
            client(&[&version::TLS12], aws_lc_rs::default_provider()),
            "/metrics"
        )
        .await
        .is_err()
    );
    let reply = https(
        listener.local_addr(),
        client(&[&version::TLS13], aws_lc_rs::default_provider()),
        "/metrics",
    )
    .await
    .unwrap();
    assert_eq!(reply.status, StatusCode::OK);
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn curves_limit_key_exchange() {
    // web_config_noAuth_someCurves.good.yml, with CurveP384: rustls cannot offer CurveP521.
    let listener = listener_with(Restrictions {
        min_version: Version::Tls13,
        curves: vec![Curve::P384],
        ..Restrictions::default()
    })
    .await;
    let only = |name: rustls::NamedGroup| {
        let mut provider = aws_lc_rs::default_provider();
        provider.kx_groups = aws_lc_rs::ALL_KX_GROUPS
            .iter()
            .filter(|group| group.name() == name)
            .copied()
            .collect();
        client(&[&version::TLS13], provider)
    };
    assert!(
        https(
            listener.local_addr(),
            only(rustls::NamedGroup::secp256r1),
            "/metrics"
        )
        .await
        .is_err()
    );
    let reply = https(
        listener.local_addr(),
        only(rustls::NamedGroup::secp384r1),
        "/metrics",
    )
    .await
    .unwrap();
    assert_eq!(reply.status, StatusCode::OK);
    listener.shutdown().await.unwrap();
}

#[test]
fn restrictions_reject_what_rustls_cannot_serve() {
    let load = |restrictions: Restrictions| {
        ServerTls::load_restricted(&options(ClientAuth::NoCert, false), &restrictions)
    };
    // Go lists CBC suites, rustls has none: skipped, and with nothing left TLS 1.2 is off, not an error.
    let cbc = load(Restrictions {
        cipher_suites: vec!["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA".into()],
        ..Restrictions::default()
    });
    assert!(cbc.is_ok());
    let cbc_only_tls12 = load(Restrictions {
        max_version: Version::Tls12,
        cipher_suites: vec!["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA".into()],
        ..Restrictions::default()
    });
    assert!(cbc_only_tls12.is_err());
    // CurveP521 is skipped when others remain, and fails when none do.
    let p521 = load(Restrictions {
        curves: vec![Curve::P521, Curve::P256],
        ..Restrictions::default()
    });
    assert!(p521.is_ok());
    let p521_only = load(Restrictions {
        curves: vec![Curve::P521],
        ..Restrictions::default()
    });
    assert!(p521_only.is_err());
    // web_config_noAuth_inventedCiphers.bad.yml
    let invented = load(Restrictions {
        cipher_suites: vec!["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA2048".into()],
        ..Restrictions::default()
    });
    assert!(invented.is_err());
    let inverted = load(Restrictions {
        min_version: Version::Tls13,
        max_version: Version::Tls12,
        ..Restrictions::default()
    });
    assert!(inverted.is_err());
}
