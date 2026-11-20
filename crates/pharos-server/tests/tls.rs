#![forbid(unsafe_code)]

use std::{path::PathBuf, sync::Arc};

use pharos_server::{
    doh,
    tls::{ClientAuth, ClientOptions, ServerOptions, ServerTls, client_config},
};
use rustls::{
    ClientConfig,
    crypto::aws_lc_rs,
    pki_types::{ServerName, pem::PemObject},
    version::TLS12,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/tls")
        .join(name)
}

fn options(client_auth: ClientAuth) -> ServerOptions {
    ServerOptions {
        cert: fixture("server.pem"),
        key: fixture("server.key.pem"),
        ca: Some(fixture("ca.pem")),
        client_auth,
        keylog: None,
    }
}

fn client(identity: Option<&str>) -> Arc<ClientConfig> {
    client_config(&ClientOptions {
        ca: Some(fixture("ca.pem")),
        identity: identity.map(|name| {
            (
                fixture(&format!("{name}.pem")),
                fixture(&format!("{name}.key.pem")),
            )
        }),
    })
    .unwrap()
}

/// Run both ends of a handshake over a pipe; the server end decides whether it passed.
async fn handshake(server: &ServerTls, client: Arc<ClientConfig>) -> Result<bool, std::io::Error> {
    let (client_io, server_io) = duplex(16 * 1024);
    let connector = tokio_rustls::TlsConnector::from(client);
    let name = ServerName::try_from("localhost").unwrap();
    let acceptor = server.acceptor();
    let server_side = async {
        let mut stream = acceptor.accept(server_io).await?;
        let presented = stream.get_ref().1.peer_certificates().is_some();
        stream.write_all(b"ok").await?;
        stream.shutdown().await?;
        Ok(presented)
    };
    let client_side = async {
        let mut stream = connector.connect(name, client_io).await?;
        let mut reply = Vec::new();
        let _ = stream.read_to_end(&mut reply).await;
        Ok::<_, std::io::Error>(())
    };
    let (server_result, _) = tokio::join!(server_side, client_side);
    server_result
}

#[tokio::test]
async fn client_trusting_the_ca_completes_a_handshake() {
    let server = ServerTls::load(&options(ClientAuth::NoCert)).unwrap();
    assert!(!handshake(&server, client(None)).await.unwrap());
}

#[tokio::test]
async fn client_rejects_a_server_from_an_untrusted_ca() {
    let server = ServerTls::load(&options(ClientAuth::NoCert)).unwrap();
    let untrusting = client_config(&ClientOptions {
        ca: Some(fixture("other-ca.pem")),
        identity: None,
    })
    .unwrap();
    let (client_io, server_io) = duplex(16 * 1024);
    let connector = tokio_rustls::TlsConnector::from(untrusting);
    let (_, connected) = tokio::join!(
        server.acceptor().accept(server_io),
        connector.connect(ServerName::try_from("localhost").unwrap(), client_io)
    );
    assert!(connected.is_err());
}

#[tokio::test]
async fn tls_1_2_only_clients_are_accepted() {
    let server = ServerTls::load(&options(ClientAuth::NoCert)).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_file_iter(fixture("ca.pem")).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    let legacy = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    assert!(handshake(&server, Arc::new(legacy)).await.is_ok());
}

// CoreDNS v1.15.0 plugin/tls/tls_test.go TestTLSClientAuthentication: one policy per keyword.
#[tokio::test]
async fn client_auth_policies_decide_which_certificates_pass() {
    // (policy, no certificate, certificate from the CA, certificate from another CA)
    let cases = [
        (ClientAuth::NoCert, true, true, true),
        (ClientAuth::Request, true, true, true),
        (ClientAuth::Require, false, true, true),
        (ClientAuth::VerifyIfGiven, true, true, false),
        (ClientAuth::RequireAndVerify, false, true, false),
    ];
    for (policy, anonymous, trusted, rogue) in cases {
        let server = ServerTls::load(&options(policy)).unwrap();
        for (identity, expected) in [
            (None, anonymous),
            (Some("client"), trusted),
            (Some("rogue-client"), rogue),
        ] {
            let passed = handshake(&server, client(identity)).await.is_ok();
            assert_eq!(passed, expected, "{policy:?} with {identity:?}");
        }
    }
}

#[tokio::test]
async fn request_policy_reports_the_certificate_a_client_sent() {
    let server = ServerTls::load(&options(ClientAuth::Request)).unwrap();
    assert!(
        handshake(&server, client(Some("rogue-client")))
            .await
            .unwrap()
    );
}

#[test]
fn load_rejects_a_key_that_does_not_match_the_certificate() {
    let mut mismatched = options(ClientAuth::NoCert);
    mismatched.key = fixture("client.key.pem");
    let error = ServerTls::load(&mismatched).unwrap_err();
    assert!(
        error.to_string().contains("could not load TLS cert"),
        "{error}"
    );
}

#[test]
fn load_rejects_a_missing_certificate_file() {
    let mut missing = options(ClientAuth::NoCert);
    missing.cert = fixture("missing.pem");
    let error = ServerTls::load(&missing).unwrap_err();
    assert!(
        error.to_string().contains("could not load TLS cert"),
        "{error}"
    );
}

#[test]
fn load_rejects_a_ca_file_without_certificates() {
    let mut empty = options(ClientAuth::NoCert);
    empty.ca = Some(fixture("server.key.pem"));
    let error = ServerTls::load(&empty).unwrap_err();
    assert!(
        error.to_string().contains("could not read root certs"),
        "{error}"
    );
}

#[tokio::test]
async fn keylog_receives_nss_lines_for_a_handshake() {
    let path = std::env::temp_dir().join(format!("pharos-keylog-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut logged = options(ClientAuth::NoCert);
    logged.keylog = Some(path.clone());
    let server = ServerTls::load(&logged).unwrap();
    handshake(&server, client(None)).await.unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(
        text.lines()
            .any(|line| line.starts_with("CLIENT_HANDSHAKE_TRAFFIC_SECRET ")
                && line.split(' ').count() == 3),
        "{text}"
    );
}

#[test]
fn keylog_in_a_missing_directory_fails_load() {
    let mut logged = options(ClientAuth::NoCert);
    logged.keylog = Some(
        std::env::temp_dir()
            .join("pharos-no-such-dir")
            .join("tls.log"),
    );
    let error = ServerTls::load(&logged).unwrap_err();
    assert!(
        error.to_string().contains("unable to write TLS Key Log"),
        "{error}"
    );
}

// CoreDNS v1.15.0 core/dnsserver/server_tls_test.go TestNewServerTLSRejectsConflictingSharedTLSConfig.
#[test]
fn conflict_names_the_first_differing_policy() {
    let base = ServerTls::load(&options(ClientAuth::RequireAndVerify)).unwrap();
    let load = |change: fn(&mut ServerOptions)| {
        let mut changed = options(ClientAuth::RequireAndVerify);
        change(&mut changed);
        ServerTls::load(&changed).unwrap()
    };
    assert_eq!(base.conflict(&load(|_| {})), None);
    assert_eq!(
        base.conflict(&load(|o| o.client_auth = ClientAuth::NoCert)),
        Some("client authentication policies differ")
    );
    assert_eq!(
        base.conflict(&load(|o| o.ca = Some(fixture("other-ca.pem")))),
        Some("client CA pools differ")
    );
    assert_eq!(
        base.conflict(&load(|o| {
            o.cert = fixture("server-renewed.pem");
            o.key = fixture("server-renewed.key.pem");
        })),
        Some("server certificates differ")
    );
}

#[test]
fn conflict_reports_differing_keylog_paths() {
    let log =
        |name: &str| std::env::temp_dir().join(format!("pharos-{name}-{}", std::process::id()));
    let load = |path: Option<PathBuf>| {
        let mut logged = options(ClientAuth::NoCert);
        logged.keylog = path;
        ServerTls::load(&logged).unwrap()
    };
    let (a, b) = (log("keylog-a"), log("keylog-b"));
    let base = load(Some(a.clone()));
    assert_eq!(base.conflict(&load(Some(a.clone()))), None);
    assert_eq!(
        base.conflict(&load(Some(b.clone()))),
        Some("TLS key log paths differ")
    );
    assert_eq!(base.conflict(&load(None)), Some("TLS key log paths differ"));
    let _ = (std::fs::remove_file(a), std::fs::remove_file(b));
}

/// Negotiated application protocol seen by the server, for a client offering `offered`.
async fn negotiated(server: &ServerTls, offered: &[&[u8]]) -> Option<Vec<u8>> {
    let mut config = (*client(None)).clone();
    config.alpn_protocols = offered.iter().map(|protocol| protocol.to_vec()).collect();
    let (client_io, server_io) = duplex(16 * 1024);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let (accepted, _) = tokio::join!(
        server.acceptor().accept(server_io),
        connector.connect(ServerName::try_from("localhost").unwrap(), client_io)
    );
    accepted
        .unwrap()
        .get_ref()
        .1
        .alpn_protocol()
        .map(<[u8]>::to_vec)
}

// RFC 7301 §3.2: the server picks the first of its protocols that the client offers.
#[tokio::test]
async fn alpn_follows_the_server_preference_and_is_optional() {
    let server = ServerTls::load(&options(ClientAuth::NoCert))
        .unwrap()
        .with_alpn(&[b"h2", b"http/1.1"]);
    assert_eq!(
        negotiated(&server, &[b"http/1.1", b"h2"]).await.as_deref(),
        Some(&b"h2"[..])
    );
    assert_eq!(
        negotiated(&server, &[b"http/1.1"]).await.as_deref(),
        Some(&b"http/1.1"[..])
    );
    assert_eq!(negotiated(&server, &[]).await, None);
}

// RFC 7301 §3.2: no overlap is fatal when the server has protocols and the client offers some.
#[tokio::test]
async fn alpn_without_overlap_fails_the_handshake() {
    let server = ServerTls::load(&options(ClientAuth::NoCert))
        .unwrap()
        .with_alpn(&[b"h2"]);
    let mut config = (*client(None)).clone();
    config.alpn_protocols = vec![b"imap".to_vec()];
    let (client_io, server_io) = duplex(16 * 1024);
    let (accepted, _) = tokio::join!(
        server.acceptor().accept(server_io),
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), client_io)
    );
    assert!(accepted.is_err());
}

#[tokio::test]
async fn alpn_does_not_change_the_shared_listener_policy() {
    let plain = ServerTls::load(&options(ClientAuth::NoCert)).unwrap();
    assert_eq!(plain.conflict(&plain.with_alpn(&[b"h2"])), None);
}

// RFC 9114 §3.1: the QUIC ALPN changes with the Transport, the identity and shared-Listener policy do not.
#[tokio::test]
async fn quic_alpn_does_not_change_the_shared_listener_policy() {
    let plain = ServerTls::load(&options(ClientAuth::NoCert)).unwrap();
    assert_eq!(
        plain.conflict(&plain.with_quic_alpn(doh::H3_ALPN).unwrap()),
        None
    );
}
