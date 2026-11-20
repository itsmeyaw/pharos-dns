#![forbid(unsafe_code)]

mod support;

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use quinn::{
    ClientConfig, Connection, ConnectionError, Endpoint, crypto::rustls::QuicClientConfig,
};
use rustls::{
    ClientConfig as TlsConfig, RootCertStore,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, pem::PemObject},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/tls")
        .join(name)
}

fn install(dir: &Path, prefix: &str) {
    fs::copy(fixture(&format!("{prefix}.pem")), dir.join("cert.pem")).unwrap();
    fs::copy(fixture(&format!("{prefix}.key.pem")), dir.join("key.pem")).unwrap();
}

async fn connect(port: u16) -> Option<(Endpoint, Connection)> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(fixture("ca.pem")).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut tls = TlsConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).unwrap(),
    )));
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let connecting = endpoint.connect(address, "localhost").ok()?;
    let connection = tokio::time::timeout(Duration::from_secs(2), connecting)
        .await
        .ok()?
        .ok()?;
    Some((endpoint, connection))
}

// RFC 9250 §4.2: one length-prefixed Query per stream, Message ID zero.
async fn exchange(connection: &Connection, id: u16) -> Option<Vec<u8>> {
    let wire = [
        (id >> 8) as u8,
        id as u8,
        1,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        b'a',
        0,
        0,
        1,
        0,
        1,
    ];
    let (mut send, mut recv) = connection.open_bi().await.ok()?;
    send.write_all(&(wire.len() as u16).to_be_bytes())
        .await
        .ok()?;
    send.write_all(&wire).await.ok()?;
    send.finish().ok()?;
    let response = tokio::time::timeout(Duration::from_secs(2), recv.read_to_end(65_537))
        .await
        .ok()?
        .ok()?;
    Some(response[2..].to_vec())
}

fn start(dir: &Path, port: u16) -> Process {
    fs::write(
        dir.join("Corefile"),
        format!("quic://.:{port} {{\n tls cert.pem key.pem\n quic {{\n  max_streams 8\n }}\n whoami\n}}\n"),
    )
    .unwrap();
    let pidfile = dir.join("pid");
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_pharos"))
            .current_dir(dir)
            .arg("--pidfile")
            .arg(&pidfile)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !pidfile.exists() {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "server exited early"
        );
        assert!(Instant::now() < deadline, "server did not start");
        thread::sleep(Duration::from_millis(20));
    }
    process
}

#[test]
fn quic_listener_answers_and_reload_serves_the_renewed_certificate() {
    let port = support::free_port();
    let dir = std::env::temp_dir().join(format!("pharos-quic-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    install(&dir, "server");
    let process = start(&dir, port);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let certificate = |connection: &Connection| {
            connection
                .peer_identity()
                .unwrap()
                .downcast::<Vec<CertificateDer<'static>>>()
                .unwrap()[0]
                .clone()
        };
        let (_endpoint, connection) = connect(port).await.expect("DoQ connection");
        let before = certificate(&connection);
        let response = exchange(&connection, 0).await.expect("DoQ response");
        // RFC 1035 §4.1.1: QR marks a response and RCODE 0 means no error condition.
        assert!(response[2] & 0x80 != 0 && response[3] & 15 == 0);

        // RFC 9250 §4.3.3: a non-zero Message ID aborts the connection with DOQ_PROTOCOL_ERROR.
        let (_endpoint, bad) = connect(port).await.expect("DoQ connection");
        assert!(exchange(&bad, 0x1234).await.is_none());
        assert!(matches!(
            bad.closed().await,
            ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 2
        ));

        install(&dir, "server-renewed");
        assert!(
            Command::new("kill")
                .args(["-USR1", &process.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let (_endpoint, connection) =
                connect(port).await.expect("Listener dropped during reload");
            if certificate(&connection) != before {
                break;
            }
            assert!(Instant::now() < deadline, "renewed certificate not served");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    drop(process);
    fs::remove_dir_all(dir).unwrap();
}
