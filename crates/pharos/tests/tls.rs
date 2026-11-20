#![forbid(unsafe_code)]

mod support;

use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    crypto::aws_lc_rs,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
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

// RFC 7858 §3.3: send one DNS Message with RFC 1035 §4.2.2 length framing and return the served certificate.
fn query(port: u16) -> Option<(Vec<u8>, CertificateDer<'static>)> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(fixture("ca.pem")).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    let config = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connection =
        ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", port)).ok()?;
    tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut stream = StreamOwned::new(connection, tcp);
    let wire = [
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
    ];
    stream.write_all(&(wire.len() as u16).to_be_bytes()).ok()?;
    stream.write_all(&wire).ok()?;
    let mut length = [0; 2];
    stream.read_exact(&mut length).ok()?;
    let mut response = vec![0; u16::from_be_bytes(length).into()];
    stream.read_exact(&mut response).ok()?;
    let certificate = stream.conn.peer_certificates()?[0].clone().into_owned();
    Some((response, certificate))
}

fn install(dir: &Path, prefix: &str) {
    fs::copy(fixture(&format!("{prefix}.pem")), dir.join("cert.pem")).unwrap();
    fs::copy(fixture(&format!("{prefix}.key.pem")), dir.join("key.pem")).unwrap();
}

#[test]
fn tls_listener_answers_and_reload_serves_the_renewed_certificate() {
    let port = support::free_port();
    let dir = std::env::temp_dir().join(format!("pharos-tls-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    install(&dir, "server");
    // Relative paths resolve against the working directory, as in CoreDNS.
    fs::write(
        dir.join("Corefile"),
        format!("tls://.:{port} {{\n tls cert.pem key.pem\n whoami\n}}\n"),
    )
    .unwrap();
    let pidfile = dir.join("pid");
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_pharos"))
            .current_dir(&dir)
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
    let (response, before) = query(port).expect("DoT query");
    // RFC 1035 §4.1.1: QR marks a response and RCODE 0 means no error condition.
    assert!(response[2] & 0x80 != 0 && response[3] & 15 == 0);

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
        // The Listener never closes during Reload, so every attempt reaches the same port.
        let (_, served) = query(port).expect("Listener dropped during reload");
        if served != before {
            break;
        }
        assert!(Instant::now() < deadline, "renewed certificate not served");
        thread::sleep(Duration::from_millis(50));
    }
    drop(process);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn invalid_certificate_fails_startup() {
    let port = support::free_port();
    let dir = std::env::temp_dir().join(format!("pharos-tls-bad-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("cert.pem"), "not a certificate").unwrap();
    fs::copy(fixture("server.key.pem"), dir.join("key.pem")).unwrap();
    fs::write(
        dir.join("Corefile"),
        format!("tls://.:{port} {{\n tls cert.pem key.pem\n whoami\n}}\n"),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not load TLS cert"));
    fs::remove_dir_all(dir).unwrap();
}
