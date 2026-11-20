#![forbid(unsafe_code)]

mod support;

use std::{
    fs,
    net::UdpSocket,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
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

fn start(dir: &Path, corefile: &str) -> Process {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("Corefile"), corefile).unwrap();
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

fn query(port: u16) -> Option<Vec<u8>> {
    let wire = [
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
    ];
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    udp.send_to(&wire, ("127.0.0.1", port)).unwrap();
    let mut response = [0; 1024];
    let n = udp.recv(&mut response).ok()?;
    Some(response[..n].to_vec())
}

// RFC 8484 §4.1: a DoH Upstream is reached with Message ID 0, and the client sees its own ID again.
#[test]
fn forward_reaches_the_https_listener_with_either_method() {
    let dir = std::env::temp_dir().join(format!("pharos-forward-https-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let upstream = support::free_port();
    fs::copy(fixture("server.pem"), dir.join("cert.pem")).unwrap();
    fs::copy(fixture("server.key.pem"), dir.join("key.pem")).unwrap();
    let _upstream = start(
        &dir.join("upstream"),
        &format!(
            "https://.:{upstream} {{\n tls {0}/cert.pem {0}/key.pem\n whoami\n}}\n",
            dir.display()
        ),
    );
    let ca = fixture("ca.pem");
    for (method, name, ok) in [
        ("POST", "localhost", true),
        ("GET", "localhost", true),
        ("POST", "wrong.example", false),
    ] {
        let front = support::free_port();
        let _front = start(
            &dir.join(format!("front-{method}-{name}")),
            &format!(
                ".:{front} {{\n forward . https://127.0.0.1:{upstream} {{\n  tls {ca}\n  tls_servername {name}\n  doh_method {method}\n }}\n}}\n",
                ca = ca.display()
            ),
        );
        let response = query(front).expect("front-end did not answer");
        assert_eq!(&response[..2], &[0x12, 0x34], "{method} {name}");
        // RFC 1035 §4.1.1: QR marks a response; RCODE 0 is NOERROR, 2 is SERVFAIL.
        assert!(response[2] & 0x80 != 0, "{method} {name}");
        assert_eq!(response[3] & 15, if ok { 0 } else { 2 }, "{method} {name}");
        if ok {
            assert!(response.windows(4).any(|w| w == b"_tcp"), "{method} {name}");
        }
    }
    fs::remove_dir_all(dir).unwrap();
}
