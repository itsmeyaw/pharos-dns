#![forbid(unsafe_code)]

mod support;

use std::{
    fs::{self, File},
    io::{Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

const QUERY: &[u8] = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x01a\0\0\x01\0\x01";
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    child: Process,
    dir: Directory,
    upstream: UdpSocket,
    upstream_peer: SocketAddr,
    upstream_query: Vec<u8>,
    _query: TcpStream,
    port: u16,
}

impl Fixture {
    fn new() -> Self {
        let dir = Directory(std::env::temp_dir().join(format!(
            "pharos-reload-drain-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        fs::create_dir_all(&dir.0).unwrap();
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let port = support::free_port();
        let destination = upstream.local_addr().unwrap();
        fs::write(dir.0.join("Corefile"), format!(".:{port} {{\n bind 127.0.0.1\n forward . {destination} {{\n  max_fails 0\n  prefer_udp\n  next SERVFAIL\n }}\n forward . {destination} {{\n  max_fails 0\n  prefer_udp\n }}\n}}\n")).unwrap();
        let log = File::create(dir.0.join("log")).unwrap();
        let mut child = Process(
            Command::new(env!("CARGO_BIN_EXE_pharos"))
                .current_dir(&dir.0)
                .arg("--pidfile")
                .arg(dir.0.join("pid"))
                .stdout(Stdio::from(log))
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !dir.0.join("pid").exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "server exited during startup"
            );
            assert!(Instant::now() < deadline, "startup timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut query = TcpStream::connect(("127.0.0.1", port)).unwrap();
        query
            .write_all(&(QUERY.len() as u16).to_be_bytes())
            .unwrap();
        query.write_all(QUERY).unwrap();
        let mut packet = [0; 512];
        let (len, upstream_peer) = upstream
            .recv_from(&mut packet)
            .expect("upstream did not receive Query");
        Self {
            dir,
            child,
            upstream,
            upstream_peer,
            upstream_query: packet[..len].to_vec(),
            _query: query,
            port,
        }
    }

    fn reload(&self, port: u16) {
        fs::write(
            self.dir.0.join("Corefile"),
            format!(".:{port} {{\n bind 127.0.0.1\n whoami\n}}\n"),
        )
        .unwrap();
        assert!(
            Command::new("kill")
                .args(["-USR1", &self.child.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }

    fn continue_to_second_upstream(&self) {
        let mut response = self.upstream_query.clone();
        response[2] |= 0x80;
        response[3] = (response[3] & 0xf0) | 2;
        self.upstream
            .send_to(&response, self.upstream_peer)
            .unwrap();
        let mut packet = [0; 512];
        self.upstream
            .recv_from(&mut packet)
            .expect("second Upstream did not receive Query");
    }

    fn wait_for_new_answer(&self, port: u16) {
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
                stream
                    .set_read_timeout(Some(Duration::from_millis(100)))
                    .unwrap();
                let mut length = [0; 2];
                if stream
                    .write_all(&(QUERY.len() as u16).to_be_bytes())
                    .is_ok()
                    && stream.write_all(QUERY).is_ok()
                    && stream.read_exact(&mut length).is_ok()
                {
                    let mut response = vec![0; usize::from(u16::from_be_bytes(length))];
                    if stream.read_exact(&mut response).is_ok()
                        && response.len() >= 12
                        && response[2] & 0x80 != 0
                    {
                        return;
                    }
                }
            }
            assert!(Instant::now() < deadline, "new Listener did not answer");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn reload_logs_undrained_replaced_and_removed_listeners_after_five_seconds() {
    for removed in [false, true] {
        let fixture = Fixture::new();
        let new_port = if removed {
            support::free_port()
        } else {
            fixture.port
        };
        let started = Instant::now();
        fixture.reload(new_port);
        fixture.wait_for_new_answer(new_port);
        while started.elapsed() < Duration::from_secs(1) {
            std::thread::sleep(Duration::from_millis(10));
        }
        fixture.continue_to_second_upstream();
        let expected = format!(
            "ERROR Stopping 127.0.0.1:{}: context deadline exceeded",
            fixture.port
        );
        let deadline = started + Duration::from_secs(9);
        loop {
            let text = fs::read_to_string(fixture.dir.0.join("log")).unwrap();
            if text.contains(&expected) {
                assert_eq!(text.matches(&expected).count(), 1);
                break;
            }
            assert!(Instant::now() < deadline, "missing timeout log: {text}");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(started.elapsed() >= Duration::from_millis(4500));
        fixture.wait_for_new_answer(new_port);
    }
}

#[test]
fn sigterm_is_serviced_while_replaced_handler_is_draining() {
    let fixture = Fixture::new();
    fixture.reload(fixture.port);
    fixture.wait_for_new_answer(fixture.port);
    assert!(
        Command::new("kill")
            .args(["-TERM", &fixture.child.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while fixture.dir.0.join("pid").exists() {
        assert!(
            Instant::now() < deadline,
            "SIGTERM was not serviced during Reload"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
