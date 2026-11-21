#![forbid(unsafe_code)]

mod support;

use std::{
    fs,
    net::UdpSocket,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
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

struct Server {
    process: Process,
    dir: PathBuf,
    corefile: PathBuf,
    port: u16,
}

impl Server {
    fn start(name: &str, body: impl Fn(&Path) -> String) -> Self {
        let dir = std::env::temp_dir().join(format!("pharos-on-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let port = support::free_port();
        let corefile = dir.join("Corefile");
        fs::write(
            &corefile,
            format!(".:{port} {{\n{}\n whoami\n}}\n", body(&dir)),
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
        let deadline = Instant::now() + Duration::from_secs(10);
        while !pidfile.exists() {
            assert!(process.0.try_wait().unwrap().is_none());
            assert!(Instant::now() < deadline, "startup timed out");
            thread::sleep(Duration::from_millis(10));
        }
        Self {
            process,
            dir,
            corefile,
            port,
        }
    }

    // RFC 1035 §4.1.2: Query asks for A/IN records for the name a; returns the RCODE.
    fn rcode(&self) -> u8 {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let query = [
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
        ];
        socket.send_to(&query, ("127.0.0.1", self.port)).unwrap();
        let mut response = [0; 1024];
        socket.recv(&mut response).unwrap();
        response[3] & 15
    }

    fn signal(&self, name: &str) {
        assert!(
            Command::new("kill")
                .args([name, &self.process.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }

    fn wait_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.process.0.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "shutdown timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .map(|text| text.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

fn wait_for(path: &Path, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while lines(path).len() < count {
        assert!(
            Instant::now() < deadline,
            "{path:?} never reached {count} lines"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn echo(event: &str, log: &Path) -> String {
    format!(" on {event} sh -c 'echo {event} >> {}'", log.display())
}

// coredns/caddy v1.1.4 caddy.go and sigtrap.go: `startup` fires per instance, `shutdown` only at exit.
#[test]
fn each_event_fires_once_at_its_time() {
    let mut server = Server::start("events", |dir| {
        let log = dir.join("log");
        format!("{}\n{}", echo("startup", &log), echo("shutdown", &log))
    });
    let log = server.dir.join("log");
    wait_for(&log, 1);
    assert_eq!(lines(&log), ["startup"]);

    fs::write(
        &server.corefile,
        fs::read_to_string(&server.corefile)
            .unwrap()
            .replace("whoami", "errors"),
    )
    .unwrap();
    server.signal("-USR1");
    wait_for(&log, 2);
    assert_eq!(lines(&log), ["startup", "startup"]);

    server.signal("-TERM");
    assert!(server.wait_exit().success());
    assert_eq!(lines(&log), ["startup", "startup", "shutdown"]);
}

// A hung, failing or missing command never stops Query serving or Reload.
#[test]
fn bad_commands_do_not_block_serving_or_reload() {
    let server = Server::start("bad", |_| {
        " on startup sh -c 'exec sleep 20 >/dev/null 2>&1'\n on startup false\n on startup pharos-no-such-binary".to_owned()
    });
    assert_eq!(server.rcode(), 0);
    fs::write(
        &server.corefile,
        fs::read_to_string(&server.corefile)
            .unwrap()
            .replace("whoami", "errors"),
    )
    .unwrap();
    server.signal("-USR1");
    let deadline = Instant::now() + Duration::from_secs(5);
    while server.rcode() != 2 {
        assert!(Instant::now() < deadline, "reload timed out");
        thread::sleep(Duration::from_millis(10));
    }
}
