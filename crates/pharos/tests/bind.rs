#![forbid(unsafe_code)]
#![recursion_limit = "512"]

mod support;

use std::{
    fs,
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
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

fn answers(address: SocketAddr) -> bool {
    let source = if address.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    };
    let socket = UdpSocket::bind(source).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(150)))
        .unwrap();
    let query = [
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
    ];
    socket.send_to(&query, address).unwrap();
    let mut response = [0; 1024];
    socket
        .recv(&mut response)
        .is_ok_and(|len| len > 12 && response[2] & 0x80 != 0 && response[3] & 15 == 0)
}

#[test]
fn unbound_listener_serves_both_address_families() {
    let ipv6 = TcpListener::bind("[::1]:0").is_ok();
    let port = support::free_port();
    let dir = std::env::temp_dir().join(format!("pharos-bind-wildcard-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("Corefile"), format!(".:{port} {{\n whoami\n}}\n")).unwrap();
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
    assert!(answers(format!("127.0.0.1:{port}").parse().unwrap()));
    assert!(TcpStream::connect(("127.0.0.1", port)).is_ok());
    if ipv6 {
        assert!(answers(format!("[::1]:{port}").parse().unwrap()));
        assert!(TcpStream::connect(("::1", port)).is_ok());
    }
    drop(process);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn loopback_except_and_reload_change_listeners() {
    let ipv6 = TcpListener::bind("[::1]:0").is_ok();
    let port = support::free_port();
    let dir = std::env::temp_dir().join(format!("pharos-bind-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let corefile = dir.join("Corefile");
    let interface = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };
    fs::write(
        &corefile,
        format!(".:{port} {{\n bind {interface} {{\n except ::1\n }}\n whoami\n}}\n"),
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
    let v4 = format!("127.0.0.1:{port}").parse().unwrap();
    assert!(answers(v4));
    if ipv6 {
        let v6 = format!("[::1]:{port}").parse().unwrap();
        assert!(!answers(v6));
        assert!(TcpStream::connect(v6).is_err());
        fs::write(
            &corefile,
            format!(".:{port} {{\n bind 127.0.0.1 ::1\n whoami\n}}\n"),
        )
        .unwrap();
        assert!(
            Command::new("kill")
                .args(["-USR1", &process.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        while !answers(v6) {
            assert!(
                Instant::now() < deadline,
                "reload did not add IPv6 listener"
            );
        }
        assert!(answers(v4));
        fs::write(&corefile, format!(".:{port} {{\n bind ::1\n whoami\n}}\n")).unwrap();
        assert!(
            Command::new("kill")
                .args(["-USR1", &process.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        let deadline = Instant::now() + Duration::from_secs(8);
        while answers(v4) {
            assert!(
                Instant::now() < deadline,
                "reload did not remove IPv4 listener"
            );
        }
        assert!(answers(v6));
    }
    drop(process);
    fs::remove_dir_all(dir).unwrap();
}
