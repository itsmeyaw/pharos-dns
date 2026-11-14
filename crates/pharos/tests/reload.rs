#![forbid(unsafe_code)]

mod support;

use std::{
    fs,
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
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

// RFC 1035 §4.2.2: TCP DNS messages use a two-octet length excluding the prefix.
fn tcp_query(stream: &mut TcpStream, query: &[u8]) -> Vec<u8> {
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .unwrap();
    stream.write_all(query).unwrap();
    let mut length = [0; 2];
    stream.read_exact(&mut length).unwrap();
    let mut response = vec![0; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut response).unwrap();
    response
}

fn try_scrape(port: u16) -> Option<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        // RFC 9110 §7.2: HTTP/1.1 request includes Host to identify the target authority.
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    // RFC 9110 §15.3.1: 200 indicates that the metrics request succeeded.
    response.starts_with("HTTP/1.1 200").then_some(response)
}

fn scrape(port: u16) -> String {
    try_scrape(port).expect("metrics endpoint unavailable")
}

fn reload_version(port: u16) -> Option<String> {
    scrape(port)
        .lines()
        .find(|line| line.starts_with("pharos_reload_version_info{"))
        .map(str::to_owned)
}

#[test]
fn comments_and_whitespace_do_not_trigger_reload() {
    let dir = std::env::temp_dir().join(format!("pharos-reload-whitespace-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let (dns, metrics) = (support::free_port(), support::free_port());
    assert_ne!(dns, metrics);
    let file = dir.join("Corefile");
    let body = format!(".:{dns} {{\n reload 2s 0\n prometheus 127.0.0.1:{metrics}\n whoami\n}}\n");
    fs::write(&file, &body).unwrap();
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
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    let before = reload_version(metrics);
    let changed = body.replace(" reload 2s 0", "    reload    2s     0");
    fs::write(
        &file,
        format!("\n# comment\n{changed}\n# another comment\n"),
    )
    .unwrap();
    thread::sleep(Duration::from_millis(2700));
    assert_eq!(
        reload_version(metrics),
        before,
        "comment-only edit caused reload"
    );
    fs::write(&file, body.replace("whoami", "errors")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if try_scrape(metrics).is_some_and(|text| {
            text.lines()
                .any(|line| line.starts_with("pharos_reload_version_info{"))
        }) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "watcher did not observe real edit"
        );
        thread::sleep(Duration::from_millis(10));
    }
    drop(process);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn sigusr1_reloads_without_reload_directive() {
    let dir = std::env::temp_dir().join(format!("pharos-reload-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let port = support::free_port();
    let corefile = dir.join("Corefile");
    fs::write(&corefile, format!(".:{port} {{\nwhoami\n}}\n")).unwrap();
    let pidfile = dir.join("pid");
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_pharos"))
            .current_dir(&dir)
            .args(["--pidfile"])
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
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    // RFC 1035 §4.1.2: Query asks for A/IN records for the name a.
    let query = [
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
    ];
    let ask = || {
        socket.send_to(&query, ("127.0.0.1", port)).unwrap();
        let mut response = [0; 1024];
        socket.recv(&mut response).unwrap();
        response[3] & 15
    };
    assert_eq!(ask(), 0);
    fs::write(&corefile, format!(".:{port} {{\nerrors\n}}\n")).unwrap();
    assert!(
        Command::new("kill")
            .args(["-USR1", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while ask() != 2 {
        assert!(Instant::now() < deadline, "reload timed out");
        thread::sleep(Duration::from_millis(10));
    }
    drop(process);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn invalid_reload_restores_http_and_keeps_dns() {
    let dir = std::env::temp_dir().join(format!("pharos-reload-invalid-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let (dns, metrics) = (support::free_port(), support::free_port());
    assert_ne!(dns, metrics);
    let file = dir.join("Corefile");
    fs::write(
        &file,
        format!(".:{dns} {{\n reload 2s 0\n prometheus 127.0.0.1:{metrics}\n whoami\n}}\n"),
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
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    let initial = scrape(metrics);
    assert!(initial.contains("pharos_reload_failed_total 0\n"));
    assert!(reload_version(metrics).is_none());
    fs::write(&file, format!(".:{dns} {{\n unknown\n")).unwrap();
    thread::sleep(Duration::from_millis(2500));
    assert!(scrape(metrics).contains("pharos_reload_failed_total 0\n"));
    assert!(reload_version(metrics).is_none());
    fs::write(&file, format!(".:{dns} {{\n unknown\n}}\n")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", metrics)) {
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            if stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .is_err()
            {
                continue;
            }
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            if response.contains("pharos_reload_failed_total 1\n") {
                break;
            }
        }
        assert!(Instant::now() < deadline, "failed reload not visible");
        thread::sleep(Duration::from_millis(10));
    }
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    socket
        .send_to(
            &[
                0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
            ],
            ("127.0.0.1", dns),
        )
        .unwrap();
    let mut response = [0; 1024];
    let len = socket.recv(&mut response).unwrap();
    assert!(len > 12 && response[3] & 15 == 0);
    assert!(reload_version(metrics).is_some());
    thread::sleep(Duration::from_millis(2500));
    assert!(scrape(metrics).contains("pharos_reload_failed_total 1\n"));
    drop(process);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn failed_sigusr1_does_not_increment_reload_metrics() {
    let dir = std::env::temp_dir().join(format!(
        "pharos-reload-signal-metric-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let (dns, metrics) = (support::free_port(), support::free_port());
    assert_ne!(dns, metrics);
    let file = dir.join("Corefile");
    fs::write(
        &file,
        format!(".:{dns} {{\n prometheus 127.0.0.1:{metrics}\n whoami\n}}\n"),
    )
    .unwrap();
    let pidfile = dir.join("pid");
    let logfile = dir.join("log");
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_pharos"))
            .current_dir(&dir)
            .arg("--pidfile")
            .arg(&pidfile)
            .stdout(fs::File::create(&logfile).unwrap())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !pidfile.exists() {
        assert!(process.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    assert!(scrape(metrics).contains("pharos_reload_failed_total 0\n"));
    assert!(reload_version(metrics).is_none());
    fs::write(&file, format!(".:{dns} {{\n unknown\n}}\n")).unwrap();
    assert!(
        Command::new("kill")
            .args(["-USR1", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fs::read_to_string(&logfile)
        .unwrap()
        .contains("Reload failed")
    {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", metrics))
            && stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .is_ok()
        {
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            if response.contains("pharos_reload_failed_total 0\n") {
                break;
            }
            assert!(!response.contains("pharos_reload_failed_total 1\n"));
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    assert!(reload_version(metrics).is_none());
    drop(process);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reload_directive_polls_for_changed_corefile() {
    let dir = std::env::temp_dir().join(format!("pharos-reload-poll-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let port = support::free_port();
    let file = dir.join("Corefile");
    let backend = dir.join("backend.override");
    fs::write(&backend, "whoami\n").unwrap();
    fs::write(
        &file,
        format!(".:{port} {{\n reload 2s 0\n import *.override\n}}\n"),
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
        assert!(process.0.try_wait().unwrap().is_none(), "startup failed");
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut query = [
        0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
    ];
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    assert_eq!(tcp_query(&mut tcp, &query)[3] & 15, 0);
    fs::write(&backend, "errors\n").unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut old_responses = 0u16;
    loop {
        query[..2].copy_from_slice(&old_responses.to_be_bytes());
        socket.send_to(&query, ("127.0.0.1", port)).unwrap();
        let mut response = [0; 1024];
        let (length, peer) = socket
            .recv_from(&mut response)
            .expect("unanswered UDP Query during Reload");
        assert_eq!(peer.port(), port);
        // RFC 1035 §4.1.1: QR marks responses, IDs match queries, and RCODE reports status.
        assert!(length >= 12 && response[2] & 0x80 != 0);
        assert_eq!(response[..2], query[..2]);
        if response[3] & 15 == 2 {
            break;
        }
        assert_eq!(response[3] & 15, 0);
        old_responses += 1;
        assert!(Instant::now() < deadline, "polling did not reload");
        thread::sleep(Duration::from_millis(1));
    }
    assert!(old_responses > 0, "no Queries were sent before Reload");
    assert_eq!(tcp_query(&mut tcp, &query)[3] & 15, 2);
    fs::write(&file, format!(".:{port} {{\n errors\n}}\n")).unwrap();
    thread::sleep(Duration::from_millis(2500));
    fs::write(&file, format!(".:{port} {{\n whoami\n}}\n")).unwrap();
    thread::sleep(Duration::from_millis(2500));
    socket.send_to(&query, ("127.0.0.1", port)).unwrap();
    let mut response = [0; 1024];
    socket.recv(&mut response).unwrap();
    assert_eq!(
        response[3] & 15,
        2,
        "polling continued after reload removal"
    );
    drop(process);
    fs::remove_dir_all(dir).unwrap();
}
