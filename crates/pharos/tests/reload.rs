#![forbid(unsafe_code)]

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
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

#[test]
fn sigusr1_reloads_without_reload_directive() {
    let dir = std::env::temp_dir().join(format!("pharos-reload-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
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
    let ports: Vec<_> = (0..2)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let dns = ports[0].local_addr().unwrap().port();
    let metrics = ports[1].local_addr().unwrap().port();
    drop(ports);
    let file = dir.join("Corefile");
    fs::write(
        &file,
        format!(".:{dns} {{\n prometheus 127.0.0.1:{metrics}\n whoami\n}}\n"),
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
    fs::write(&file, format!(".:{dns} {{\n unknown\n}}\n")).unwrap();
    assert!(
        Command::new("kill")
            .args(["-USR1", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", metrics)) {
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .unwrap();
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
    drop(process);
    fs::remove_dir_all(dir).unwrap();
}
