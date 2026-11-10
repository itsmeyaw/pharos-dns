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
fn default_server_answers_udp_and_tcp_then_removes_pidfile() {
    let dir = std::env::temp_dir().join(format!("pharos-e2e-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let pidfile = dir.join("pharos.pid");
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_pharos"))
            .current_dir(&dir)
            .args(["-p", &port.to_string(), "--pidfile"])
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
    let query = [
        0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l',
        b'e', 3, b'o', b'r', b'g', 0, 0, 1, 0, 1,
    ];
    let address = format!("127.0.0.1:{port}");
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    udp.send_to(&query, &address).unwrap();
    let mut response = [0; 1024];
    let n = udp.recv(&mut response).unwrap();
    assert!(n > 12 && response[2] & 0x80 != 0 && response[3] & 0x0f == 0);
    assert!(response[..n].windows(4).any(|w| w == b"_udp"));
    assert!(response[..n].windows(4).any(|w| w == [127, 0, 0, 1]));
    let mut tcp = TcpStream::connect(&address).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    tcp.write_all(&(query.len() as u16).to_be_bytes()).unwrap();
    tcp.write_all(&query).unwrap();
    let mut len = [0; 2];
    tcp.read_exact(&mut len).unwrap();
    let mut response = vec![0; u16::from_be_bytes(len) as usize];
    tcp.read_exact(&mut response).unwrap();
    assert!(response.len() > 12 && response[2] & 0x80 != 0 && response[3] & 0x0f == 0);
    assert!(response.windows(4).any(|w| w == b"_tcp"));
    drop(tcp);
    assert!(
        Command::new("kill")
            .args(["-TERM", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(process.0.wait().unwrap().code(), Some(0));
    assert!(!pidfile.exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn explicit_corefile_uses_default_port_quiet_and_signals() {
    let dir = std::env::temp_dir().join(format!("pharos-signals-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("config"), ". {\nwhoami\n}\n").unwrap();
    fs::write(dir.join("Corefile"), ". {\nunknown\n}\n").unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let pidfile = dir.join("pid");
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_pharos"))
            .current_dir(&dir)
            .args([
                "-c",
                "config",
                "--port",
                &port.to_string(),
                "--pidfile",
                "pid",
                "-q",
                "--log-format",
                "json",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !pidfile.exists() {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "server exited early"
        );
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(20));
    }
    TcpStream::connect(("127.0.0.1", port)).unwrap();
    for signal in ["-HUP", "-USR1"] {
        assert!(
            Command::new("kill")
                .args([signal, &process.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        thread::sleep(Duration::from_millis(100));
        assert!(process.0.try_wait().unwrap().is_none());
    }
    assert!(
        Command::new("kill")
            .args(["-QUIT", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(process.0.wait().unwrap().code(), Some(0));
    let mut stdout = String::new();
    process
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let mut stderr = String::new();
    process
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stdout.is_empty());
    assert!(stderr.contains("Reload"));
    assert!(!pidfile.exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn long_quiet_flag_suppresses_startup() {
    let dir = std::env::temp_dir().join(format!("pharos-quiet-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let pid = dir.join("pid");
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_pharos"))
            .current_dir(&dir)
            .args([
                "--conf",
                "stdin",
                "--port",
                &port.to_string(),
                "--pidfile",
                "pid",
                "--quiet",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    process
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b". {\nwhoami\n}\n")
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !pid.exists() {
        assert!(process.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        Command::new("kill")
            .args(["-TERM", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(process.0.wait().unwrap().code(), Some(0));
    let mut stdout = String::new();
    process
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert!(stdout.is_empty());
    assert!(!pid.exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn explicit_port_overrides_flag_and_interrupt_exits_cleanly() {
    let dir = std::env::temp_dir().join(format!("pharos-port-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let unused = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    fs::write(dir.join("config"), format!(".:{port} {{\nwhoami\n}}\n")).unwrap();
    drop(listener);
    let pid = dir.join("pid");
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_pharos"))
            .current_dir(&dir)
            .args([
                "--conf",
                "config",
                "-p",
                &unused.to_string(),
                "--pidfile",
                "pid",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !pid.exists() {
        assert!(process.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(20));
    }
    TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert!(
        Command::new("kill")
            .args(["-INT", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(process.0.wait().unwrap().code(), Some(0));
    let mut stdout = String::new();
    process
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert!(
        stdout.starts_with(&format!(".:{port}\nPharos-")),
        "{stdout}"
    );
    assert!(!pid.exists());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn pidfile_write_failure_is_logged_and_server_keeps_running() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_pharos"))
            .args([
                "--conf",
                "stdin",
                "-p",
                &port.to_string(),
                "--pidfile",
                "/no-such-pharos-directory/pid",
                "-q",
            ])
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    process
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(b". {\nwhoami\n}\n")
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "server exited early"
        );
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_millis(100));
    assert!(process.0.try_wait().unwrap().is_none());
    assert!(
        Command::new("kill")
            .args(["-TERM", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(process.0.wait().unwrap().code(), Some(0));
    let mut stderr = String::new();
    process
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        stderr.contains("[ERROR] Could not write pidfile:"),
        "{stderr}"
    );
}

#[test]
fn empty_corefiles_use_the_default_server() {
    let dir = std::env::temp_dir().join(format!("pharos-empty-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    for (file, content) in [
        ("config", ""),
        ("config", "# comment only\n"),
        ("stdin", ""),
        ("Corefile", "# comment only\n"),
    ] {
        if file == "Corefile" && std::path::Path::new("/etc/pharos/pharos.conf").exists() {
            continue;
        }
        if file != "stdin" {
            fs::write(dir.join(file), content).unwrap();
        }
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut command = Command::new(env!("CARGO_BIN_EXE_pharos"));
        command
            .current_dir(&dir)
            .args(["-p", &port.to_string(), "--pidfile", "pid", "-q"])
            .stdin(Stdio::piped())
            .stderr(Stdio::inherit());
        if file != "Corefile" {
            command.args(["--conf", file]);
        }
        let mut process = Process(command.spawn().unwrap());
        process
            .0
            .stdin
            .take()
            .unwrap()
            .write_all(content.as_bytes())
            .unwrap();
        let pid = dir.join("pid");
        let deadline = Instant::now() + Duration::from_secs(15);
        while !pid.exists() {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "server exited for {file}"
            );
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            TcpStream::connect(("127.0.0.1", port)).is_ok(),
            "default not listening for {file}"
        );
        assert!(
            Command::new("kill")
                .args(["-TERM", &process.0.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(process.0.wait().unwrap().code(), Some(0));
        assert!(!pid.exists());
    }
    fs::remove_dir_all(dir).unwrap();
}
