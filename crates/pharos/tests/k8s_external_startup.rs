#![forbid(unsafe_code)]

mod support;

use std::{
    fs,
    net::{TcpListener, UdpSocket},
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
fn missing_kubernetes_exits_one_with_coredns_error() {
    let port = support::free_port();
    let dir =
        std::env::temp_dir().join(format!("pharos-k8s-startup-{}-{port}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("Corefile"),
        format!(".:{port} {{\n k8s_external example.org\n}}\n"),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "plugin/k8s_external: kubernetes plugin not loaded"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_kubernetes_wins_over_occupied_dns_port() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();
    let _udp = UdpSocket::bind(("127.0.0.1", port)).unwrap();
    let dir =
        std::env::temp_dir().join(format!("pharos-k8s-occupied-{}-{port}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("Corefile"),
        format!(".:{port} {{\n bind 127.0.0.1\n k8s_external example.org\n}}\n"),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        "plugin/k8s_external: kubernetes plugin not loaded"
    );
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    api.set_nonblocking(true).unwrap();
    fs::write(
        dir.join("Corefile"),
        format!(".:{port} {{\n bind 127.0.0.1\n kubernetes cluster.local {{\n  endpoint http://{}\n }}\n}}\n", api.local_addr().unwrap()),
    ).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_pharos"))
        .current_dir(&dir)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains(&format!("127.0.0.1:{port}:"))
    );
    assert_eq!(
        api.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn check_validates_kubernetes_without_starting_controllers() {
    let port = support::free_port();
    let dir = std::env::temp_dir().join(format!("pharos-k8s-check-{}-{port}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let corefile = dir.join("Corefile");
    fs::write(
        &corefile,
        format!(".:{port} {{\n k8s_external example.org\n}}\n"),
    )
    .unwrap();
    let run = |check: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pharos"));
        command.current_dir(&dir);
        if check {
            command.arg("check");
        }
        command.output().unwrap()
    };
    let startup = run(false);
    let check = run(true);
    assert_eq!(startup.status.code(), Some(1));
    assert_eq!(check.status.code(), Some(1));
    assert_eq!(check.stderr, startup.stderr);
    assert_eq!(
        String::from_utf8(check.stderr).unwrap().trim(),
        "plugin/k8s_external: kubernetes plugin not loaded"
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    fs::write(&corefile, format!(".:{port} {{\n k8s_external example.org\n}}\nother:{port} {{\n kubernetes cluster.local {{\n  endpoint http://{}\n }}\n}}\n", listener.local_addr().unwrap())).unwrap();
    let check = run(true);
    assert_eq!(check.status.code(), Some(1));
    assert_eq!(check.stderr, startup.stderr);
    fs::write(&corefile, format!(".:{port} {{\n k8s_external example.org\n kubernetes cluster.local {{\n  endpoint http://{}\n }}\n}}\n", listener.local_addr().unwrap())).unwrap();
    let check = run(true);
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn missing_kubernetes_on_reload_keeps_old_dns_configuration() {
    let port = support::free_port();
    let dir = std::env::temp_dir().join(format!("pharos-k8s-reload-{}-{port}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let corefile = dir.join("Corefile");
    let pidfile = dir.join("pid");
    let logfile = dir.join("log");
    fs::write(&corefile, format!(".:{port} {{\n whoami\n}}\n")).unwrap();
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
        assert!(process.0.try_wait().unwrap().is_none(), "server exited");
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
        let len = socket.recv(&mut response).unwrap();
        assert!(len > 12);
        response[3] & 15
    };
    // RFC 1035 §4.1.1: RCODE 0 means the response has no error condition.
    assert_eq!(ask(), 0);
    fs::write(
        &corefile,
        format!(".:{port} {{\n k8s_external example.org\n}}\n"),
    )
    .unwrap();
    assert!(
        Command::new("kill")
            .args(["-USR1", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !fs::read_to_string(&logfile)
        .unwrap()
        .contains("Reload failed: plugin/k8s_external: kubernetes plugin not loaded")
    {
        assert!(process.0.try_wait().unwrap().is_none(), "server exited");
        assert!(Instant::now() < deadline, "reload failure not reported");
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(ask(), 0);
    drop(process);
    fs::remove_dir_all(dir).unwrap();
}
