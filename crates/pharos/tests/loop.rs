#![forbid(unsafe_code)]

mod support;

use std::{
    fs,
    io::Read,
    net::UdpSocket,
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

fn start(backend: &str) -> (Process, u16, std::path::PathBuf) {
    let port = support::free_port();
    let dir = std::env::temp_dir().join(format!("pharos-loop-{}-{port}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let backend = backend.replace("{port}", &port.to_string());
    fs::write(
        dir.join("Corefile"),
        format!(".:{port} {{\n loop\n {backend}\n}}\n"),
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_pharos"))
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    (Process(child), port, dir)
}

#[test]
fn self_forwarding_exits_one_with_loop_message() {
    let (mut process, _, dir) = start("forward . 127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "loop was not detected");
        thread::sleep(Duration::from_millis(20));
    };
    let mut output = String::new();
    process
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert_eq!(status.code(), Some(1), "{output}");
    assert!(
        output.contains("Loop (")
            && output.contains("detected for zone \".\"")
            && output.contains("Query: \"HINFO "),
        "{output}"
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn non_looping_whoami_keeps_serving() {
    let (mut process, port, dir) = start("whoami");
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "server exited early"
        );
        socket.send_to(&query, ("127.0.0.1", port)).unwrap();
        let mut response = [0; 512];
        if let Ok((len, _)) = socket.recv_from(&mut response) {
            // RFC 1035 §4.1.1: QR set to 1 identifies a DNS response.
            assert!(len > 12 && response[2] & 0x80 != 0);
            break;
        }
        assert!(Instant::now() < deadline, "server did not respond");
    }
    thread::sleep(Duration::from_secs(3));
    assert!(process.0.try_wait().unwrap().is_none());
    drop(process);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn reload_starts_new_probe_on_installed_chain() {
    let (mut process, port, dir) = start("whoami");
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let query = [0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(process.0.try_wait().unwrap().is_none());
        socket.send_to(&query, ("127.0.0.1", port)).unwrap();
        if socket.recv_from(&mut [0; 512]).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline);
    }
    fs::write(
        dir.join("Corefile"),
        format!(".:{port} {{\n loop\n forward . 127.0.0.1:{port}\n}}\n"),
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
    let status = loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "reload probe did not detect loop"
        );
        thread::sleep(Duration::from_millis(20));
    };
    let mut output = String::new();
    process
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert_eq!(status.code(), Some(1), "{output}");
    assert!(output.contains("detected for zone \".\""), "{output}");
    fs::remove_dir_all(dir).unwrap();
}
