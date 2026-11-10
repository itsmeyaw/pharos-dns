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
    let mut tcp = TcpStream::connect(&address).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    tcp.write_all(&(query.len() as u16).to_be_bytes()).unwrap();
    tcp.write_all(&query).unwrap();
    let mut len = [0; 2];
    tcp.read_exact(&mut len).unwrap();
    let mut response = vec![0; u16::from_be_bytes(len) as usize];
    tcp.read_exact(&mut response).unwrap();
    assert!(response.len() > 12 && response[2] & 0x80 != 0 && response[3] & 0x0f == 0);
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
