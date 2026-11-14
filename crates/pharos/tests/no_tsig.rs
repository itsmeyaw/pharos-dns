#![forbid(unsafe_code)]

mod support;

use std::{
    fs,
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn unsigned_listener_matches_pre_tsig_udp_and_tcp_wire() {
    // RFC 1035 §4.2: UDP and TCP carry identical DNS Messages apart from TCP framing.
    // Fixtures were captured from commit 687f5bad56105aae6ac00c9582deab998f346884.
    let fixture =
        Fixture(std::env::temp_dir().join(format!("pharos-no-tsig-{}", std::process::id())));
    fs::create_dir_all(&fixture.0).unwrap();
    let port = support::free_port();
    let mut config = format!(
        ".:{port} {{\n hosts /nonexistent example. {{\n ttl 60\n 192.0.2.200 one.example.\n"
    );
    for i in 1..=40 {
        config.push_str(&format!(" 192.0.2.{i} many.example.\n"));
    }
    config.push_str(" }\n}\n");
    fs::write(fixture.0.join("Corefile"), config).unwrap();
    let pidfile = fixture.0.join("pid");
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_pharos"))
            .current_dir(&fixture.0)
            .arg("--pidfile")
            .arg(&pidfile)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !pidfile.exists() {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "server exited before startup"
        );
        assert!(Instant::now() < deadline, "server did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut cases = 0;
    for line in include_str!("fixtures/no-tsig-responses.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let (case, hex) = line.split_once('=').unwrap();
        let edns = case.contains("_edns_");
        let large = case.ends_with("_large");
        let tcp = case.starts_with("tcp_");
        let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, u8::from(edns)];
        let label = if large {
            b"many".as_slice()
        } else {
            b"one".as_slice()
        };
        // RFC 1035 §4.1.2: Questions carry a label-encoded QNAME and two-octet QTYPE and QCLASS.
        query.push(label.len() as u8);
        query.extend_from_slice(label);
        query.extend_from_slice(b"\x07example\0\0\x01\0\x01");
        if edns {
            // RFC 6891 §6.1.3: OPT TTL carries the extended RCODE, EDNS version, and flags.
            query.extend_from_slice(&[0, 0, 41, 2, 0, 0, 0, 0x80, 0, 0, 0]);
        }
        let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        let expected: Vec<u8> = pairs
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        // RFC 1035 §4.2.2: TCP DNS messages use a two-octet length excluding the prefix.
        let actual = if tcp {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .write_all(&(query.len() as u16).to_be_bytes())
                .unwrap();
            socket.write_all(&query).unwrap();
            let mut len = [0; 2];
            socket.read_exact(&mut len).unwrap();
            let mut response = vec![0; usize::from(u16::from_be_bytes(len))];
            socket.read_exact(&mut response).unwrap();
            response
        } else {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket.send_to(&query, ("127.0.0.1", port)).unwrap();
            let mut response = vec![0; 65535];
            let len = socket.recv(&mut response).unwrap();
            response.truncate(len);
            response
        };
        assert_eq!(actual, expected, "{case}");
        // RFC 1035 §4.2.1: UDP payloads over 512 octets here are truncated with TC set.
        assert_eq!(actual[2] & 0x02 != 0, large && !tcp, "{case}");
        cases += 1;
    }
    assert_eq!(cases, 8);
}
