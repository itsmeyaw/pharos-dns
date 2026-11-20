use super::*;

fn resolver(ip: Option<[u8; 4]>) -> (SocketAddr, std::thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let mut wire = [0; 512];
        for qtype in [1, 28] {
            let (len, peer) = socket.recv_from(&mut wire).unwrap();
            assert_eq!(
                Message::parse(&wire[..len])
                    .unwrap()
                    .questions()
                    .next()
                    .unwrap()
                    .qtype
                    .0,
                qtype
            );
            wire[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            let mut answer = wire[..len].to_vec();
            if qtype == 1
                && let Some(ip) = ip
            {
                answer[6..8].copy_from_slice(&1_u16.to_be_bytes());
                answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
                answer.extend_from_slice(&ip);
            }
            socket.send_to(&answer, peer).unwrap();
        }
    });
    (address, thread)
}

fn resolver_once(
    respond: impl FnOnce(&mut Vec<u8>, usize) + Send + 'static,
) -> (SocketAddr, std::thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let mut query = [0; 512];
        let (len, peer) = socket.recv_from(&mut query).unwrap();
        let mut response = query[..len].to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        respond(&mut response, len);
        socket.send_to(&response, peer).unwrap();
    });
    (address, thread)
}

#[test]
fn uses_first_resolver_with_addresses() {
    let (first, a) = resolver(None);
    let (second, b) = resolver(Some([192, 0, 2, 123]));
    assert_eq!(
        resolve("upstream.example", &[first, second]).unwrap(),
        ["192.0.2.123".parse::<IpAddr>().unwrap()]
    );
    a.join().unwrap();
    b.join().unwrap();
}

#[test]
fn rejects_query_shaped_wrong_question_and_error_responses() {
    for mutate in [
        Box::new(|response: &mut Vec<u8>, _| {
            response[2..4].copy_from_slice(&0x0100_u16.to_be_bytes());
        }) as Box<dyn FnOnce(&mut Vec<u8>, usize) + Send>,
        Box::new(|response: &mut Vec<u8>, len| {
            response[len - 4..len - 2].copy_from_slice(&Type::AAAA.0.to_be_bytes());
        }),
        Box::new(|response: &mut Vec<u8>, _| {
            response[3] = 0x83;
        }),
    ] {
        let (server, thread) = resolver_once(mutate);
        assert!(lookup(&"host.example.".parse().unwrap(), server, Type::A).is_err());
        thread.join().unwrap();
    }
}

#[test]
fn ignores_address_records_outside_the_answer_name() {
    let (server, thread) = resolver_once(|response, _| {
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[1, b'x', 0, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 77]);
    });
    assert!(
        lookup(&"host.example.".parse().unwrap(), server, Type::A)
            .unwrap()
            .is_empty()
    );
    thread.join().unwrap();
}

#[test]
fn follows_cname_only_answer() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let mut query = [0; 512];
        let (len, peer) = socket.recv_from(&mut query).unwrap();
        let mut response = query[..len].to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[
            0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 30, 0, 16, 6, b't', b'a', b'r', b'g', b'e', b't', 7,
            b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
        ]);
        socket.send_to(&response, peer).unwrap();

        let (len, peer) = socket.recv_from(&mut query).unwrap();
        let mut response = query[..len].to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 88]);
        socket.send_to(&response, peer).unwrap();
    });
    assert_eq!(
        lookup(&"host.example.".parse().unwrap(), address, Type::A).unwrap(),
        ["192.0.2.88".parse::<IpAddr>().unwrap()]
    );
    thread.join().unwrap();
}

// Ephemeral TCP and UDP port spaces are independent, so a same-port pair can collide: retry on a fresh port.
fn bind_pair_std(ip: std::net::IpAddr) -> (std::net::TcpListener, std::net::UdpSocket) {
    for _ in 0..16 {
        let tcp = std::net::TcpListener::bind((ip, 0)).unwrap();
        match std::net::UdpSocket::bind(tcp.local_addr().unwrap()) {
            Ok(udp) => return (tcp, udp),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("bind UDP: {error}"),
        }
    }
    panic!("no free same-port TCP/UDP pair on {ip}");
}

#[test]
fn retries_truncated_udp_answer_over_tcp() {
    let (tcp, udp) = bind_pair_std(std::net::Ipv4Addr::LOCALHOST.into());
    let address = tcp.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let mut query = [0; 512];
        let (len, peer) = udp.recv_from(&mut query).unwrap();
        let mut truncated = query[..len].to_vec();
        truncated[2..4].copy_from_slice(&0x8380_u16.to_be_bytes());
        udp.send_to(&truncated, peer).unwrap();

        let (mut stream, _) = tcp.accept().unwrap();
        let mut frame_len = [0; 2];
        stream.read_exact(&mut frame_len).unwrap();
        let mut query = vec![0; usize::from(u16::from_be_bytes(frame_len))];
        stream.read_exact(&mut query).unwrap();
        let mut response = query.clone();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 99]);
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .unwrap();
        stream.write_all(&response).unwrap();
    });
    assert_eq!(
        lookup(&"host.example.".parse().unwrap(), address, Type::A).unwrap(),
        ["192.0.2.99".parse::<IpAddr>().unwrap()]
    );
    thread.join().unwrap();
}

#[test]
fn system_resolver_uses_absolute_hostname() {
    assert!(
        resolve("localhost", &[])
            .unwrap()
            .iter()
            .any(IpAddr::is_loopback)
    );
}
