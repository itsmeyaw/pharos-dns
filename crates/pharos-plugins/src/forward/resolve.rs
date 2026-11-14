//! Resolve configured hostname Upstreams once, during setup.

use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    time::Duration,
};

use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};

pub(super) fn resolve(host: &str, resolvers: &[SocketAddr]) -> io::Result<Vec<IpAddr>> {
    // RFC 1034 §3.1: an absolute domain name's presentation form ends in a dot.
    let absolute = if host.ends_with('.') {
        host.to_owned()
    } else {
        format!("{host}.")
    };
    let name: Name = absolute
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid Upstream hostname"))?;
    if resolvers.is_empty() {
        let ips = (absolute.as_str(), 0)
            .to_socket_addrs()?
            .map(|address| address.ip())
            .collect::<Vec<_>>();
        return if ips.is_empty() {
            Err(io::Error::other("no addresses found"))
        } else {
            Ok(ips)
        };
    }
    let mut last_error = None;
    for &resolver in resolvers {
        let mut ips = match lookup(&name, resolver, Type::A) {
            Ok(ips) => ips,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        match lookup(&name, resolver, Type::AAAA) {
            Ok(v6) => ips.extend(v6),
            Err(error) if ips.is_empty() => {
                last_error = Some(error);
                continue;
            }
            Err(_) => {}
        }
        if !ips.is_empty() {
            return Ok(ips);
        }
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("no addresses found")))
}

fn lookup(name: &Name, resolver: SocketAddr, qtype: Type) -> io::Result<Vec<IpAddr>> {
    lookup_chain(name, resolver, qtype, 0)
}

fn lookup_chain(
    name: &Name,
    resolver: SocketAddr,
    qtype: Type,
    depth: usize,
) -> io::Result<Vec<IpAddr>> {
    if depth == 16 {
        return Err(io::Error::other("resolver CNAME chain is too long"));
    }
    // RFC 5452 §9.2: outgoing queries use unpredictable IDs.
    let mut id = [0; 2];
    getrandom::getrandom(&mut id).map_err(|_| io::Error::other("random ID generation failed"))?;
    let id = u16::from_ne_bytes(id);
    let mut query = Vec::new();
    // RFC 1035 §4.2.1: UDP messages are limited to 512 octets.
    // RFC 6891 §4.3: traditional DNS messages over UDP are limited to 512 octets.
    let mut builder = MessageBuilder::new(&mut query, 512, id, 0x0100).map_err(io::Error::other)?;
    // RFC 1035 §4.1.2: Encode the name, type, and class in the Question section.
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).map_err(io::Error::other)?,
            qtype,
            Class::IN,
        )
        .map_err(io::Error::other)?;
    let _ = builder.finish();
    let bind = if resolver.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    // RFC 5452 §9.2: Bind port 0 so the OS picks an ephemeral source port per query.
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    socket.connect(resolver)?;
    socket.send(&query)?;
    let mut wire = [0; 65535];
    let len = socket.recv(&mut wire)?;
    let response_len = if len >= 4 && wire[2] & 0x02 != 0 {
        // RFC 7766 §5: Retry truncated UDP responses over TCP.
        let stream = TcpStream::connect_timeout(&resolver, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        let mut stream = stream;
        stream.write_all(&(query.len() as u16).to_be_bytes())?;
        stream.write_all(&query)?;
        let mut frame_len = [0; 2];
        stream.read_exact(&mut frame_len)?;
        let response_len = usize::from(u16::from_be_bytes(frame_len));
        stream.read_exact(&mut wire[..response_len])?;
        response_len
    } else {
        len
    };
    let response = Message::parse(&wire[..response_len]).map_err(io::Error::other)?;
    // RFC 5452 §4.2: Match response ID, QR, and Question before accepting data.
    if response.id() != id
        || !response.qr()
        || response.question_count() != 1
        || !response.questions().all(|question| {
            question.name == NameRef::parse(name.as_wire(), 0).expect("valid configured name")
                && question.qtype == qtype
                && question.qclass == Class::IN
        })
    {
        return Err(io::Error::other("resolver response does not match query"));
    }
    if response.rcode() != pharos_proto::Rcode::NOERROR {
        // RFC 1034 §5.3.3: Do not use address data from an unsuccessful resolution.
        return Err(io::Error::other("resolver returned an error RCODE"));
    }
    let mut ips = Vec::new();
    let mut cname = None;
    for answer in response.answers() {
        // RFC 1034 §5.3.3: Address resolution uses Internet-class records.
        if answer.class != Class::IN {
            continue;
        }
        if answer.rtype == Type::CNAME
            && answer.name == NameRef::parse(name.as_wire(), 0).expect("valid configured name")
        {
            if let Ok(pharos_proto::Rdata::Cname(target)) = answer.data() {
                cname = Some(
                    target
                        .to_string()
                        .parse::<Name>()
                        .map_err(io::Error::other)?,
                );
            }
            continue;
        }
        // RFC 5452 §6: Accept address data only for the queried owner name.
        if answer.name != NameRef::parse(name.as_wire(), 0).expect("valid configured name") {
            continue;
        }
        // RFC 1035 §3.4.1: A RDATA contains a 32-bit Internet address.
        if qtype == Type::A && answer.rtype == Type::A {
            if let Ok(bytes) = <[u8; 4]>::try_from(answer.rdata) {
                ips.push(IpAddr::V4(Ipv4Addr::from(bytes)));
            }
        // RFC 3596 §2.2: AAAA RDATA contains a 128-bit IPv6 address.
        } else if qtype == Type::AAAA
            && answer.rtype == Type::AAAA
            && let Ok(bytes) = <[u8; 16]>::try_from(answer.rdata)
        {
            ips.push(IpAddr::V6(Ipv6Addr::from(bytes)));
        }
    }
    if let Some(target) = cname {
        // RFC 1034 §5.3.3: Restart lookup at the canonical name after a CNAME.
        return lookup_chain(&target, resolver, qtype, depth + 1);
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
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
                0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 30, 0, 16, 6, b't', b'a', b'r', b'g', b'e', b't',
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
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

    #[test]
    fn retries_truncated_udp_answer_over_tcp() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(address).unwrap();
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
}
