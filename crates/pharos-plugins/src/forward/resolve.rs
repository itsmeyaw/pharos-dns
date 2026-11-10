//! Resolve configured hostname Upstreams once, during setup.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    time::Duration,
};

use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};

pub(super) fn resolve(host: &str, resolvers: &[SocketAddr]) -> io::Result<Vec<IpAddr>> {
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
    let mut id = [0; 2];
    getrandom::getrandom(&mut id).map_err(|_| io::Error::other("random ID generation failed"))?;
    let id = u16::from_ne_bytes(id);
    let mut query = Vec::new();
    let mut builder = MessageBuilder::new(&mut query, 512, id, 0x0100).map_err(io::Error::other)?;
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
    let socket = UdpSocket::bind(bind)?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    socket.connect(resolver)?;
    socket.send(&query)?;
    let mut wire = [0; 65535];
    let len = socket.recv(&mut wire)?;
    let response = Message::parse(&wire[..len]).map_err(io::Error::other)?;
    if response.id() != id {
        return Err(io::Error::other("resolver response ID mismatch"));
    }
    let mut ips = Vec::new();
    for answer in response.answers() {
        if qtype == Type::A && answer.rtype == Type::A {
            if let Ok(bytes) = <[u8; 4]>::try_from(answer.rdata) {
                ips.push(IpAddr::V4(Ipv4Addr::from(bytes)));
            }
        } else if qtype == Type::AAAA
            && answer.rtype == Type::AAAA
            && let Ok(bytes) = <[u8; 16]>::try_from(answer.rdata)
        {
            ips.push(IpAddr::V6(Ipv6Addr::from(bytes)));
        }
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
    fn system_resolver_uses_absolute_hostname() {
        assert!(
            resolve("localhost", &[])
                .unwrap()
                .iter()
                .any(IpAddr::is_loopback)
        );
    }
}
