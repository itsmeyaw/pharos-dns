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
    // RFC 1034 §5.3.3: Bound CNAME restarts; shortcut: 16 aliases, raise when resolver policy is configurable.
    if depth == 16 {
        return Err(io::Error::other("resolver CNAME chain is too long"));
    }
    // RFC 5452 §9.2: outgoing queries use unpredictable IDs.
    let mut id = [0; 2];
    getrandom::getrandom(&mut id).map_err(|_| io::Error::other("random ID generation failed"))?;
    let id = u16::from_ne_bytes(id);
    let question_name = NameRef::parse(name.as_wire(), 0).map_err(io::Error::other)?;
    let mut query = Vec::new();
    // RFC 1035 §4.2.1: UDP messages are limited to 512 octets.
    // RFC 6891 §4.3: traditional DNS messages over UDP are limited to 512 octets.
    let mut builder = MessageBuilder::new(&mut query, 512, id, 0x0100).map_err(io::Error::other)?;
    // RFC 1035 §4.1.2: Encode the name, type, and class in the Question section.
    builder
        .question(question_name, qtype, Class::IN)
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
            question.name == question_name
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
        if answer.rtype == Type::CNAME && answer.name == question_name {
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
        if answer.name != question_name {
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
mod tests;
