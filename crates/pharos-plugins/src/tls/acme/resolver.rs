//! The `resolver` option: wait until a DNS server shows the challenge TXT record before the CA is asked to validate it.

use std::{io, net::SocketAddr, time::Duration};

use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rdata, Type};
use tokio::{
    net::{UdpSocket, lookup_host},
    time::{Instant, sleep, timeout},
};

/// How long the record may take to appear; certmagic waits up to 2 minutes (`DefaultPropagationTimeout`).
const PROPAGATION: Duration = Duration::from_secs(120);
const INTERVAL: Duration = Duration::from_secs(2);
const EXCHANGE: Duration = Duration::from_secs(3);

/// Poll `resolver` (`HOST:PORT`) until `record` has a TXT string equal to `value`.
// certmagic v0.25 DNS01Solver.Present: wait for propagation by asking the configured resolvers.
pub(crate) async fn wait(resolver: &str, record: &str, value: &str) -> io::Result<()> {
    let address = lookup_host(resolver)
        .await?
        .next()
        .ok_or_else(|| io::Error::other(format!("ACME resolver {resolver} has no address")))?;
    let deadline = Instant::now() + PROPAGATION;
    loop {
        // A lost or malformed answer is the same as an absent record: ask again until the deadline.
        if let Ok(Ok(true)) = timeout(EXCHANGE, visible(address, record, value)).await {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{record} TXT did not appear at resolver {resolver}"),
            ));
        }
        sleep(INTERVAL).await;
    }
}

async fn visible(resolver: SocketAddr, record: &str, value: &str) -> io::Result<bool> {
    let name: Name = record
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid challenge name"))?;
    let mut id = [0; 2];
    aws_lc_rs::rand::fill(&mut id).map_err(|_| io::Error::other("no random bytes"))?;
    let id = u16::from_be_bytes(id);
    // RFC 1035 §4.1.1: a standard Query with RD set asks the resolver to recurse.
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, id, 0x0100).map_err(io::Error::other)?;
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).map_err(io::Error::other)?,
            Type::TXT,
            Class::IN,
        )
        .map_err(io::Error::other)?;
    let _ = builder.finish();
    let socket = UdpSocket::bind(if resolver.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(resolver).await?;
    socket.send(&wire).await?;
    let mut response = vec![0; 4096];
    loop {
        let len = socket.recv(&mut response).await?;
        let Ok(message) = Message::parse(&response[..len]) else {
            continue;
        };
        // RFC 5452 §9.1: accept only an answer carrying the Query's ID.
        if message.id() != id || !message.qr() {
            continue;
        }
        return Ok(message.answers().any(|record| {
            matches!(record.data(), Ok(Rdata::Txt(txt)) if strings(txt) == value.as_bytes())
        }));
    }
}

// RFC 1035 §3.3.14: TXT RDATA is a sequence of length-prefixed character-strings, read as one value.
fn strings(mut rdata: &[u8]) -> Vec<u8> {
    let mut joined = Vec::new();
    while let Some((&len, rest)) = rdata.split_first() {
        let (text, rest) = rest.split_at(rest.len().min(usize::from(len)));
        joined.extend_from_slice(text);
        rdata = rest;
    }
    joined
}

#[cfg(test)]
mod tests {
    use super::strings;

    #[test]
    fn character_strings_are_joined() {
        assert_eq!(strings(&[2, b'a', b'b', 1, b'c']), b"abc");
        assert_eq!(
            strings(&[9, b'a']),
            b"a",
            "a truncated string yields what is there"
        );
        assert!(strings(&[]).is_empty());
    }
}
