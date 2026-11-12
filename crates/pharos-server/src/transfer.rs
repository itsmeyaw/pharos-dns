//! Unsigned Zone Transfer client helpers.

use std::{io, net::SocketAddr, time::Duration};

use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rcode, Type};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Send an unsigned NOTIFY, retrying up to three times as CoreDNS does.
pub async fn notify(
    address: SocketAddr,
    zone: &Name,
    id: u16,
    deadline: Duration,
) -> io::Result<()> {
    // shortcut: one Query buffer allocation per NOTIFY; reuse it when callers batch Zones.
    let mut query = Vec::with_capacity(512);
    // RFC 1996 §3.7: NOTIFY has opcode 4, AA set, and an SOA Question.
    let mut builder = MessageBuilder::new(&mut query, 512, id, 0x2400).map_err(io::Error::other)?;
    builder
        .question(
            NameRef::parse(zone.as_wire(), 0).map_err(io::Error::other)?,
            Type::SOA,
            Class::IN,
        )
        .map_err(io::Error::other)?;
    let _ = builder.finish();
    let bind = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(address).await?;
    let mut wire = [0; 65535];
    let mut last_error = invalid("NOTIFY was not accepted");
    for _ in 0..3 {
        let result = timeout(deadline, async {
            socket.send(&query).await?;
            let len = socket.recv(&mut wire).await?;
            let response =
                Message::parse(&wire[..len]).map_err(|_| invalid("invalid NOTIFY Response"))?;
            // RFC 1996 §3.8: NOTIFY Responses acknowledge the original Message.
            if response.id() != id
                || response.flags() & 0x8000 == 0
                || response.opcode() != pharos_proto::Opcode::NOTIFY
                || response.rcode() != Rcode::NOERROR
            {
                return Err(invalid("NOTIFY was not accepted"));
            }
            Ok(())
        })
        .await;
        match result {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(error)) => last_error = error,
            Err(error) => last_error = io::Error::new(io::ErrorKind::TimedOut, error),
        }
    }
    Err(last_error)
}

/// Receive an AXFR incrementally. The callback must discard partial data on error.
pub async fn axfr(
    address: SocketAddr,
    zone: &Name,
    id: u16,
    deadline: Duration,
    mut on_message: impl FnMut(Message<'_>) -> io::Result<()>,
) -> io::Result<()> {
    // shortcut: buffers are allocated once per Zone Transfer; reuse across transfers when needed.
    let mut query = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut query, 512, id, 0).map_err(io::Error::other)?;
    builder
        .question(
            NameRef::parse(zone.as_wire(), 0).map_err(io::Error::other)?,
            Type::AXFR,
            Class::IN,
        )
        .map_err(io::Error::other)?;
    let _ = builder.finish();
    let mut socket = timeout(deadline, TcpStream::connect(address)).await??;
    // RFC 1035 §4.2.2: TCP Messages are prefixed with a two-octet length.
    timeout(deadline, async {
        socket
            .write_all(&(query.len() as u16).to_be_bytes())
            .await?;
        socket.write_all(&query).await
    })
    .await??;
    let mut wire = Vec::new();
    let mut opening = None;
    loop {
        timeout(deadline, async {
            let length = socket.read_u16().await?;
            wire.resize(usize::from(length), 0);
            socket.read_exact(&mut wire).await?;
            Ok::<_, io::Error>(())
        })
        .await??;
        let message = Message::parse(&wire).map_err(|_| invalid("invalid AXFR Message"))?;
        // RFC 5936 §2.2: every Response belongs to the Query and carries its ID.
        if message.id() != id || message.flags() & 0x8000 == 0 || message.rcode() != Rcode::NOERROR
        {
            return Err(invalid("invalid AXFR Response header"));
        }
        for question in message.questions() {
            if question.name != *zone
                || question.qtype != Type::AXFR
                || question.qclass != Class::IN
            {
                return Err(invalid("invalid AXFR Question"));
            }
        }
        if message.answer_count() == 0 {
            return Err(invalid("empty AXFR Response"));
        }
        let first_message = opening.is_none();
        if first_message {
            opening = Some(wire.clone());
        }
        let original = Message::parse(opening.as_ref().unwrap())
            .map_err(|_| invalid("invalid opening AXFR Message"))?;
        let first = original
            .answers()
            .next()
            .filter(|record| {
                record.rtype == Type::SOA && record.name == *zone && record.class == Class::IN
            })
            .ok_or_else(|| invalid("AXFR must begin with apex SOA"))?;
        let first_data = first.data().map_err(|_| invalid("invalid AXFR SOA"))?;
        let mut done = false;
        for (index, record) in message.answers().enumerate() {
            if record.rtype == Type::SOA && (!first_message || index > 0) {
                // RFC 5936 §2.2: the final RR must be the same SOA that opened the transfer.
                if record.name != first.name
                    || record.class != first.class
                    || record.ttl != first.ttl
                    || record.data().ok() != Some(first_data)
                    || index + 1 != usize::from(message.answer_count())
                {
                    return Err(invalid("invalid closing AXFR SOA"));
                }
                done = true;
            }
        }
        on_message(message)?;
        if done {
            return Ok(());
        }
    }
}
