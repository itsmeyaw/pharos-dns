use pharos_proto::{Class, MessageBuilder, NameRef, Opcode, Section, Type};
use pharos_server::{Context, Error, Outcome, Protocol};
use std::net::IpAddr;

/// Returns the client's address and protocol in the Additional section.
#[derive(Debug)]
pub struct Whoami;

impl pharos_server::Plugin for Whoami {
    async fn serve<N: pharos_server::Next + Send>(
        &self,
        context: &mut Context<'_>,
        _next: N,
    ) -> Outcome {
        match response(context) {
            Ok(()) => Outcome::Response,
            Err(error) => Outcome::Error(error),
        }
    }
}

fn response(context: &mut Context<'_>) -> Result<(), Error> {
    let question = context.query.questions().next();
    let name = question.map_or_else(
        || NameRef::parse(&[0], 0).expect("root name"),
        |question| question.name,
    );
    let class = question.map_or(Class(0), |question| question.qclass);
    let max_size = context.max_response_size.max(512);
    if context.response.capacity() < max_size {
        return Err(Error::ResponseBufferTooSmall);
    }
    let mut srv_name = [0_u8; 255];
    let label = match context.protocol {
        Protocol::Udp => b"_udp",
        Protocol::Tcp => b"_tcp",
    };
    srv_name[0] = 4;
    srv_name[1..5].copy_from_slice(label);
    let mut position = 5;
    for label in name.labels() {
        if position + 1 + label.len() >= srv_name.len() {
            return Err(Error::InvalidQuery);
        }
        srv_name[position] = label.len() as u8;
        position += 1;
        srv_name[position..position + label.len()].copy_from_slice(label);
        position += label.len();
    }
    let srv_name = NameRef::parse(&srv_name[..=position], 0).map_err(|_| Error::InvalidQuery)?;
    let mut flags = 0x8400 | (context.query.flags() & 0x7800);
    if context.query.opcode() == Opcode::QUERY {
        flags |= context.query.flags() & 0x0110;
    }
    let mut builder = MessageBuilder::new(context.response, max_size, context.query.id(), flags)
        .map_err(Error::Build)?;
    if let Some(question) = question {
        builder
            .question(question.name, question.qtype, question.qclass)
            .map_err(Error::Build)?;
    }
    match context.client.ip() {
        IpAddr::V4(ip) => {
            builder.record(Section::Additional, name, Type::A, class, 0, &ip.octets())
        }
        IpAddr::V6(ip) => builder.record(
            Section::Additional,
            name,
            Type::AAAA,
            class,
            0,
            &ip.octets(),
        ),
    }
    .map_err(Error::Build)?;
    let port = context.client.port().to_be_bytes();
    builder
        .record(
            Section::Additional,
            srv_name,
            Type::SRV,
            class,
            0,
            &[0, 0, 0, 0, port[0], port[1], 0],
        )
        .map_err(Error::Build)?;
    let _ = builder.finish();
    Ok(())
}
