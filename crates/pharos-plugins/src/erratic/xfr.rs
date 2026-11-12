use pharos_proto::{Class, MessageBuilder, NameRef, Opcode, Section, Type};
use pharos_server::{Context, Error, Stream};

pub(super) fn stream(context: &Context<'_, '_>, truncated: bool) -> Result<Stream, Error> {
    let question = context
        .query
        .questions()
        .next()
        .ok_or(Error::InvalidQuery)?;
    let mut wire = [0u8; 255];
    let mut len = 0;
    for label in question.name.labels() {
        wire[len] = label.len() as u8;
        len += 1;
        wire[len..len + label.len()].copy_from_slice(label);
        len += label.len();
    }
    len += 1;
    let id = context.query.id();
    let class = question.qclass;
    let mut flags = 0x8400 | (context.query.flags() & 0x7800);
    if context.query.opcode() == Opcode::QUERY {
        flags |= context.query.flags() & 0x0110;
    }
    let mut done = false;
    // shortcut: one allocation per Zone Transfer; remove when a concrete stream type exists.
    Ok(Stream::new(move |response| {
        if done {
            return Ok(false);
        }
        done = true;
        // CoreDNS cannot encode its generated a./b. names for these apexes.
        if len == 1 || len + 2 > wire.len() {
            return Ok(false);
        }
        if response.capacity() < 65535 {
            response.reserve(65535 - response.len());
        }
        let owner = NameRef::parse(&wire[..len], 0).map_err(|_| Error::InvalidQuery)?;
        let mut a_wire = [0u8; 255];
        a_wire[0..2].copy_from_slice(&[1, b'a']);
        a_wire[2..len + 2].copy_from_slice(&wire[..len]);
        let a = NameRef::parse(&a_wire[..len + 2], 0).map_err(|_| Error::InvalidQuery)?;
        let mut b_wire = a_wire;
        b_wire[1] = b'b';
        let b = NameRef::parse(&b_wire[..len + 2], 0).map_err(|_| Error::InvalidQuery)?;
        let mname = NameRef::parse(b"\x03sns\x03dns\x05icann\x03org\0", 0)
            .map_err(|_| Error::InvalidQuery)?;
        let rname = NameRef::parse(b"\x03noc\x03dns\x05icann\x03org\0", 0)
            .map_err(|_| Error::InvalidQuery)?;
        // RFC 8945 §5.3: leave room for Listener-applied TSIG.
        let mut builder = MessageBuilder::new(response, 64500, id, flags).map_err(Error::Build)?;
        if !builder
            .question(owner, Type::AXFR, class)
            .map_err(Error::Build)?
        {
            return Err(Error::ResponseBufferTooSmall);
        }
        // RFC 5936 §2.2: an AXFR begins and ends with the Zone SOA.
        for index in 0..if truncated { 5 } else { 6 } {
            let written = match index {
                0 | 5 => {
                    builder.record_with(Section::Answer, owner, Type::SOA, Class::IN, 0, |writer| {
                        writer.write_name(mname)?;
                        writer.write_name(rname)?;
                        for value in [2018050825u32, 7200, 3600, 1209600, 3600] {
                            writer.write_bytes(&value.to_be_bytes())?;
                        }
                        Ok(())
                    })
                }
                1 | 2 => {
                    builder.record_with(Section::Answer, owner, Type::NS, Class::IN, 0, |writer| {
                        writer.write_name(if index == 1 { b } else { a })
                    })
                }
                3 => builder.record(
                    Section::Answer,
                    a,
                    Type::AAAA,
                    Class::IN,
                    0,
                    &[0x20, 1, 0x0b, 0xd8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53],
                ),
                _ => builder.record(
                    Section::Answer,
                    b,
                    Type::AAAA,
                    Class::IN,
                    0,
                    &[0x20, 1, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x54],
                ),
            }
            .map_err(Error::Build)?;
            if !written {
                return Err(Error::ResponseBufferTooSmall);
            }
        }
        let _ = builder.finish();
        Ok(true)
    }))
}
