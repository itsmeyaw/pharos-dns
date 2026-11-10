use pharos_proto::{Class, Message, MessageBuilder, Opcode, Rcode};

/// Query admission result. `Respond` writes to the supplied Response buffer.
pub enum Admission<'a> {
    Query(Message<'a>),
    Respond,
    Drop,
}

/// Apply the DNS Listener's header, class, and EDNS admission policy.
pub fn admit<'a>(wire: &'a [u8], allow_non_in: bool, response: &mut Vec<u8>) -> Admission<'a> {
    if wire.len() < 12 {
        return Admission::Drop;
    }
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    if flags & 0x8000 != 0 {
        return Admission::Drop;
    }
    let opcode = (flags >> 11) & 15;
    if opcode != 0 && opcode != 4 {
        header_error(wire, response, Rcode::NOTIMP, true);
        return Admission::Respond;
    }
    let count = |i| u16::from_be_bytes([wire[i], wire[i + 1]]);
    if count(4) != 1 || count(6) > 1 || count(8) > 1 || count(10) > 2 {
        header_error(wire, response, Rcode::FORMERR, false);
        return Admission::Respond;
    }
    let Ok(query) = Message::parse(wire) else {
        header_error(wire, response, Rcode::FORMERR, false);
        return Admission::Respond;
    };
    let Some(question) = query.questions().next() else {
        header_error(wire, response, Rcode::SERVFAIL, false);
        return Admission::Respond;
    };
    if !allow_non_in && question.qclass != Class::IN {
        write_error(query, response, Rcode::REFUSED);
        return Admission::Respond;
    }
    if query
        .badvers_response(response)
        .expect("valid BADVERS Response")
        .is_some()
    {
        return Admission::Respond;
    }
    Admission::Query(query)
}

fn header_error(wire: &[u8], response: &mut Vec<u8>, rcode: Rcode, keep_opcode: bool) {
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    let flags = 0x8000 | (flags & 0x03b0) | if keep_opcode { flags & 0x7800 } else { 0 } | rcode.0;
    response.clear();
    response.extend_from_slice(&wire[..2]);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&[0; 8]);
}

pub(crate) fn write_error(query: Message<'_>, response: &mut Vec<u8>, rcode: Rcode) {
    let flags = 0x8000
        | (query.flags() & 0x7800)
        | if query.opcode() == Opcode::QUERY {
            query.flags() & 0x0110
        } else {
            0
        }
        | (rcode.0 & 15);
    let mut builder = MessageBuilder::new(response, usize::from(u16::MAX), query.id(), flags)
        .expect("valid maximum");
    if let Some(question) = query.questions().next() {
        let _ = builder.question(question.name, question.qtype, question.qclass);
    }
    let _ = builder.finish();
}
