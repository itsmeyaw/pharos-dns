use pharos_proto::{Class, Message, MessageBuilder, NameRef, Opcode, Opt, Rcode, Type};

/// Query admission result. `Respond` writes to the supplied Response buffer.
// Keep the Message inline: boxing it would allocate for every Query.
#[allow(clippy::large_enum_variant)]
pub enum Admission<'a> {
    Query(Message<'a>),
    Respond,
    Drop,
}

/// Apply the DNS Listener's header, class, and EDNS admission policy.
pub fn admit<'a>(wire: &'a [u8], allow_non_in: bool, response: &mut Vec<u8>) -> Admission<'a> {
    admit_with_update(wire, allow_non_in, false, response)
}

/// Apply Listener admission, permitting UPDATE when a configured Chain accepts it.
pub fn admit_with_update<'a>(
    wire: &'a [u8],
    allow_non_in: bool,
    allow_update: bool,
    response: &mut Vec<u8>,
) -> Admission<'a> {
    // RFC 5625 §6.3: Intrinsically malformed packets MAY be dropped; a header-less packet has no usable ID and a reply would amplify it.
    if wire.len() < 12 {
        return Admission::Drop;
    }
    // RFC 1035 §4.1.1: QR=1 identifies a Response, not a request.
    if wire[2] & 0x80 != 0 {
        return Admission::Drop;
    }
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    // RFC 6895 §2.1: Do not reject the reserved DNS header Z bit.
    let opcode = Opcode(((flags >> 11) & 15) as u8);
    let count = |i| u16::from_be_bytes([wire[i], wire[i + 1]]);
    // RFC 8490 §§5.4.1, 5.4.3: DSO unidirectional Messages have ID zero and no Response.
    if opcode == Opcode::STATEFUL {
        if is_dso_unidirectional(wire) {
            return Admission::Drop;
        }
        // RFC 8490 §5.4: DSO Messages have zero counts in every DNS section.
        if wire[4..12].iter().any(|byte| *byte != 0) {
            header_error(wire, response, Rcode::FORMERR);
            return Admission::Respond;
        }
        // RFC 8490 §5.4.1: DSO-not-supported Responses use NOTIMP.
        header_error(wire, response, Rcode::NOTIMP);
        return Admission::Respond;
    }
    // RFC 3425 §3: Obsolete IQUERY requests receive NOTIMP.
    if opcode != Opcode::QUERY
        && opcode != Opcode::NOTIFY
        && !(opcode == Opcode::UPDATE && allow_update)
    {
        // RFC 2136 §3: An unimplemented UPDATE receives NOTIMP before message validation.
        header_error(wire, response, Rcode::NOTIMP);
        return Admission::Respond;
    }
    let update_query = if opcode == Opcode::UPDATE {
        // RFC 2136 §2.3: The UPDATE Zone Section contains exactly one record.
        if count(4) != 1 {
            header_error(wire, response, Rcode::FORMERR);
            return Admission::Respond;
        }
        match Message::parse(wire) {
            Ok(query) => Some(query),
            _ => {
                // RFC 1035 §4.1.1; RFC 2136 §3.1.1: Malformed accepted UPDATEs receive FORMERR.
                header_error(wire, response, Rcode::FORMERR);
                return Admission::Respond;
            }
        }
    } else {
        None
    };
    // RFC 9619 §4: QUERY permits zero questions and requires FORMERR above one.
    // RFC 2136 §§2.4–2.5: UPDATE prerequisite and update sections may contain multiple records.
    // RFC 1996 §§3.7, 3.9: NOTIFY requires at least one Question and ignores other sections.
    if (opcode == Opcode::NOTIFY && count(4) == 0)
        || (opcode != Opcode::UPDATE && opcode != Opcode::NOTIFY && count(4) > 1)
        || (opcode != Opcode::UPDATE
            && opcode != Opcode::NOTIFY
            && (count(6) > 1 || count(8) > 1 || count(10) > 2))
    {
        header_error(wire, response, Rcode::FORMERR);
        return Admission::Respond;
    }
    // RFC 6891 §6.1.1: Message parsing rejects duplicate OPT records.
    let Some(query) = update_query.or_else(|| Message::parse(wire).ok()) else {
        header_error(wire, response, Rcode::FORMERR);
        return Admission::Respond;
    };
    if query.has_nonfinal_tsig() {
        // RFC 8945 §5.2: a misplaced TSIG requires FORMERR even without a TSIG Plugin.
        header_error(wire, response, Rcode::FORMERR);
        return Admission::Respond;
    }
    // RFC 2930 §3: A server without TKEY service returns NOTIMP (or REFUSED); Pharos returns NOTIMP.
    if query.opcode() == Opcode::QUERY
        && query
            .questions()
            .any(|question| question.qtype == Type::TKEY)
    {
        write_error(query, response, Rcode::NOTIMP);
        return Admission::Respond;
    }
    // RFC 1996 §3.9: hide ignored Authority and Additional records from handlers.
    let query = query.ignore_notify_sections();
    // RFC 1035 §4.1.1: RCODE 5 refuses an operation for policy reasons.
    if !allow_non_in
        && query
            .questions()
            .next()
            .is_some_and(|q| q.qclass != Class::IN)
    {
        write_error(query, response, Rcode::REFUSED);
        return Admission::Respond;
    }
    // RFC 6891 §6.1.3: an unsupported EDNS version requires BADVERS.
    if query
        .badvers_response(response)
        .expect("valid BADVERS Response")
        .is_some()
    {
        return Admission::Respond;
    }
    Admission::Query(query)
}

// RFC 8490 §5.4.1; shortcut: skip Primary-TLV parsing for ID-zero DSO until support lands.
pub(crate) fn is_dso_unidirectional(wire: &[u8]) -> bool {
    if wire.len() < 12 {
        return false;
    }
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    flags & 0x8000 == 0
        && Opcode(((flags >> 11) & 15) as u8) == Opcode::STATEFUL
        && wire[0..2] == [0, 0]
}

fn header_error(wire: &[u8], response: &mut Vec<u8>, rcode: Rcode) {
    let flags = u16::from_be_bytes([wire[2], wire[3]]);
    // RFC 6895 §2: copy OPCODE, RD, and CD; clear TC, RA, AD, and Z.
    let dso = Opcode(((flags >> 11) & 15) as u8) == Opcode::STATEFUL;
    // RFC 8490 §5.4.1: DSO Response reserved flag bits are zero.
    let flags = 0x8000 | (flags & 0x7800) | if dso { 0 } else { flags & 0x0110 } | rcode.0;
    // RFC 1035 §4.1.1: copy Questions only from a fully parsed Message.
    let mut pointer_budget = NameRef::MAX_MESSAGE_POINTER_HOPS;
    let parsed = Message::parse_with_pointer_budget(wire, &mut pointer_budget);
    let query = parsed.ok();
    // RFC 1035 §4.1.4: malformed-message recovery shares the aggregate pointer budget.
    // RFC 6891 §7: preserve raw OPT presence when strict option parsing fails.
    let raw_opt = if query.is_none() {
        raw_opt(wire, &mut pointer_budget)
    } else {
        None
    };
    // RFC 1035 §4.1.1: construct a Response with the Query ID and selected RCODE.
    let Some(mut builder) = MessageBuilder::new(
        response,
        usize::from(u16::MAX),
        u16::from_be_bytes([wire[0], wire[1]]),
        flags,
    )
    .ok() else {
        // RFC 1035 §4.1.1: preserve the Message ID and FORMERR RCODE in the minimal Response.
        response.clear();
        response.extend_from_slice(&wire[..2]);
        response.extend_from_slice(&flags.to_be_bytes());
        response.extend_from_slice(&[0; 8]);
        return;
    };
    // RFC 1035 §4.1.1: copy validated Questions into the Response.
    if let Some(query) = &query {
        for question in query.questions() {
            let _ = builder.question(question.name, question.qtype, question.qclass);
        }
    } else if let Some((name, qtype, qclass)) = raw_question(wire, &mut pointer_budget) {
        // RFC 1035 §4.1.2: recover the first Question from an otherwise malformed Message.
        let _ = builder.question(name, qtype, qclass);
    }
    // RFC 6891 §7: include an OPT Response when a valid Query contained OPT.
    if let Some(opt) = query.as_ref().and_then(Message::opt) {
        let response_opt = opt.response_registered(None, rcode);
        if builder.reserve_response_opt(&response_opt).is_ok() {
            let _ = builder.finish_with_response_opt(&response_opt);
            return;
        }
    } else if let Some(opt_flags) = raw_opt {
        // RFC 6891 §7: preserve EDNS's presence on FORMERR, even when option parsing failed.
        let ttl = (u32::from((rcode.0 >> 4) as u8) << 24)
            // RFC 9824 §5.1: preserve CO; reserved EDNS flag bits remain zero.
            | u32::from(opt_flags & 0x4000)
            | if opt_flags & 0x8000 != 0 { 0x8000 } else { 0 };
        let mut opt = [0; 11];
        opt[1..3].copy_from_slice(&41_u16.to_be_bytes());
        opt[3..5].copy_from_slice(&Opt::RESPONSE_UDP_PAYLOAD_SIZE.to_be_bytes());
        opt[5..9].copy_from_slice(&ttl.to_be_bytes());
        if builder.reserve(opt.len()).is_ok() {
            let _ = builder.finish_with_opt(&opt);
            return;
        }
    }
    let _ = builder.finish();
}

// RFC 1035 §4.1.2: recover the first Question without constructing a validated Message.
fn raw_question<'a>(
    wire: &'a [u8],
    pointer_budget: &mut usize,
) -> Option<(NameRef<'a>, Type, Class)> {
    if wire.len() < 12 || u16::from_be_bytes([wire[4], wire[5]]) == 0 {
        return None;
    }
    let name = NameRef::parse_with_budget(wire, 12, pointer_budget).ok()?;
    let offset = 12 + name.wire_len();
    Some((
        name,
        Type(u16::from_be_bytes(
            wire.get(offset..offset + 2)?.try_into().ok()?,
        )),
        Class(u16::from_be_bytes(
            wire.get(offset + 2..offset + 4)?.try_into().ok()?,
        )),
    ))
}

// RFC 6891 §7: fall back only when strict parsing rejects malformed EDNS; recover OPT presence.
fn raw_opt(wire: &[u8], pointer_budget: &mut usize) -> Option<u16> {
    if wire.len() < 12 {
        return None;
    }
    let counts = [
        u16::from_be_bytes([wire[4], wire[5]]),
        u16::from_be_bytes([wire[6], wire[7]]),
        u16::from_be_bytes([wire[8], wire[9]]),
        u16::from_be_bytes([wire[10], wire[11]]),
    ];
    let mut offset = 12;
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            let name = NameRef::parse_with_budget(wire, offset, pointer_budget).ok()?;
            offset = offset.checked_add(name.wire_len())?;
            if section == 0 {
                offset = offset.checked_add(4)?;
            } else {
                let fields = wire.get(offset..offset + 10)?;
                let rtype = u16::from_be_bytes([fields[0], fields[1]]);
                let flags = u16::from_be_bytes([fields[6], fields[7]]);
                let rdata_len = usize::from(u16::from_be_bytes([fields[8], fields[9]]));
                let end = offset.checked_add(10 + rdata_len)?;
                if end > wire.len() {
                    return None;
                }
                if rtype == Type::OPT.0 && section == 3 {
                    return Some(flags);
                }
                offset = end;
            }
            if offset > wire.len() {
                return None;
            }
        }
    }
    None
}

// RFC 5936 §2.2: AXFR errors end with one Response carrying the applicable RCODE.
pub fn write_error(query: Message<'_>, response: &mut Vec<u8>, rcode: Rcode) {
    // RFC 1035 §4.1.1: QR marks a response; the opcode and RD are copied from the query.
    let flags = 0x8000
        | (query.flags() & 0x7800)
        | if query.opcode() == Opcode::QUERY {
            // RFC 4035 §3.2.2: Copy the query's CD bit into the response.
            query.flags() & 0x0110
        } else {
            0
        }
        | (rcode.0 & 15);
    // RFC 1035 §4.1.1: Copy the Query ID into the Response.
    let mut builder = MessageBuilder::new(response, usize::from(u16::MAX), query.id(), flags)
        .expect("valid maximum");
    // RFC 5936 §2.2.2: Copy the AXFR Query's Question into an error Response.
    if let Some(question) = query.questions().next() {
        let _ = builder.question(question.name, question.qtype, question.qclass);
    }
    let _ = builder.finish();
}
