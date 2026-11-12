use pharos_proto::{EdnsOptions, Message, Opt, Rcode, Type, normalized_udp_size};

use crate::{Action, Error, Outcome, Protocol, admission::write_error};

/// Maximum Response size requested by the client for this protocol.
pub fn response_limit(query: Message<'_>, protocol: Protocol) -> usize {
    // RFC 6891 §6.2.3: EDNS advertises a UDP payload size, with a 512-octet minimum.
    usize::from(normalized_udp_size(
        query.opt().map_or(512, |opt| opt.udp_payload_size()),
        protocol == Protocol::Tcp,
    ))
}

/// Finish a Plugin outcome, reporting Plugin and malformed Response errors.
pub fn finish_outcome(
    query: Message<'_>,
    protocol: Protocol,
    outcome: Outcome,
    response: &mut Vec<u8>,
    mut log: impl FnMut(Error),
) -> Action {
    match outcome {
        Outcome::Drop => return Action::Drop,
        Outcome::Stream(stream) => {
            return if protocol == Protocol::Tcp {
                Action::Stream(stream)
            } else {
                Action::Drop
            };
        }
        Outcome::Unanswered(code) => {
            if !matches!(
                code,
                Rcode::SERVFAIL | Rcode::REFUSED | Rcode::FORMERR | Rcode::NOTIMP
            ) {
                return Action::Drop;
            }
            write_error(query, response, code);
        }
        Outcome::Error(error) => {
            log(error);
            write_error(query, response, Rcode::SERVFAIL);
        }
        Outcome::Response => {}
    }
    if let Err(error) = scrub(query, response_limit(query, protocol), protocol, response) {
        log(error);
        write_error(query, response, Rcode::SERVFAIL);
    }
    Action::Respond
}

fn scrub(
    query: Message<'_>,
    limit: usize,
    protocol: Protocol,
    wire: &mut Vec<u8>,
) -> Result<(), Error> {
    let message = Message::parse(wire).map_err(|_| Error::InvalidQuery)?;
    if query.opt().is_none() && message.opt().is_none() && wire.len() <= limit {
        return Ok(());
    }
    let mut options = [0_u8; 65535];
    let existing = message.opt().map(|opt| {
        let bytes = opt.options().as_bytes();
        options[..bytes.len()].copy_from_slice(bytes);
        (
            opt.udp_payload_size(),
            opt.extended_rcode(),
            opt.version(),
            opt.flags(),
            bytes.len(),
        )
    });
    let existing = existing.map(|(size, code, version, flags, len)| {
        Opt::new(
            size,
            code,
            version,
            flags,
            EdnsOptions::parse(&options[..len]).expect("validated options"),
        )
    });
    let rcode = message.rcode();
    // RFC 6891 §6.1.1: an EDNS request requires an OPT record in the response.
    let response_opt = query
        .opt()
        .map(|opt| opt.response_registered(existing, rcode));
    let opt_len = response_opt.map_or(0, |opt| opt.wire_len());
    // RFC 6891 §7: a truncated EDNS response must retain the question and OPT record.
    let budget = limit
        .max(512)
        .checked_sub(opt_len)
        .ok_or(Error::ResponseBufferTooSmall)?;
    let mut end = 12
        + message
            .questions()
            .map(|q| q.name.wire_len() + 4)
            .sum::<usize>();
    if end > budget {
        return Err(Error::ResponseBufferTooSmall);
    }
    let mut counts = [message.question_count(), 0, 0, 0];
    let original = [
        message.question_count(),
        message.answer_count(),
        message.authority_count(),
        message.additional_count() - u16::from(existing.is_some()),
    ];
    let mut stopped = false;
    for (section, records) in [
        (1, message.answers()),
        (2, message.authorities()),
        (3, message.additionals()),
    ] {
        for record in records {
            if record.rtype == Type::OPT {
                // shortcut: records following OPT are dropped to preserve compression offsets.
                stopped = true;
                break;
            }
            let next = record.rdata_offset + record.rdata.len();
            if next > budget {
                stopped = true;
                break;
            }
            end = next;
            counts[section] += 1;
        }
        if stopped {
            break;
        }
    }
    let truncated = counts != original;
    if end + opt_len > wire.capacity() {
        if protocol == Protocol::Udp {
            return Err(Error::ResponseBufferTooSmall);
        }
        wire.reserve((end + opt_len).saturating_sub(wire.len()));
    }
    wire.truncate(end);
    if truncated {
        wire[2] |= 0x02;
    }
    if let Some(opt) = response_opt {
        opt.encode(wire).map_err(Error::Build)?;
        counts[3] += 1;
    }
    // RFC 1035 §4.1.1: header counts describe the records in each response section.
    for (i, count) in counts.into_iter().enumerate() {
        wire[4 + 2 * i..6 + 2 * i].copy_from_slice(&count.to_be_bytes());
    }
    Ok(())
}
