use pharos_proto::{EdnsOptions, Message, Opt, Rcode, Type, normalized_udp_size};

use crate::{Action, Error, Outcome, Protocol, admission::write_error};

/// Maximum Response size requested by the client for this protocol.
pub fn response_limit(query: Message<'_>, protocol: Protocol) -> usize {
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
        // shortcut: Zone Transfer streams need a streaming Listener (#35).
        Outcome::Stream(_) => return Action::Drop,
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
    if let Err(error) = scrub(query, response_limit(query, protocol), response) {
        log(error);
        write_error(query, response, Rcode::SERVFAIL);
    }
    Action::Respond
}

fn scrub(query: Message<'_>, limit: usize, wire: &mut Vec<u8>) -> Result<(), Error> {
    let message = Message::parse(wire).map_err(|_| Error::InvalidQuery)?;
    if query.opt().is_none() && wire.len() <= limit {
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
    let response_opt = query.opt().map(|opt| opt.response(existing, &[], rcode));
    let opt_len = response_opt.map_or_else(
        || existing.map_or(0, |opt| 11 + opt.options().as_bytes().len()),
        |opt| opt.wire_len(),
    );
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
        return Err(Error::ResponseBufferTooSmall);
    }
    wire.truncate(end);
    if truncated {
        wire[2] |= 0x02;
    }
    if let Some(opt) = response_opt {
        opt.encode(wire).map_err(Error::Build)?;
        counts[3] += 1;
    } else if let Some(opt) = existing {
        opt.encode(wire).map_err(Error::Build)?;
        counts[3] += 1;
    }
    for (i, count) in counts.into_iter().enumerate() {
        wire[4 + 2 * i..6 + 2 * i].copy_from_slice(&count.to_be_bytes());
    }
    Ok(())
}
