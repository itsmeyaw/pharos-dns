use pharos_proto::{
    Message, MessageBuilder, Opt, Rcode, Section, TsigKey, TsigRecord, Type, normalized_udp_size,
};
use std::sync::Arc;

use crate::{Action, Error, Outcome, Protocol, admission::write_error};

/// Per-Query TSIG request; keys are shared with the Listener's configuration.
pub enum TsigSigning {
    Signed {
        key: Arc<TsigKey>,
        time: u64,
        fudge: u16,
        reserved: usize,
    },
    Error {
        key: Option<Arc<TsigKey>>,
        time: u64,
        code: u16,
        reserved: usize,
    },
}

/// Maximum Response size requested by the client for this protocol.
// RFC 4033 §9: Honor the requester's EDNS UDP payload size for DNSSEC responses.
pub fn response_limit(query: Message<'_>, protocol: Protocol) -> usize {
    // RFC 6891 §6.2.3: EDNS advertises a UDP payload size, with a 512-octet minimum.
    usize::from(normalized_udp_size(
        query.opt().map_or(512, |opt| opt.udp_payload_size()),
        // RFC 1035 §4.2.2: TCP response size is limited by the two-octet length prefix.
        protocol == Protocol::Tcp,
    ))
}

/// Finish a Plugin outcome, reporting Plugin and malformed Response errors.
pub fn finish_outcome(
    query: Message<'_>,
    protocol: Protocol,
    outcome: Outcome,
    response: &mut Vec<u8>,
    log: impl FnMut(Error),
) -> Action {
    finish_outcome_signed(query, protocol, outcome, response, None, log)
}

/// Finish the Response and append any requested TSIG as the last operation.
pub fn finish_outcome_signed(
    query: Message<'_>,
    protocol: Protocol,
    outcome: Outcome,
    response: &mut Vec<u8>,
    signing: Option<TsigSigning>,
    mut log: impl FnMut(Error),
) -> Action {
    match outcome {
        Outcome::Drop => return Action::Drop,
        Outcome::Stream(mut stream) => {
            if protocol == Protocol::Tcp {
                match signing {
                    // RFC 5936 §2.2.5: Include transaction-security records in AXFR responses.
                    Some(TsigSigning::Signed { key, fudge, .. }) => {
                        stream.signing = Some(crate::StreamSigning { key, fudge });
                    }
                    Some(TsigSigning::Error { .. }) => return Action::Drop,
                    None => {}
                }
                return Action::Stream(stream);
            }
            let qtype = query.questions().next().map(|q| q.qtype);
            if qtype == Some(Type::IXFR) {
                if let Err(error) = udp_ixfr(query, &mut stream, response) {
                    log(error);
                    write_error(query, response, Rcode::SERVFAIL);
                }
            } else {
                // RFC 5936 §4.2: AXFR is carried over TCP, not UDP.
                write_error(query, response, Rcode::REFUSED);
            }
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
        // RFC 1035 §4.1.1: Encode a processing error as RCODE 2 (SERVFAIL).
        Outcome::Error(error) => {
            log(error);
            write_error(query, response, Rcode::SERVFAIL);
        }
        Outcome::Response => {}
    }
    // RFC 8945 §5.3: the complete TSIG must fit within the advertised UDP size.
    let reserved = signing.as_ref().map_or(0, |request| match request {
        TsigSigning::Signed { reserved, .. } | TsigSigning::Error { reserved, .. } => *reserved,
    });
    let signed = signing.is_some();
    let before = signed
        .then(|| Message::parse(response).ok())
        .flatten()
        .map(|message| {
            message.answer_count() as usize
                + message.authority_count() as usize
                + message
                    .additionals()
                    .filter(|rr| rr.rtype != Type::OPT)
                    .count()
        });
    let result = response_limit(query, protocol)
        .checked_sub(reserved)
        .ok_or(Error::ResponseBufferTooSmall)
        .and_then(|limit| scrub(query, limit, protocol, response))
        .and_then(|()| {
            if !signed {
                return Ok(());
            }
            let message = Message::parse(response).map_err(|_| Error::InvalidQuery)?;
            let after = message.answer_count() as usize
                + message.authority_count() as usize
                + message
                    .additionals()
                    .filter(|rr| rr.rtype != Type::OPT)
                    .count();
            if before.is_some_and(|count| count > after) {
                // RFC 8945 §5.3: a TSIG-truncated Response contains only the Question and TSIG.
                let flags = (message.flags() | 0x0200) & !0x000f;
                let mut builder = MessageBuilder::new(
                    response,
                    response_limit(query, protocol) - reserved,
                    query.id(),
                    flags,
                )
                .map_err(Error::Build)?;
                for question in query.questions() {
                    if !builder
                        .question(question.name, question.qtype, question.qclass)
                        .map_err(Error::Build)?
                    {
                        return Err(Error::ResponseBufferTooSmall);
                    }
                }
                let _ = builder.finish();
            }
            Ok(())
        })
        .and_then(|()| match signing {
            Some(request) => append_tsig(query, protocol, response, request),
            None => Ok(()),
        });
    if let Err(error) = result {
        log(error);
        // RFC 8945 §5.3: never substitute an unsigned Response to a signed Query.
        if signed {
            return Action::Drop;
        }
        write_error(query, response, Rcode::SERVFAIL);
    }
    Action::Respond
}

fn udp_ixfr(
    query: Message<'_>,
    stream: &mut crate::Stream,
    response: &mut Vec<u8>,
) -> Result<(), Error> {
    // shortcut: one temporary Message allocation per UDP IXFR; reuse a transfer buffer when available.
    let mut first = Vec::new();
    if !stream.next(&mut first)? {
        return Err(Error::InvalidQuery);
    }
    let message = Message::parse(&first).map_err(|_| Error::InvalidQuery)?;
    let record = message
        .answers()
        .next()
        .filter(|record| record.rtype == Type::SOA)
        .ok_or(Error::InvalidQuery)?;
    let data = record.data().map_err(|_| Error::InvalidQuery)?;
    let question = query.questions().next().ok_or(Error::InvalidQuery)?;
    // RFC 1995 §2: UDP IXFR returns the current SOA when the full transfer does not fit.
    let mut builder = MessageBuilder::new(
        response,
        response_limit(query, Protocol::Udp),
        query.id(),
        message.flags(),
    )
    .map_err(Error::Build)?;
    builder
        .question(question.name, question.qtype, question.qclass)
        .map_err(Error::Build)?;
    builder
        .record_with(
            Section::Answer,
            record.name,
            Type::SOA,
            record.class,
            record.ttl,
            |writer| data.write(writer),
        )
        .map_err(Error::Build)?;
    let _ = builder.finish();
    Ok(())
}

// RFC 7766 §4: Without EDNS(0), truncate UDP responses above 512 octets and set TC.
fn scrub(
    query: Message<'_>,
    limit: usize,
    protocol: Protocol,
    wire: &mut Vec<u8>,
) -> Result<(), Error> {
    let message = Message::parse(wire).map_err(|_| Error::InvalidQuery)?;
    // RFC 6891 §7: Omit OPT when the request did not include an OPT record.
    if query.opt().is_none() && message.opt().is_none() && wire.len() <= limit {
        return Ok(());
    }
    let existing = message.opt();
    let existing_options = message
        .additionals()
        .find(|rr| rr.rtype == Type::OPT)
        .map(|rr| (rr.rdata_offset, rr.rdata.len()));
    let rcode = message.rcode();
    // RFC 6891 §6.1.1: an EDNS request requires an OPT record in the response.
    // RFC 7828 §3.3.1: UDP keepalive has no effect; only registered options are echoed.
    let response_opt = query
        .opt()
        .map(|opt| opt.response_registered(existing, rcode));
    let opt_len = response_opt.map_or(0, |opt| opt.wire_len());
    // RFC 6891 §7: a truncated EDNS response must retain the question and OPT record.
    let budget = limit
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
    // RFC 1035 §6.2: Truncate from the end to preserve earlier Answer and Authority records.
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
    let existing_flags = existing.map(Opt::flags);
    if end + opt_len > wire.capacity() {
        if protocol == Protocol::Udp {
            return Err(Error::ResponseBufferTooSmall);
        }
        wire.reserve((end + opt_len).saturating_sub(wire.len()));
    }
    if let (Some((offset, len)), Some(query_opt)) = (existing_options, query.opt()) {
        // RFC 6891 §6.1.2: preserve Response options while relocating the OPT record.
        wire.resize(wire.len().max(end + opt_len), 0);
        wire.copy_within(offset..offset + len, end + 11);
        wire.truncate(end + opt_len);
        wire[end..end + 3].copy_from_slice(&[0, 0, 41]);
        wire[end + 3..end + 5].copy_from_slice(&query_opt.udp_payload_size().to_be_bytes());
        // RFC 3225 §3: Copy the query's DO bit into the response.
        let ttl = (u32::from((rcode.0 >> 4) as u8) << 24)
            | u32::from(existing_flags.unwrap_or_default() & 0xff00)
            | if query_opt.dnssec_ok() { 0x8000 } else { 0 };
        wire[end + 5..end + 9].copy_from_slice(&ttl.to_be_bytes());
        wire[end + 9..end + 11].copy_from_slice(&(len as u16).to_be_bytes());
        counts[3] += 1;
    } else {
        wire.truncate(end);
        if let Some(opt) = query.opt() {
            opt.response_registered(None, rcode)
                .encode(wire)
                .map_err(Error::Build)?;
            counts[3] += 1;
        }
    }
    // RFC 5625 §4.4: Set TC on local truncation and preserve any upstream TC bit.
    if truncated {
        wire[2] |= 0x02;
    }
    // RFC 1035 §4.1.1: header counts describe the records in each response section.
    for (i, count) in counts.into_iter().enumerate() {
        wire[4 + 2 * i..6 + 2 * i].copy_from_slice(&count.to_be_bytes());
    }
    Ok(())
}

fn append_tsig(
    query: Message<'_>,
    protocol: Protocol,
    wire: &mut Vec<u8>,
    request: TsigSigning,
) -> Result<(), Error> {
    let record = TsigRecord::parse(query.as_wire()).map_err(|_| Error::InvalidQuery)?;
    let reserved = match &request {
        TsigSigning::Signed { reserved, .. } | TsigSigning::Error { reserved, .. } => *reserved,
    };
    if wire.capacity() < wire.len() + reserved {
        if protocol == Protocol::Udp {
            return Err(Error::ResponseBufferTooSmall);
        }
        wire.reserve(reserved);
    }
    match request {
        TsigSigning::Signed {
            key, time, fudge, ..
        } => {
            // RFC 8945 §4.3.1: the Response MAC includes the authenticated Query MAC.
            // RFC 8945 §5.2.2.1: Use the verified truncated Query MAC in the Response MAC.
            // RFC 8945 §5.3: The Response MAC covers the Query MAC, Message, and TSIG variables.
            key.sign(wire, time, fudge, Some(record.mac))
                .map_err(|_| Error::InvalidQuery)
        }
        TsigSigning::Error {
            key: Some(key),
            time,
            ..
        } => {
            key.sign_error_response(wire, query.as_wire(), time, 0)
                .map_err(|_| Error::InvalidQuery)?
                .ok_or(Error::InvalidQuery)?;
            Ok(())
        }
        TsigSigning::Error {
            key: None, code, ..
        } => {
            let algorithm_len = record
                .algorithm
                .labels()
                .map(|l| l.len() + 1)
                .sum::<usize>()
                + 1;
            // RFC 8945 §5.3.2: BADKEY and BADSIG carry an empty MAC.
            for label in record.owner.labels() {
                wire.push(label.len() as u8);
                wire.extend_from_slice(label);
            }
            wire.push(0);
            wire.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0]);
            wire.extend_from_slice(&((algorithm_len + 16) as u16).to_be_bytes());
            for label in record.algorithm.labels() {
                wire.push(label.len() as u8);
                wire.extend_from_slice(label);
            }
            wire.push(0);
            wire.extend_from_slice(&[0; 6]);
            wire.extend_from_slice(&record.fudge.to_be_bytes());
            wire.extend_from_slice(&[0; 2]);
            wire.extend_from_slice(&record.original_id.to_be_bytes());
            wire.extend_from_slice(&code.to_be_bytes());
            wire.extend_from_slice(&[0; 2]);
            let count = u16::from_be_bytes([wire[10], wire[11]]) + 1;
            wire[10..12].copy_from_slice(&count.to_be_bytes());
            Ok(())
        }
    }
}
