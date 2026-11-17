use pharos_proto::{
    Message, MessageBuilder, NameRef, Opt, Rcode, Section, TsigKey, TsigRecord, Type,
};
use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};

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

/// Maximum Response size allowed for this Query and protocol.
// RFC 4033 §9: Honor the requester's EDNS UDP payload size for DNSSEC responses.
pub fn response_limit(query: Message<'_>, protocol: Protocol) -> usize {
    if protocol == Protocol::Tcp {
        // RFC 1035 §4.2.2: TCP response size is limited by the two-octet length prefix.
        usize::from(u16::MAX)
    } else {
        // RFC 6891 §§6.2.3–6.2.5: cap UDP Responses at requester size and responder capacity.
        usize::from(query.opt().map_or(512, Opt::response_udp_payload_size))
    }
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
            // RFC 2136 §3.1.1: NOTAUTH reports an UPDATE outside server authority.
            if !matches!(
                code,
                Rcode::SERVFAIL | Rcode::REFUSED | Rcode::FORMERR | Rcode::NOTIMP | Rcode::NOTAUTH
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
    let question_end = end;
    let mut counts = [message.question_count(), 0, 0, 0];
    let original = [
        message.question_count(),
        message.answer_count(),
        message.authority_count(),
        message.additional_count() - u16::from(existing.is_some()),
    ];
    let mut stopped = false;
    let mut required_truncated = false;
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
                required_truncated = section != 3;
                break;
            }
            end = next;
            counts[section] += 1;
        }
        if stopped {
            break;
        }
    }
    if required_truncated {
        // RFC 2181 §9: Keep earlier complete RRsets and drop any group split by the cutoff.
        let (safe_end, answer_count, authority_count) =
            required_section_end(message, question_end, end);
        end = safe_end;
        counts[1] = answer_count;
        counts[2] = authority_count;
        counts[3] = 0;
    }
    // RFC 2181 §9 and RFC 4035 §3.1.1: optional Additional omissions alone do not set TC.
    let truncated = counts[1..3] != original[1..3];
    // RFC 7871 §7.2.2: Select ECS according to the Query before discarding upstream bytes.
    // RFC 1035 §4.1.3 and RFC 6891 §6.1.2: Encode RDLENGTH from the selected RDATA.
    // shortcut: allocate an OPT buffer per EDNS Response; reuse scratch storage when available.
    let mut encoded_opt = Vec::with_capacity(opt_len);
    if let Some(opt) = response_opt {
        opt.encode(&mut encoded_opt).map_err(Error::Build)?;
        counts[3] += 1;
    }
    if end + opt_len > wire.capacity() {
        if protocol == Protocol::Udp {
            return Err(Error::ResponseBufferTooSmall);
        }
        wire.reserve((end + opt_len).saturating_sub(wire.len()));
    }
    wire.truncate(end);
    wire.extend_from_slice(&encoded_opt);
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

// RFC 2181 §9: move truncation before every required RRset that crosses the size limit.
fn required_section_end(
    message: Message<'_>,
    question_end: usize,
    end: usize,
) -> (usize, u16, u16) {
    let end = contiguous_rrset_end(message, question_end, end)
        .unwrap_or_else(|| spanning_rrset_end(message, question_end, end));
    let answer_count = message
        .answers()
        .take_while(|record| record.rdata_offset + record.rdata.len() <= end)
        .count() as u16;
    let authority_count = message
        .authorities()
        .take_while(|record| record.rdata_offset + record.rdata.len() <= end)
        .count() as u16;
    (end, answer_count, authority_count)
}

fn rrset_key<'a>(record: &pharos_proto::Record<'a>) -> RrsetKey<'a> {
    RrsetKey {
        name: record.name,
        rtype: record.rtype,
        class: record.class,
    }
}

// RFC 2181 §9: Contiguous RRsets cannot overlap; only a key seen on both sides of the cutoff can
// widen a span, and that case returns None for the exact analysis. Allocation-free.
fn contiguous_rrset_end(message: Message<'_>, question_end: usize, cut: usize) -> Option<usize> {
    const MAX_LEFT_RUNS: usize = 64;
    let mut left = [0u64; MAX_LEFT_RUNS];
    let mut left_runs = 0;
    let mut end = cut;
    let mut run: Option<(RrsetKey<'_>, usize, usize)> = None;
    let mut start = question_end;
    let close = |run: Option<(RrsetKey<'_>, usize, usize)>, end: &mut usize| {
        if let Some((_, run_start, run_end)) = run
            && run_start < cut
            && cut < run_end
        {
            *end = run_start;
        }
    };
    for record in message.answers().chain(message.authorities()) {
        let key = rrset_key(&record);
        let record_end = record.rdata_offset + record.rdata.len();
        match run.as_mut() {
            Some((run_key, _, run_end)) if *run_key == key => *run_end = record_end,
            _ => {
                close(run.take(), &mut end);
                let fingerprint = key.fingerprint();
                if start < cut {
                    if left_runs == MAX_LEFT_RUNS || left[..left_runs].contains(&fingerprint) {
                        return None;
                    }
                    left[left_runs] = fingerprint;
                    left_runs += 1;
                } else if left[..left_runs].contains(&fingerprint) {
                    return None;
                }
                run = Some((key, start, record_end));
            }
        }
        start = record_end;
    }
    close(run.take(), &mut end);
    Some(end)
}

// RFC 2181 §9: Interleaved RRsets span other records, so merge overlapping spans.
fn spanning_rrset_end(message: Message<'_>, question_end: usize, mut end: usize) -> usize {
    let mut rrsets = std::collections::HashMap::new();
    let mut start = question_end;
    for record in message.answers().chain(message.authorities()) {
        let record_end = record.rdata_offset + record.rdata.len();
        rrsets
            .entry(rrset_key(&record))
            .and_modify(|range: &mut (usize, usize)| range.1 = record_end)
            .or_insert((start, record_end));
        start = record_end;
    }
    let mut ranges = rrsets.into_values().collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|(start, _)| *start);
    let mut component = None;
    let mut component_end = 0;
    for (start, range_end) in ranges {
        if start < component_end {
            component_end = component_end.max(range_end);
        } else {
            if let Some(first) = component.filter(|first| *first < end && end < component_end) {
                end = first;
                break;
            }
            component = Some(start);
            component_end = range_end;
        }
    }
    if let Some(first) = component.filter(|first| *first < end && end < component_end) {
        end = first;
    }
    end
}

#[derive(Clone, Copy)]
struct RrsetKey<'a> {
    name: NameRef<'a>,
    rtype: Type,
    class: pharos_proto::Class,
}

impl PartialEq for RrsetKey<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.rtype == other.rtype && self.class == other.class
    }
}

impl Eq for RrsetKey<'_> {}

impl RrsetKey<'_> {
    // RFC 4343 §3: Fold ASCII case so equal owner names share a fingerprint (FNV-1a over label bytes).
    fn fingerprint(&self) -> u64 {
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut hash =
            0xcbf2_9ce4_8422_2325 ^ (u64::from(self.rtype.0) << 16 | u64::from(self.class.0));
        for label in self.name.labels() {
            hash = (hash ^ label.len() as u64).wrapping_mul(PRIME);
            for byte in label {
                hash = (hash ^ u64::from(byte.to_ascii_lowercase())).wrapping_mul(PRIME);
            }
        }
        hash
    }
}

impl Hash for RrsetKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.fingerprint());
    }
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
