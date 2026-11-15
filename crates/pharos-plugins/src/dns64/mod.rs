//! DNS64 address synthesis.

pub(crate) mod setup;

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use pharos_corefile::{Cursor, Error};
use pharos_proto::{
    Class, Message, MessageBuilder, Opcode, Rcode, Rdata, Section, Type,
};
use pharos_server::{Context, Error as ServerError, Next, Outcome, Plugin, Protocol};

#[derive(Debug)]
pub struct Dns64 {
    prefix: [u8; 16],
    prefix_len: u8,
    translate_all: bool,
    allow_ipv4: bool,
    metrics: Vec<(SocketAddr, Arc<AtomicU64>)>,
}

impl Dns64 {
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        // RFC 6147 §5.2: use the Well-Known Prefix when no Pref64 is configured.
        let mut result = Self {
            // RFC 6052 §2.1: the default prefix is the well-known prefix 64:ff9b::/96.
            prefix: crate::rfc6052::WELL_KNOWN_PREFIX,
            prefix_len: 96,
            translate_all: false,
            allow_ipv4: false,
            metrics: Vec::new(),
        };
        while cursor.next() {
            let args = cursor.remaining_args();
            if let [prefix] = args.as_slice() {
                // RFC 6147 §5.2: use the configured Pref64 instead of the Well-Known Prefix.
                (result.prefix, result.prefix_len) = parse_prefix(cursor, prefix)?;
                continue;
            }
            if !args.is_empty() {
                return Err(cursor.arg_err());
            }
            while cursor.next_block() {
                match cursor.val() {
                    "prefix" => {
                        let args = cursor.remaining_args();
                        let Some(prefix) = args.first() else {
                            return Err(cursor.arg_err());
                        };
                        (result.prefix, result.prefix_len) = parse_prefix(cursor, prefix)?;
                    }
                    "translate_all" => result.translate_all = true,
                    "allow_ipv4" => result.allow_ipv4 = true,
                    _ => return Err(cursor.error("unknown dns64 property")),
                }
            }
        }
        Ok(result)
    }

    pub(crate) fn set_metrics(
        &mut self,
        registry: &pharos_server::metrics::Registry,
        listeners: &[pharos_server::ListenerKey],
    ) {
        for listener in listeners {
            let address = listener.address;
            let server = if address.ip().is_unspecified() {
                format!("dns://:{}", address.port())
            } else {
                format!("dns://{address}")
            };
            self.metrics.push((address, registry.dns64(&server)));
        }
    }
}

fn parse_prefix(cursor: &Cursor<'_>, value: &str) -> Result<([u8; 16], u8), Error> {
    crate::rfc6052::parse(value).map_err(|error| {
        cursor.error(match error {
            crate::rfc6052::PrefixError::Format => "invalid dns64 prefix",
            crate::rfc6052::PrefixError::Length => "invalid dns64 prefix length",
            crate::rfc6052::PrefixError::WellKnownLength => {
                "invalid dns64 well-known prefix length"
            }
            crate::rfc6052::PrefixError::ReservedOctet => "invalid dns64 reserved octet",
        })
    })
}

// RFC 6147 §5.1.4: IPv4-mapped AAAA records do not suppress DNS64 synthesis.
fn has_usable_aaaa(message: &Message<'_>) -> bool {
    message
        .answers()
        .any(|rr| rr.rtype == Type::AAAA && !is_excluded_aaaa(rr.rdata))
}

fn has_excluded_aaaa(message: &Message<'_>) -> bool {
    message
        .answers()
        .any(|rr| rr.rtype == Type::AAAA && is_excluded_aaaa(rr.rdata))
}

// RFC 6147 §5.1.4: The default exclusion set is IPv4-mapped IPv6 addresses.
fn is_excluded_aaaa(rdata: &[u8]) -> bool {
    let Ok(bytes) = <[u8; 16]>::try_from(rdata) else {
        return false;
    };
    Ipv6Addr::from(bytes).to_ipv4_mapped().is_some()
}

fn filter_excluded_aaaa(
    cx: &mut Context<'_, '_>,
    original_wire: &[u8],
) -> Result<(), ServerError> {
    let original = Message::parse(original_wire).map_err(|_| ServerError::InvalidQuery)?;
    let max = cx.max_response_size.max(512);
    if cx.response.capacity() < max {
        if cx.protocol == Protocol::Tcp {
            cx.response.reserve(max.saturating_sub(cx.response.len()));
        } else {
            return Err(ServerError::ResponseBufferTooSmall);
        }
    }
    let mut builder = MessageBuilder::new(cx.response, max, original.id(), original.flags())
        .map_err(ServerError::Build)?;
    for question in original.questions() {
        builder
            .question(question.name, question.qtype, question.qclass)
            .map_err(ServerError::Build)?;
    }
    for (section, records) in [
        (Section::Answer, original.answers()),
        (Section::Authority, original.authorities()),
        (Section::Additional, original.additionals()),
    ] {
        for rr in records {
            // RFC 6147 §5.1.4: Do not return AAAA records from the excluded IPv4-mapped range.
            if section == Section::Answer && rr.rtype == Type::AAAA && is_excluded_aaaa(rr.rdata) {
                continue;
            }
            let data = rr.data().map_err(|_| ServerError::InvalidQuery)?;
            builder
                .record_with(section, rr.name, rr.rtype, rr.class, rr.ttl, |writer| {
                    data.write(writer)
                })
                .map_err(ServerError::Build)?;
        }
    }
    let _ = builder.finish();
    Ok(())
}

impl Plugin for Dns64 {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let query = cx.query;
        let Some(question) = query.questions().next() else {
            return next.run(cx).await;
        };
        // RFC 6147 §5.1: DNS64 applies to IN AAAA Queries from IPv6 clients.
        // RFC 6147 §5.3.1: process PTR queries for nonmatching prefixes as normal DNS queries.
        if question.qtype != Type::AAAA
            || question.qclass != Class::IN
            || (!self.allow_ipv4
                && (cx.client.is_ipv4() || cx.client.ip().to_canonical().is_ipv4()))
        {
            return next.run(cx).await;
        }
        // RFC 6147 §5.1: retrieve existing non-synthetic AAAA data before synthesis.
        let outcome = next.run(cx).await;
        if outcome != Outcome::Response {
            return outcome;
        }
        let original = match Message::parse(cx.response) {
            Ok(message) => message,
            Err(_) => return Outcome::Error(ServerError::InvalidQuery),
        };
        let original_flags = original.flags();
        // RFC 6147 §5.1.1: return existing AAAA data without synthesis by default.
        // RFC 6147 §5.1.2: NXDOMAIN remains a name error even when signatures are expired.
        if original.rcode() == Rcode::NXDOMAIN {
            return outcome;
        }
        if !self.translate_all && has_usable_aaaa(&original) {
            if has_excluded_aaaa(&original) {
                // RFC 1035 §4.1.4: Snapshot this rare path before re-encoding compression pointers.
                let original_wire = cx.response.clone();
                return match filter_excluded_aaaa(cx, &original_wire) {
                    Ok(()) => outcome,
                    Err(error) => Outcome::Error(error),
                };
            }
            return outcome;
        }
        // RFC 6147 §5.1.7: cap synthesized TTL at the negative SOA TTL or 600 seconds.
        let soa_ttl = original
            .authorities()
            .filter(|rr| rr.rtype == Type::SOA)
            .last()
            .map_or(600, |rr| rr.ttl);
        let name = question.name.to_name();
        // shortcut: Self Lookup allocates; remove when issue #86 makes it allocation-free.
        // RFC 6147 §5.1.6: Retrieve A records when the AAAA lookup provides no usable AAAA answer.
        let mut lookup = match cx.self_lookup(&name, Type::A).await {
            Ok(wire) => wire,
            Err(error) => return Outcome::Error(error),
        };
        let mut response = match Message::parse(&lookup) {
            Ok(message) => message,
            Err(_) => return Outcome::Error(ServerError::InvalidQuery),
        };
        // RFC 6147 §5.4: if the successful A lookup is empty, return the original AAAA response.
        if response.rcode() == pharos_proto::Rcode::NOERROR && response.answer_count() == 0 {
            if has_excluded_aaaa(&original) {
                // RFC 1035 §4.1.4: Snapshot this rare path before re-encoding compression pointers.
                let original_wire = cx.response.clone();
                return match filter_excluded_aaaa(cx, &original_wire) {
                    Ok(()) => outcome,
                    Err(error) => Outcome::Error(error),
                };
            }
            return outcome;
        }
        let mut lookup_chain = Vec::new();
        let mut cname_hops = 0;
        loop {
            let target = if response.rcode() == Rcode::NOERROR
                && !response.answers().any(|rr| rr.rtype == Type::A)
            {
                response.answers().find_map(|rr| match rr.data().ok()? {
                    Rdata::Cname(target) => Some(target.to_name()),
                    _ => None,
                })
            } else {
                None
            };
            let Some(target) = target else { break };
            // RFC 1034 §3.6.2: Bound alias chasing so cycles terminate with an error.
            // shortcut: allow eight A-target lookups; raise only with cycle-safe chain tracking.
            if cname_hops >= 8 {
                return Outcome::Error(ServerError::SelfLookupDepth);
            }
            cname_hops += 1;
            // RFC 6147 §5.1.5: Continue A lookup at each CNAME target until terminal data.
            lookup_chain.push(lookup);
            lookup = match cx.self_lookup(&target, Type::A).await {
                Ok(wire) => wire,
                Err(error) => return Outcome::Error(error),
            };
            response = match Message::parse(&lookup) {
                Ok(message) => message,
                Err(_) => return Outcome::Error(ServerError::InvalidQuery),
            };
        }
        let result = (|| {
            let max = cx.max_response_size.max(512);
            if cx.response.capacity() < max {
                if cx.protocol == Protocol::Tcp {
                    cx.response.reserve(max.saturating_sub(cx.response.len()));
                } else {
                    return Err(ServerError::ResponseBufferTooSmall);
                }
            }
            // RFC 6147 §5.4: Assemble the response for the original question.
            // RFC 1035 §4.1.1: construct a Response for the original Question.
            let flags = 0x8000
                | (cx.query.flags() & 0x7800)
                | if cx.query.opcode() == Opcode::QUERY {
                    cx.query.flags() & 0x0110
                } else {
                    0
                }
                // RFC 6147 §5.4: role flags come from the original AAAA response.
                // RFC 6147 §5.4 and RFC 1035 §4.1.1: retain final RCODE and TC on truncation.
                | (original_flags & 0x0480)
                | (response.flags() & 0x020f);
            let mut builder = MessageBuilder::new(cx.response, max, cx.query.id(), flags)
                .map_err(ServerError::Build)?;
            builder
                .question(question.name, question.qtype, question.qclass)
                .map_err(ServerError::Build)?;
            // RFC 6147 §5.1.5: Preserve CNAME or DNAME chains with synthesized AAAA records.
            for wire in lookup_chain.iter().chain(std::iter::once(&lookup)) {
                let message = Message::parse(wire).map_err(|_| ServerError::InvalidQuery)?;
                for rr in message.answers() {
                    // RFC 6147 §5.3.2: Synthesize AAAA records from Answer-section A records.
                    if rr.rtype == Type::A {
                        let ipv4: [u8; 4] =
                            rr.rdata.try_into().map_err(|_| ServerError::InvalidQuery)?;
                        // RFC 6052 §3.1: Do not use the Well-Known Prefix for non-global IPv4.
                        if self.prefix_len == 96
                            && self.prefix == crate::rfc6052::WELL_KNOWN_PREFIX
                            && !crate::rfc6052::is_global_ipv4(Ipv4Addr::from(ipv4))
                        {
                            continue;
                        }
                        // RFC 6147 §5.2: Embed IPv4 in the prefix, skipping byte 8.
                        let mut ipv6 = self.prefix;
                        let mut index = usize::from(self.prefix_len / 8);
                        // RFC 6052 §2.2: byte 8 is reserved unless the prefix is /96.
                        // RFC 6147 §5.2: Use the RFC 6052 synthesis algorithm.
                        for byte in ipv4 {
                            if index == 8 {
                                index += 1;
                            }
                            ipv6[index] = byte;
                            index += 1;
                        }
                        builder
                            // RFC 6147 §5.1.7: Preserve NAME and CLASS and encode AAAA RDATA.
                            .record(
                                Section::Answer,
                                rr.name,
                                Type::AAAA,
                                rr.class,
                                rr.ttl.min(soa_ttl),
                                &ipv6,
                            )
                            .map_err(ServerError::Build)?;
                    } else {
                        let data = rr.data().map_err(|_| ServerError::InvalidQuery)?;
                        builder
                            .record_with(
                                Section::Answer,
                                rr.name,
                                rr.rtype,
                                rr.class,
                                rr.ttl,
                                |writer| {
                                data.write(writer)
                                },
                            )
                            .map_err(ServerError::Build)?;
                    }
                }
            }
            for (section, records) in [
                (Section::Authority, response.authorities()),
                (Section::Additional, response.additionals()),
            ] {
                for rr in records {
                    // RFC 9460 §4.2.1: DNS64 leaves SvcParam IP hints unchanged.
                    let data = rr.data().map_err(|_| ServerError::InvalidQuery)?;
                    builder
                        .record_with(section, rr.name, rr.rtype, rr.class, rr.ttl, |writer| {
                            data.write(writer)
                        })
                        .map_err(ServerError::Build)?;
                }
            }
            let _ = builder.finish();
            Ok(())
        })();
        match result {
            Ok(()) => {
                if let Some((_, counter)) = self
                    .metrics
                    .iter()
                    .find(|(address, _)| *address == cx.local)
                {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                Outcome::Response
            }
            Err(error) => Outcome::Error(error),
        }
    }
}
