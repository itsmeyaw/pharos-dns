//! DNS64 address synthesis.

pub(crate) mod setup;

use std::{
    net::{Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use pharos_corefile::{Cursor, Error};
use pharos_proto::{
    Class, Message, MessageBuilder, Opcode, ResponseType, Section, Type, typify_response,
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
        let mut result = Self {
            prefix: "64:ff9b::".parse::<Ipv6Addr>().unwrap().octets(),
            prefix_len: 96,
            translate_all: false,
            allow_ipv4: false,
            metrics: Vec::new(),
        };
        while cursor.next() {
            let args = cursor.remaining_args();
            if let [prefix] = args.as_slice() {
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
    let (ip, len) = value
        .split_once('/')
        .ok_or_else(|| cursor.error("invalid dns64 prefix"))?;
    let ip: Ipv6Addr = ip
        .parse()
        .map_err(|_| cursor.error("invalid dns64 prefix"))?;
    let len: u8 = len
        .parse()
        .map_err(|_| cursor.error("invalid dns64 prefix"))?;
    // RFC 6052 §2.2: only these six prefix lengths are defined.
    if !matches!(len, 32 | 40 | 48 | 56 | 64 | 96) {
        return Err(cursor.error("invalid dns64 prefix length"));
    }
    let mut bytes = ip.octets();
    bytes[usize::from(len / 8)..].fill(0);
    Ok((bytes, len))
}

impl Plugin for Dns64 {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let query = cx.query;
        let Some(question) = query.questions().next() else {
            return next.run(cx).await;
        };
        // RFC 6147 §5.1: DNS64 applies to IN AAAA Queries from IPv6 clients.
        if question.qtype != Type::AAAA
            || question.qclass != Class::IN
            || (!self.allow_ipv4
                && (cx.client.is_ipv4() || cx.client.ip().to_canonical().is_ipv4()))
        {
            return next.run(cx).await;
        }
        let outcome = next.run(cx).await;
        if outcome != Outcome::Response {
            return outcome;
        }
        let original = match Message::parse(cx.response) {
            Ok(message) => message,
            Err(_) => return Outcome::Error(ServerError::InvalidQuery),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| {
                i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
            });
        if typify_response(Some(&original), now) == ResponseType::NxDomain
            || (!self.translate_all && original.answers().any(|rr| rr.rtype == Type::AAAA))
        {
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
        let lookup = match cx.self_lookup(&name, Type::A).await {
            Ok(wire) => wire,
            Err(error) => return Outcome::Error(error),
        };
        let response = match Message::parse(&lookup) {
            Ok(message) => message,
            Err(_) => return Outcome::Error(ServerError::InvalidQuery),
        };
        let result = (|| {
            let max = cx.max_response_size.max(512);
            if cx.response.capacity() < max {
                if cx.protocol == Protocol::Tcp {
                    cx.response.reserve(max.saturating_sub(cx.response.len()));
                } else {
                    return Err(ServerError::ResponseBufferTooSmall);
                }
            }
            // RFC 1035 §4.1.1: construct a Response for the original Question.
            let flags = 0x8000
                | (cx.query.flags() & 0x7800)
                | if cx.query.opcode() == Opcode::QUERY {
                    cx.query.flags() & 0x0110
                } else {
                    0
                }
                | (response.flags() & 0x020f);
            let mut builder = MessageBuilder::new(cx.response, max, cx.query.id(), flags)
                .map_err(ServerError::Build)?;
            builder
                .question(question.name, question.qtype, question.qclass)
                .map_err(ServerError::Build)?;
            for (section, records) in [
                (Section::Answer, response.answers()),
                (Section::Authority, response.authorities()),
                (Section::Additional, response.additionals()),
            ] {
                for rr in records {
                    if section == Section::Answer && rr.rtype == Type::A {
                        let ipv4: [u8; 4] =
                            rr.rdata.try_into().map_err(|_| ServerError::InvalidQuery)?;
                        let mut ipv6 = self.prefix;
                        let mut index = usize::from(self.prefix_len / 8);
                        // RFC 6052 §2.2: byte 8 is reserved unless the prefix is /96.
                        for byte in ipv4 {
                            if index == 8 {
                                index += 1;
                            }
                            ipv6[index] = byte;
                            index += 1;
                        }
                        builder
                            .record(
                                section,
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
                            .record_with(section, rr.name, rr.rtype, rr.class, rr.ttl, |writer| {
                                data.write(writer)
                            })
                            .map_err(ServerError::Build)?;
                    }
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
