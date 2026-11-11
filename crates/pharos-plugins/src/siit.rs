//! SIIT address synthesis.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
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
pub struct Siit {
    prefix: [u8; 16],
    prefix_len: u8,
    eam: Vec<(Ipv6Addr, Ipv4Addr)>,
    metrics: Vec<(SocketAddr, Arc<AtomicU64>)>,
}

impl Siit {
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        let mut result = Self {
            prefix: "64:ff9b::".parse::<Ipv6Addr>().unwrap().octets(),
            prefix_len: 96,
            eam: Vec::new(),
            metrics: Vec::new(),
        };
        while cursor.next() {
            if !cursor.remaining_args().is_empty() {
                return Err(cursor.arg_err());
            }
            while cursor.next_block() {
                match cursor.val() {
                    "ipv6_prefix" => {
                        let args = cursor.remaining_args();
                        let value = args.first().ok_or_else(|| cursor.arg_err())?;
                        let (ip, len) = value
                            .split_once('/')
                            .ok_or_else(|| cursor.error("invalid prefix"))?;
                        let ip: Ipv6Addr =
                            ip.parse().map_err(|_| cursor.error("invalid prefix"))?;
                        let len: u8 = len.parse().map_err(|_| cursor.error("invalid prefix"))?;
                        // RFC 6052 §2.2: only six prefix lengths are defined and the u octet is zero.
                        if !matches!(len, 32 | 40 | 48 | 56 | 64 | 96) {
                            return Err(cursor.error("invalid prefix length"));
                        }
                        let mut bytes = ip.octets();
                        bytes[usize::from(len / 8)..].fill(0);
                        if bytes[8] != 0 {
                            return Err(cursor.error("invalid reserved octet"));
                        }
                        result.prefix = bytes;
                        result.prefix_len = len;
                    }
                    "eam" => {
                        let args = cursor.remaining_args();
                        let [v4, v6] = args.as_slice() else {
                            return Err(cursor.arg_err());
                        };
                        let v4 = v4
                            .parse()
                            .map_err(|_| cursor.error("invalid IPv4 address"))?;
                        let v6: Ipv6Addr = v6
                            .parse()
                            .map_err(|_| cursor.error("invalid IPv6 address"))?;
                        if v6.to_ipv4_mapped().is_some() {
                            return Err(cursor.error("invalid IPv6 address"));
                        }
                        result.eam.retain(|(addr, _)| *addr != v6);
                        result.eam.push((v6, v4));
                    }
                    _ => return Err(cursor.error("unknown siit property")),
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
            self.metrics.push((address, registry.siit(&server)));
        }
    }

    fn translate(&self, bytes: &[u8]) -> Option<[u8; 4]> {
        let addr: [u8; 16] = bytes.try_into().ok()?;
        let ip = Ipv6Addr::from(addr);
        if ip.to_ipv4_mapped().is_some() {
            return None;
        }
        // RFC 7757 §3.3.2: an explicit address mapping takes precedence.
        if let Some((_, v4)) = self.eam.iter().find(|(v6, _)| *v6 == ip) {
            return Some(v4.octets());
        }
        let prefix_len = usize::from(self.prefix_len / 8);
        // RFC 6052 §2.2: the reserved u octet must be zero.
        if addr[..prefix_len] != self.prefix[..prefix_len] || addr[8] != 0 {
            return None;
        }
        let mut v4 = [0; 4];
        let mut index = prefix_len;
        for byte in &mut v4 {
            if index == 8 {
                index += 1;
            }
            *byte = addr[index];
            index += 1;
        }
        Some(v4)
    }
}

impl Plugin for Siit {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let query = cx.query;
        let Some(question) = query.questions().next() else {
            return next.run(cx).await;
        };
        // RFC 6147 §5.1: only IN A Queries are eligible for synthesis.
        if cx.siit_lookup_active() || question.qtype != Type::A || question.qclass != Class::IN {
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
        if original.tc()
            || typify_response(Some(&original), now) == ResponseType::NxDomain
            || original.answers().any(|rr| rr.rtype == Type::A)
        {
            return outcome;
        }
        // RFC 6147 §5.1.7: use the negative SOA TTL or 600 seconds as a cap.
        let soa_ttl = original
            .authorities()
            .filter(|rr| rr.rtype == Type::SOA)
            .last()
            .map_or(600, |rr| rr.ttl);
        let name = question.name.to_name();
        // shortcut: Self Lookup allocates; remove when issue #86 makes it allocation-free.
        let wire = match cx.siit_lookup(&name, Type::AAAA).await {
            Ok(wire) => wire,
            Err(error) => return Outcome::Error(error),
        };
        let response = match Message::parse(&wire) {
            Ok(message) => message,
            Err(_) => return Outcome::Error(ServerError::InvalidQuery),
        };
        let success = response.rcode().0 == 0;
        if success
            && !response
                .answers()
                .any(|rr| rr.rtype == Type::AAAA && self.translate(rr.rdata).is_some())
        {
            return outcome;
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
            // RFC 1035 §4.1.1: retain the client's original Question and transaction ID.
            let flags = 0x8000
                | (cx.query.flags() & 0x7800)
                | if cx.query.opcode() == Opcode::QUERY {
                    cx.query.flags() & 0x0110
                } else {
                    0
                }
                | (response.flags() & 0x068f);
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
                    if success && section == Section::Answer && rr.rtype == Type::AAAA {
                        if let Some(v4) = self.translate(rr.rdata) {
                            builder
                                .record(
                                    section,
                                    rr.name,
                                    Type::A,
                                    rr.class,
                                    rr.ttl.min(soa_ttl),
                                    &v4,
                                )
                                .map_err(ServerError::Build)?;
                        }
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
                if success
                    && let Some((_, counter)) = self
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
