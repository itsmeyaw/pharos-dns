//! Localhost and locally served reverse Domains.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use pharos_corefile::{Cursor, Error as CorefileError};
use pharos_proto::{Class, MessageBuilder, NameRef, Opcode, Section, Type};
use pharos_server::{Context, Error, Next, Outcome, Plugin, Protocol, metrics::Registry};

const TTL: u32 = 604_800;
const LOCALHOST: &[u8] = b"\x09localhost\0";
// RFC 1035 §3.3.13: SOA RDATA contains MNAME, RNAME and five 32-bit values.
const SOA: &[u8] =
    b"\x09localhost\0\x04root\x09localhost\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\x09\x3a\x80";

#[derive(Debug)]
pub struct Local {
    prefix: bool,
    counter: Option<Arc<AtomicU64>>,
}

impl Local {
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, CorefileError> {
        cursor.next();
        if !cursor.remaining_args().is_empty() {
            return Err(cursor.arg_err());
        }
        let mut prefix = true;
        while cursor.next_block() {
            if cursor.val() != "localhost_prefix" {
                return Err(cursor.error("unknown local property"));
            }
            let args = cursor.remaining_args();
            prefix = match args.as_slice() {
                [value] if value == "on" => true,
                [value] if value == "off" => false,
                _ => return Err(cursor.arg_err()),
            };
        }
        Ok(Self {
            prefix,
            counter: None,
        })
    }

    pub(crate) fn set_metrics(&mut self, registry: &Registry) {
        self.counter = Some(registry.local());
    }
}

impl Plugin for Local {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        let mut labels = [&[][..]; 127];
        let mut count = 0;
        for label in question.name.labels() {
            labels[count] = label;
            count += 1;
        }
        // RFC 4343 §2: compare DNS labels without ASCII case sensitivity.
        let eq = |i: usize, value: &[u8]| labels[i].eq_ignore_ascii_case(value);
        // RFC 6761 §6.3: localhost and its subdomains resolve to loopback.
        let special =
            count > 1 && (eq(count - 1, b"localhost") || (self.prefix && eq(0, b"localhost")));
        let zone_start = if count > 0 && eq(count - 1, b"localhost") {
            Some(count - 1)
        } else if count >= 3
            && eq(count - 2, b"in-addr")
            && eq(count - 1, b"arpa")
            && [b"0".as_slice(), b"127", b"255"]
                .iter()
                .any(|z| eq(count - 3, z))
        {
            Some(count - 3)
        } else {
            None
        };
        if !special && zone_start.is_none() {
            return next.run(cx).await;
        }
        if special {
            if pharos_server::logging::debug_enabled() {
                pharos_server::logging::log_debug(
                    "local",
                    format_args!(
                        "Intercepting localhost query for \"{}\" {}, from {}",
                        question.name,
                        question.qtype,
                        cx.client.ip()
                    ),
                );
            }
            if let Some(counter) = &self.counter {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        let apex = zone_start == Some(0);
        let localhost_apex = apex && eq(0, b"localhost");
        let reverse_ptr = count == 6
            && eq(0, b"1")
            && eq(1, b"0")
            && eq(2, b"0")
            && eq(3, b"127")
            && eq(4, b"in-addr")
            && eq(5, b"arpa");
        // RFC 1035 §4.1.2: select records matching the Question type.
        let answer_type = if special || localhost_apex {
            match question.qtype {
                Type::A | Type::AAAA => Some(question.qtype),
                Type::NS | Type::SOA if !special => Some(question.qtype),
                _ => None,
            }
        } else if apex && matches!(question.qtype, Type::NS | Type::SOA) {
            Some(question.qtype)
        } else if reverse_ptr && question.qtype == Type::PTR {
            Some(Type::PTR)
        } else {
            None
        };
        // RFC 2308 §2: distinguish name errors from existing names without matching records.
        let nxdomain = !special && !apex && !reverse_ptr;
        // RFC 1035 §3.1: encode Domain names as length-prefixed labels ending in zero.
        let mut origin = [0u8; 255];
        let mut len = 0;
        if !special {
            for label in &labels[zone_start.unwrap()..count] {
                origin[len] = label.len() as u8;
                len += 1;
                origin[len..len + label.len()].copy_from_slice(label);
                len += label.len();
            }
        }
        let owner = if special || apex {
            question.name
        } else {
            NameRef::parse(&origin[..=len], 0).expect("valid Domain")
        };
        let result = (|| {
            let max = cx.max_response_size.max(512);
            if cx.response.capacity() < max {
                if cx.protocol == Protocol::Tcp {
                    cx.response.reserve(max.saturating_sub(cx.response.len()));
                } else {
                    return Err(Error::ResponseBufferTooSmall);
                }
            }
            // RFC 1035 §4.1.1: copy the opcode and Query recursion flags into the Response.
            let mut flags = 0x8000 | (cx.query.flags() & 0x7800) | if nxdomain { 3 } else { 0 };
            if cx.query.opcode() == Opcode::QUERY {
                flags |= cx.query.flags() & 0x0110;
            }
            let mut builder = MessageBuilder::new(cx.response, max, cx.query.id(), flags)
                .map_err(Error::Build)?;
            builder
                .question(question.name, question.qtype, question.qclass)
                .map_err(Error::Build)?;
            let rtype = answer_type.unwrap_or(Type::SOA);
            let rdata: &[u8] = match rtype {
                Type::A => &[127, 0, 0, 1],
                Type::AAAA => &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                Type::NS | Type::PTR => LOCALHOST,
                _ => SOA,
            };
            builder
                .record(
                    if answer_type.is_some() {
                        Section::Answer
                    } else {
                        Section::Authority
                    },
                    if answer_type.is_some() {
                        question.name
                    } else {
                        owner
                    },
                    rtype,
                    Class::IN,
                    TTL,
                    rdata,
                )
                .map_err(Error::Build)?;
            let _ = builder.finish();
            Ok(())
        })();
        match result {
            Ok(()) => Outcome::Response,
            Err(error) => Outcome::Error(error),
        }
    }
}
