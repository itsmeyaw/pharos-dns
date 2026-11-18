//! Localhost and locally served reverse Domains.

pub(crate) mod setup;

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use pharos_corefile::{Cursor, Error as CorefileError, normalize_domain};
use pharos_proto::{Class, Name, NameRef, Opcode, Section, Type};
use pharos_server::{Context, Error, Next, Outcome, Plugin, metrics::Registry};

// RFC 6303 §3: Set the SOA minimum (negative-cache TTL) equal to the record TTL.
const TTL: u32 = 604_800;
// RFC 1035 §3.3.13: SOA RDATA contains MNAME, RNAME and five 32-bit values.
// RFC 6303 §3: Serve localhost SOA and NS data to identify empty-zone answers.
// RFC 6303 §3: Use nobody.invalid. as the SOA RNAME.

#[derive(Debug)]
pub struct Local {
    prefix: bool,
    disabled_zones: Vec<Name>,
    counter: Option<Arc<AtomicU64>>,
}

impl Local {
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, CorefileError> {
        cursor.next();
        if !cursor.remaining_args().is_empty() {
            return Err(cursor.arg_err());
        }
        let mut prefix = true;
        let mut disabled_zones = Vec::new();
        while cursor.next_block() {
            let option = cursor.val().to_owned();
            let args = cursor.remaining_args();
            match option.as_str() {
                "localhost_prefix" => {
                    prefix = match args.as_slice() {
                        [value] if value == "on" => true,
                        [value] if value == "off" => false,
                        _ => return Err(cursor.arg_err()),
                    };
                }
                "disable" if !args.is_empty() => {
                    for value in args {
                        let zones = normalize_domain(&value);
                        if zones.is_empty() {
                            return Err(cursor.error(format!("invalid Zone {value}")));
                        }
                        for zone in zones {
                            disabled_zones.push(
                                zone.parse::<Name>()
                                    .map_err(|_| cursor.error(format!("invalid Zone {value}")))?,
                            );
                        }
                    }
                }
                "disable" => return Err(cursor.arg_err()),
                _ => return Err(cursor.error("unknown local property")),
            }
        }
        Ok(Self {
            prefix,
            disabled_zones,
            counter: None,
        })
    }

    pub(crate) fn set_metrics(&mut self, registry: &Registry) {
        self.counter = Some(registry.local());
    }
}

impl Plugin for Local {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        // RFC 1034 §4.3.1: Local data is IN-class; RFC 1035 §6.2 permits QCLASS=ANY.
        if cx
            .query
            .questions()
            .next()
            .is_some_and(|question| question.qclass != Class::IN && question.qclass != Class::ANY)
        {
            return next.run(cx).await;
        }
        if cx.query.questions().next().is_some_and(|question| {
            question
                .name
                .labels()
                .last()
                .is_some_and(|label| label.eq_ignore_ascii_case(b"arpa"))
        }) {
            // RFC 6303 §4: later authoritative Plugins own matching reverse names first.
            return next.run(cx).await;
        }
        match self.answer(cx, None) {
            Some(outcome) => outcome,
            None => next.run(cx).await,
        }
    }
}

impl Local {
    pub(crate) fn answer_special(
        &self,
        cx: &mut Context<'_, '_>,
        special: crate::SpecialUse,
    ) -> Option<Outcome> {
        self.answer(cx, Some(special))
    }

    fn answer(
        &self,
        cx: &mut Context<'_, '_>,
        special_use: Option<crate::SpecialUse>,
    ) -> Option<Outcome> {
        let question = cx.query.questions().next()?;
        // RFC 1035 §6.2: QCLASS=ANY matches the IN-class local data.
        if question.qclass != Class::IN && question.qclass != Class::ANY {
            return None;
        }
        let mut first = None;
        let mut last = None;
        let mut count = 0;
        let mut reverse_ptr = true;
        for label in question.name.labels() {
            if count == 0 {
                first = Some(label);
            }
            last = Some(label);
            let expected = match count {
                0 => b"1".as_slice(),
                1 | 2 => b"0",
                3 => b"127",
                4 => b"in-addr",
                5 => b"arpa",
                _ => {
                    reverse_ptr = false;
                    count += 1;
                    continue;
                }
            };
            reverse_ptr &= label.eq_ignore_ascii_case(expected);
            count += 1;
        }
        let first = first?;
        let last = last?;
        let reverse_ptr = reverse_ptr && count == 6;
        // RFC 6761 §6.3: localhost and its subdomains resolve to loopback.
        let special = count > 1
            && (last.eq_ignore_ascii_case(b"localhost")
                || (self.prefix && first.eq_ignore_ascii_case(b"localhost")));
        let reverse_zone_labels = match special_use {
            Some(crate::SpecialUse::Reverse { zone_labels })
                if !last.eq_ignore_ascii_case(b"localhost") =>
            {
                Some(zone_labels)
            }
            _ => None,
        };
        // RFC 6303 §4: serve all locally assigned reverse Zones from the shared catalogue.
        let zone_start = if last.eq_ignore_ascii_case(b"localhost") {
            Some(count - 1)
        } else {
            reverse_zone_labels.map(|zone_labels| count - zone_labels)
        };
        if !special && zone_start.is_none() {
            return None;
        }
        // RFC 6303 §3: Let operators disable each locally served reverse Zone independently.
        if self
            .disabled_zones
            .iter()
            .any(|zone| crate::name_within(question.name, zone))
        {
            return None;
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
        let localhost_apex = apex && first.eq_ignore_ascii_case(b"localhost");
        // RFC 1034 §4.3.2: select records matching the Question type.
        let answer_type = if special || localhost_apex {
            match question.qtype {
                Type::A | Type::AAAA => Some(question.qtype),
                _ => None,
            }
        // RFC 6303 §3: Answer NS and SOA at the zone apex for UPDATE zone discovery.
        } else if apex && matches!(question.qtype, Type::NS | Type::SOA) {
            Some(question.qtype)
        } else if reverse_ptr && question.qtype == Type::PTR {
            Some(Type::PTR)
        } else {
            None
        };
        // RFC 1035 §6.2 and RFC 2308 §2: IN-only local data cannot prove QCLASS=ANY denial.
        if question.qclass == Class::ANY && answer_type.is_none() {
            return None;
        }
        // RFC 2308 §2: distinguish name errors from existing names without matching records.
        let nxdomain = !special && !apex && !reverse_ptr;
        // RFC 1035 §3.1: encode Domain names as length-prefixed labels ending in zero.
        let mut origin = [0u8; 255];
        let mut len = 0;
        if let Some(start) = zone_start {
            for label in question.name.labels().skip(start) {
                origin[len] = label.len() as u8;
                len += 1;
                origin[len..len + label.len()].copy_from_slice(label);
                len += label.len();
            }
        } else {
            // RFC 6761 §6.3: localhost-prefix aliases use localhost. as their local zone.
            origin[..crate::LOCALHOST_NAME.len()].copy_from_slice(crate::LOCALHOST_NAME);
            len = crate::LOCALHOST_NAME.len() - 1;
        }
        let owner = NameRef::parse(&origin[..=len], 0).expect("valid Domain");
        let result = (|| {
            // RFC 1035 §4.1.1 and RFC 4035 §3.2.2: mark a Response and copy opcode, RD and CD.
            // RFC 1034 §4.3.2: mark local-zone answers, including NXDOMAIN, authoritative.
            // RFC 1035 §6.2: QCLASS=ANY cannot be authoritative for selected-class local data.
            let mut flags = 0x8000
                | if question.qclass == Class::ANY {
                    0
                } else {
                    0x0400
                }
                | (cx.query.flags() & 0x7800)
                | if nxdomain { 3 } else { 0 };
            if cx.query.opcode() == Opcode::QUERY {
                flags |= cx.query.flags() & 0x0110;
            }
            let mut builder = crate::response_builder(
                cx.response,
                cx.query,
                cx.protocol,
                cx.max_response_size,
                flags,
            )?;
            builder
                .question(question.name, question.qtype, question.qclass)
                .map_err(Error::Build)?;
            // RFC 6303 §3: Include SOA records for negative caching and update discovery.
            let rtype = answer_type.unwrap_or(Type::SOA);
            // RFC 1035 §3.4.1 and RFC 3596 §2.2: encode A and AAAA loopback addresses.
            let mut soa = [0u8; crate::LOCALHOST_NAME.len() + crate::EMPTY_ZONE_SOA_TAIL.len()];
            let rdata: &[u8] = match rtype {
                Type::A => &[127, 0, 0, 1],
                Type::AAAA => &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                // RFC 6303 §3: use resolvable localhost. as the local NS target.
                Type::NS => crate::LOCALHOST_NAME,
                Type::PTR => crate::LOCALHOST_NAME,
                _ => {
                    // RFC 2181 §7.3: make SOA MNAME match the resolvable local NS target.
                    soa[..crate::LOCALHOST_NAME.len()].copy_from_slice(crate::LOCALHOST_NAME);
                    soa[crate::LOCALHOST_NAME.len()
                        ..crate::LOCALHOST_NAME.len() + crate::EMPTY_ZONE_SOA_TAIL.len()]
                        .copy_from_slice(crate::EMPTY_ZONE_SOA_TAIL);
                    &soa[..crate::LOCALHOST_NAME.len() + crate::EMPTY_ZONE_SOA_TAIL.len()]
                }
            };
            // RFC 2181 §7.2: SOA answers retain a nonzero TTL instead of forcing TTL zero.
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
        Some(match result {
            Ok(()) => Outcome::Response,
            Err(error) => Outcome::Error(error),
        })
    }
}
