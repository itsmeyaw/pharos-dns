use super::Zone;
use crate::transfer::TransferRequest;
use pharos_proto::{MessageBuilder, NameRef, Section, Type};
use pharos_server::{Error, Protocol, Stream};
use std::sync::Arc;

impl Zone {
    /// Stream this Zone in response to a Zone Transfer request.
    pub fn transfer(self: Arc<Self>, request: TransferRequest<'_>) -> Result<Stream, Error> {
        self.transfer_with_question(request, false)
    }

    #[cfg_attr(not(feature = "plugin-auto"), allow(dead_code))]
    pub(crate) fn transfer_with_question(
        self: Arc<Self>,
        request: TransferRequest<'_>,
        preserve_question: bool,
    ) -> Result<Stream, Error> {
        let zone = self;
        let soa = zone
            .records
            .iter()
            .position(|rr| rr.rtype == Type::SOA)
            .ok_or(Error::InvalidQuery)?;
        let current = zone.serial().ok_or(Error::InvalidQuery)?;
        // RFC 1995 §2: an up-to-date IXFR returns only the current SOA.
        // RFC 1995 §6: An unknown requested version falls back to a full TCP zone transfer.
        let only_soa = request.qtype == Type::IXFR
            && (request.protocol == Protocol::Udp
                || request.serial != 0 && request.serial == current);
        let authoritative = !(only_soa && request.protocol == Protocol::Tcp);
        let id = request.id;
        let flags = request.flags;
        let qtype = request.qtype;
        let qclass = request.qclass;
        let mut question = [0u8; 255];
        let mut question_len = 0;
        // RFC 5936 §2.2.2: the first Message copies the query Question.
        if preserve_question {
            for label in request.zone.labels() {
                question[question_len] = label.len() as u8;
                question_len += 1;
                question[question_len..question_len + label.len()].copy_from_slice(label);
                question_len += label.len();
            }
            question_len += 1;
        }
        let mut phase = 0u8;
        let mut index = 0usize;
        // RFC 5936 §2.2: the Zone snapshot is bounded by matching SOA records.
        // shortcut: Stream allocates once per Zone Transfer; see #50.
        // RFC 5936 §3: serve one immutable Zone version for this transfer.
        Ok(Stream::new(move |response| {
            if phase == 4 {
                return Ok(false);
            }
            if response.capacity() < 65535 {
                response.reserve(65535 - response.len());
            }
            let apex = NameRef::parse(zone.apex.as_wire(), 0).map_err(|_| Error::InvalidQuery)?;
            // RFC 8945 §5.3: reserve room for Listener-applied TSIG on each Message.
            // RFC 5936 §2.2.1: AXFR sets QR and AA and echoes ID, RD and CD.
            let mut builder = MessageBuilder::new(
                response,
                64500,
                id,
                0x8000 | if authoritative { 0x0400 } else { 0 } | (flags & 0x0110),
            )
            .map_err(Error::Build)?;
            let qname = if preserve_question {
                NameRef::parse(&question[..question_len], 0).map_err(|_| Error::InvalidQuery)?
            } else {
                apex
            };
            // RFC 5936 §2.2.2: subsequent Transfer Messages may repeat the Question.
            builder
                .question(qname, qtype, qclass)
                .map_err(Error::Build)?;
            // RFC 5936 §7.1: Send multiple resource records per response by default.
            let mut size = 0usize;
            loop {
                let previous = (phase, index);
                // RFC 3225 §3: include DNSSEC RRsets in zone transfers regardless of DO.
                let next = loop {
                    // RFC 4035 §3.1.5: zone transfers include authoritative DNSSEC records.
                    match phase {
                        0 => {
                            // RFC 1995 §4: full-zone IXFR starts and ends with the SOA.
                            phase = if only_soa { 4 } else { 1 };
                            break Some(&zone.records[soa]);
                        }
                        // RFC 5936 §3.5: AXFR includes occluded names in the Zone snapshot.
                        1 | 2 => {
                            let rr = zone.records.get(index);
                            index += 1;
                            match rr {
                                Some(rr) => {
                                    let apex_record = rr.owner == zone.apex
                                        && (rr.rtype == Type::NS
                                            || rr.rtype == Type::RRSIG
                                                && rr.rdata.get(..2).is_some_and(|covered| {
                                                    covered == Type::NS.0.to_be_bytes()
                                                        || covered == Type::SOA.0.to_be_bytes()
                                                }));
                                    if rr.rtype != Type::SOA && (phase == 1) == apex_record {
                                        break Some(rr);
                                    }
                                }
                                None => {
                                    phase += 1;
                                    index = 0;
                                }
                            }
                        }
                        3 => {
                            phase = 4;
                            break Some(&zone.records[soa]);
                        }
                        _ => break None,
                    }
                };
                let Some(rr) = next else {
                    break;
                };
                // RFC 5936 §2.2: include as many RRs per message as fit to amortize overhead.
                // RFC 1035 §§4.1.3, 4.2.2: keep RR batches within the TCP Message limit.
                let estimate = rr.owner.as_wire().len() + 10 + rr.rdata.len();
                if size > 0 && size + estimate > 63000 {
                    (phase, index) = previous;
                    break;
                }
                // RFC 5936 §2.2.3: each zone RR is written into the Answer section.
                let owner =
                    NameRef::parse(rr.owner.as_wire(), 0).map_err(|_| Error::InvalidQuery)?;
                // RFC 5936 §3.4: AXFR RDATA names are emitted without added compression.
                if !builder
                    .record(
                        Section::Answer,
                        owner,
                        rr.rtype,
                        rr.class,
                        rr.ttl,
                        &rr.rdata,
                    )
                    .map_err(Error::Build)?
                {
                    return Err(Error::ResponseBufferTooSmall);
                }
                size += estimate;
            }
            let _ = builder.finish();
            Ok(true)
        }))
    }
}
