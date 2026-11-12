use super::*;
use crate::transfer::{Transfer, TransferRequest, Transferer};
use pharos_proto::{MessageBuilder, NameRef, Section, Type};
use pharos_server::{Error, Protocol, Stream};

impl Transferer for File {
    fn bind_transfer(&self, transfer: Option<&Transfer>) {
        *self.notifier.lock().unwrap() = transfer.cloned();
    }

    fn transfer(&self, request: TransferRequest<'_>) -> Result<Option<Stream>, Error> {
        let Some(loaded) = self.zones.iter().find(|zone| {
            NameRef::parse(zone.apex.as_wire(), 0).is_ok_and(|name| name == request.zone)
        }) else {
            return Ok(None);
        };
        let zone = loaded.current.load_full().ok_or(Error::InvalidQuery)?;
        let soa = zone
            .records
            .iter()
            .position(|rr| rr.rtype == Type::SOA)
            .ok_or(Error::InvalidQuery)?;
        let current = zone.serial().ok_or(Error::InvalidQuery)?;
        let only_soa = request.qtype == Type::IXFR
            && (request.protocol == Protocol::Udp
                || request.serial != 0 && request.serial == current);
        let authoritative = !(only_soa && request.protocol == Protocol::Tcp);
        let id = request.id;
        let flags = request.flags;
        let qtype = request.qtype;
        let qclass = request.qclass;
        let mut phase = 0u8;
        let mut index = 0usize;
        // RFC 5936 §2.2: the Zone snapshot is bounded by matching SOA records.
        // shortcut: Stream allocates once per Zone Transfer; see #50.
        Ok(Some(Stream::new(move |response| {
            if phase == 4 {
                return Ok(false);
            }
            if response.capacity() < 65535 {
                response.reserve(65535 - response.len());
            }
            let apex = NameRef::parse(zone.apex.as_wire(), 0).map_err(|_| Error::InvalidQuery)?;
            let mut builder = MessageBuilder::new(
                response,
                64500,
                id,
                0x8000 | if authoritative { 0x0400 } else { 0 } | (flags & 0x0110),
            )
            .map_err(Error::Build)?;
            builder
                .question(apex, qtype, qclass)
                .map_err(Error::Build)?;
            let mut size = 0usize;
            loop {
                let previous = (phase, index);
                let next = loop {
                    match phase {
                        0 => {
                            phase = if only_soa { 4 } else { 1 };
                            break Some(&zone.records[soa]);
                        }
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
                let estimate = rr.owner.as_wire().len() + 10 + rr.rdata.len();
                if size > 0 && size + estimate > 63000 {
                    (phase, index) = previous;
                    break;
                }
                let owner =
                    NameRef::parse(rr.owner.as_wire(), 0).map_err(|_| Error::InvalidQuery)?;
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
        })))
    }
}
