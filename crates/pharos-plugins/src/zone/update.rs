use super::Zone;
use pharos_proto::{Class, NameRef, Rdata, Type, zone::ZoneRecord};

// RFC 1035 §4.1.4 and RFC 3597 §4: expand embedded names before moving RDATA.
pub(crate) fn legacy_name_rdata(
    kind: Type,
    wire: &[u8],
    offset: usize,
    len: usize,
    canonical: bool,
) -> Result<Option<Vec<u8>>, ()> {
    let end = offset.checked_add(len).ok_or(())?;
    let bytes = wire.get(offset..end).ok_or(())?;
    let (prefix, count, exact) = match kind {
        Type::MD | Type::MF | Type::MB | Type::MG | Type::MR | Type::NSAP_PTR => (0, Some(1), true),
        Type::MINFO | Type::RP => (0, Some(2), true),
        Type::AFSDB | Type::RT | Type::KX | Type::LP => (2, Some(1), true),
        Type::PX => (2, Some(2), true),
        Type::IPSECKEY if bytes.get(1) == Some(&3) => (3, Some(1), false),
        Type::AMTRELAY if bytes.get(1).is_some_and(|value| value & 0x7f == 3) => (2, Some(1), true),
        Type::IPSECKEY | Type::AMTRELAY => return Ok(Some(bytes.to_vec())),
        Type::HIP => {
            let header = bytes.get(..4).ok_or(())?;
            let prefix = 4usize
                .checked_add(usize::from(header[0]))
                .and_then(|n| {
                    n.checked_add(usize::from(u16::from_be_bytes([header[2], header[3]])))
                })
                .ok_or(())?;
            (prefix, None, true)
        }
        _ => return Ok(None),
    };
    let mut result = bytes.get(..prefix).ok_or(())?.to_vec();
    let mut cursor = prefix;
    let mut remaining = count;
    while remaining.is_none_or(|n| n > 0) && (remaining.is_some() || cursor < len) {
        if cursor >= len {
            return Err(());
        }
        let name = NameRef::parse(wire, offset.checked_add(cursor).ok_or(())?).map_err(|_| ())?;
        cursor = cursor.checked_add(name.wire_len()).ok_or(())?;
        if cursor > len {
            return Err(());
        }
        for label in name.labels() {
            result.push(label.len() as u8);
            if canonical {
                result.extend(label.iter().map(u8::to_ascii_lowercase));
            } else {
                result.extend_from_slice(label);
            }
        }
        result.push(0);
        if let Some(count) = &mut remaining {
            *count -= 1;
        }
    }
    if exact && cursor != len {
        return Err(());
    }
    result.extend_from_slice(bytes.get(cursor..).ok_or(())?);
    Ok(Some(result))
}

// RFC 2136 §§1.1.1–1.1.2: UPDATE matching ignores TTL and compares names case-insensitively.
pub(crate) fn same_record(left: &ZoneRecord, right: &ZoneRecord) -> bool {
    left.owner == right.owner
        && left.rtype == right.rtype
        && if let (Ok(Some(a)), Ok(Some(b))) = (
            legacy_name_rdata(left.rtype, &left.rdata, 0, left.rdata.len(), true),
            legacy_name_rdata(right.rtype, &right.rdata, 0, right.rdata.len(), true),
        ) {
            a == b
        } else {
            match (
                Rdata::parse(left.rtype, &left.rdata),
                Rdata::parse(right.rtype, &right.rdata),
            ) {
                (Ok(left), Ok(right)) => left == right,
                _ => left.rdata == right.rdata,
            }
        }
}

impl Zone {
    // RFC 2136 §1.1.3: UPDATE owners match literally, so a wildcard matches only a wildcard owner.
    /// Apply validated UPDATE records to a private copy and index the result once.
    ///
    /// The caller must validate the UPDATE section, including owner, class,
    /// type, TTL, RDATA and nonzero SOA serial, before calling this method.
    pub fn apply_updates(&self, updates: &[ZoneRecord]) -> Result<(Self, bool), String> {
        let mut records = self.records.clone();
        let mut changed = false;
        let mut explicit_soa = false;
        // RFC 2136 §3.4.2: process UPDATE records in order on a private candidate.
        for update in updates {
            let apex = update.owner == self.apex;
            // RFC 2136 §3.4.2.6: Map Update CLASS and TYPE to add and delete operations.
            match update.class {
                // RFC 3007 §4.4: Secure dynamic updates may change the Zone SOA.
                Class::IN if update.rtype == Type::SOA => {
                    let current = records.iter().find(|rr| rr.rtype == Type::SOA);
                    let Some((old, new)) = current
                        .and_then(super::soa_serial)
                        .zip(super::soa_serial(update))
                    else {
                        return Err("invalid SOA".into());
                    };
                    // RFC 1982 §3.2: serial comparisons use the smaller half-space.
                    if new != old && new.wrapping_sub(old) < (1 << 31) {
                        records.retain(|rr| rr.rtype != Type::SOA);
                        records.push(update.clone());
                        changed = true;
                        explicit_soa = true;
                    }
                }
                // RFC 6672 §5.2: ignore a CNAME update when a DNAME already owns the name.
                Class::IN if update.rtype == Type::CNAME => {
                    if records
                        .iter()
                        .any(|rr| rr.owner == update.owner && rr.rtype != Type::CNAME)
                    {
                        continue;
                    }
                    let mut existing = records
                        .iter()
                        .filter(|rr| rr.owner == update.owner && rr.rtype == Type::CNAME);
                    if existing
                        .next()
                        .is_some_and(|rr| same_record(rr, update) && rr.ttl == update.ttl)
                        && existing.next().is_none()
                    {
                        continue;
                    }
                    records.retain(|rr| !(rr.owner == update.owner && rr.rtype == Type::CNAME));
                    records.push(update.clone());
                    changed = true;
                }
                // RFC 6672 §5.2: ignore updates when a CNAME already owns the name.
                Class::IN => {
                    if records
                        .iter()
                        .any(|rr| rr.owner == update.owner && rr.rtype == Type::CNAME)
                    {
                        continue;
                    }
                    if let Some(rr) = records.iter_mut().find(|rr| same_record(rr, update)) {
                        if rr.ttl != update.ttl {
                            *rr = update.clone();
                            changed = true;
                        }
                    } else {
                        records.push(update.clone());
                        changed = true;
                    }
                }
                // RFC 2136 §3.4.2.3: delete the named RRsets, keeping apex SOA and NS.
                Class::ANY => {
                    let before = records.len();
                    records.retain(|rr| {
                        rr.owner != update.owner
                            || (update.rtype != Type::ANY && rr.rtype != update.rtype)
                            || (apex && matches!(rr.rtype, Type::SOA | Type::NS))
                    });
                    changed |= before != records.len();
                }
                // RFC 2136 §3.4.2.4: Delete the RR, keeping apex SOA and the final apex NS.
                Class::NONE => {
                    if apex && update.rtype == Type::SOA {
                        continue;
                    }
                    if apex
                        && update.rtype == Type::NS
                        && records
                            .iter()
                            .filter(|rr| rr.owner == update.owner && rr.rtype == Type::NS)
                            .count()
                            <= 1
                    {
                        continue;
                    }
                    if let Some(index) = records.iter().position(|rr| same_record(rr, update)) {
                        records.remove(index);
                        changed = true;
                    }
                }
                _ => return Err("invalid UPDATE class".into()),
            }
        }
        // RFC 3007 §1.1: increment SOA serial after a Zone change.
        if changed && !explicit_soa {
            let soa = records
                .iter_mut()
                .find(|rr| rr.rtype == Type::SOA)
                .ok_or("Zone has no SOA")?;
            let offset = soa.rdata.len().checked_sub(20).ok_or("invalid SOA")?;
            // RFC 1982 §3.1: SOA serial addition wraps modulo 2^32.
            let serial = super::soa_serial(soa)
                .ok_or("invalid SOA")?
                // RFC 1982 §7 and RFC 2136 §7.11: Increment UPDATE SOA serial, skipping zero.
                .wrapping_add(1)
                .max(1);
            // RFC 2136 §7.11: skip zero when incrementing the SOA serial.
            soa.rdata[offset..offset + 4].copy_from_slice(&serial.to_be_bytes());
        }
        Ok((
            Self::from_dynamic_records(self.apex.clone(), records)?,
            changed,
        ))
    }
}
