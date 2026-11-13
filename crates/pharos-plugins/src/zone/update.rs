use super::Zone;
use pharos_proto::{Class, Rdata, Type, zone::ZoneRecord};

// RFC 2136 §1.1.1: RR comparison ignores TTL and compares domain names case-insensitively.
pub(crate) fn same_record(left: &ZoneRecord, right: &ZoneRecord) -> bool {
    left.owner == right.owner
        && left.rtype == right.rtype
        && match (
            Rdata::parse(left.rtype, &left.rdata),
            Rdata::parse(right.rtype, &right.rdata),
        ) {
            (Ok(left), Ok(right)) => left == right,
            _ => left.rdata == right.rdata,
        }
}

impl Zone {
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
            match update.class {
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
                Class::ANY => {
                    let before = records.len();
                    records.retain(|rr| {
                        rr.owner != update.owner
                            || (update.rtype != Type::ANY && rr.rtype != update.rtype)
                            || (apex && matches!(rr.rtype, Type::SOA | Type::NS))
                    });
                    changed |= before != records.len();
                }
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
        if changed && !explicit_soa {
            let soa = records
                .iter_mut()
                .find(|rr| rr.rtype == Type::SOA)
                .ok_or("Zone has no SOA")?;
            let offset = soa.rdata.len().checked_sub(20).ok_or("invalid SOA")?;
            let serial = super::soa_serial(soa)
                .ok_or("invalid SOA")?
                .wrapping_add(1)
                .max(1);
            // RFC 2136 §7.11: skip zero when incrementing the SOA serial.
            soa.rdata[offset..offset + 4].copy_from_slice(&serial.to_be_bytes());
        }
        Ok((Self::from_records(self.apex.clone(), records)?, changed))
    }
}
