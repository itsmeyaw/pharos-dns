use super::ExpandedRecord;
use crate::zone::{
    Zone,
    update::{WKS_HEADER_LEN, WKS_TYPE, same_record_with_rdata_lengths},
};
use pharos_proto::{Class, Name, Rcode, Type, zone::ZoneRecord};
use std::collections::BTreeMap;

fn query_metatype(kind: Type) -> bool {
    matches!(
        kind,
        Type::ANY
            | Type::AXFR
            | Type::IXFR
            | Type::MAILA
            | Type::MAILB
            | Type::OPT
            | Type::TKEY
            | Type::TSIG
    )
}

fn known(kind: Type) -> bool {
    super::setup::known(kind)
}

pub(super) fn build_zone(
    origin: Name,
    records: Vec<ZoneRecord>,
    max_records: usize,
    max_bytes: usize,
) -> Result<Zone, String> {
    if records.len() > max_records {
        return Err("Zone exceeds max_records".into());
    }
    let mut remaining = max_bytes;
    let mut names: BTreeMap<Name, (bool, bool)> = BTreeMap::new();
    let mut soa_count = 0;
    for rr in &records {
        let size = rr
            .owner
            .as_wire()
            .len()
            .checked_add(10)
            .and_then(|size| size.checked_add(rr.rdata.len()))
            .ok_or("Zone exceeds max_bytes")?;
        remaining = remaining
            .checked_sub(size)
            .ok_or("Zone exceeds max_bytes")?;
        // RFC 1035 §5.2: Validate the seed zone's class and apex SOA before serving it.
        // RFC 1035 §3.4.2: WKS RDATA needs a four-octet address and protocol octet.
        if rr.class != Class::IN
            || !rr.owner.is_subdomain_of(&origin)
            || super::setup::unsupported(rr.rtype)
            || rr.rtype == WKS_TYPE && rr.rdata.len() < WKS_HEADER_LEN
        {
            return Err("invalid Zone record".into());
        }
        // RFC 1034 §3.6.2: CNAME data cannot coexist with other data at the same owner.
        let state = names.entry(rr.owner.clone()).or_default();
        if rr.rtype == Type::CNAME {
            if state.0 || state.1 {
                return Err("CNAME conflict".into());
            }
            state.0 = true;
        } else {
            if state.0 {
                return Err("CNAME conflict".into());
            }
            state.1 = true;
        }
        if rr.rtype == Type::SOA {
            // RFC 2136 §§4.2 and 7.11: Zone SOA serials must be nonzero.
            let serial = rr
                .rdata
                .len()
                .checked_sub(20)
                .and_then(|offset| rr.rdata.get(offset..offset + 4))
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .map(u32::from_be_bytes);
            if rr.owner != origin || serial.is_none_or(|serial| serial == 0) {
                return Err("invalid SOA".into());
            }
            soa_count += 1;
        }
    }
    if soa_count != 1 {
        return Err("Zone must have exactly one SOA".into());
    }
    Zone::from_dynamic_records(origin, records)
}

// RFC 2136 §3.4.1: prescan the complete Update section before changing the Zone.
pub(super) fn validate_updates(zone: &Zone, records: &[ExpandedRecord]) -> Rcode {
    for expanded in records {
        let record = &expanded.record;
        // RFC 2136 §1.2: UPDATE owner names must be within the Zone named in the request.
        if !record.owner.is_subdomain_of(zone.apex()) {
            return Rcode::NOTZONE;
        }
        if !known(record.rtype) {
            return Rcode::FORMERR;
        }
        match record.class {
            Class::IN => {
                if query_metatype(record.rtype) {
                    return Rcode::FORMERR;
                }
                // RFC 1035 §3.4.2: WKS RDATA needs address, protocol, and bitmap fields.
                if record.rtype == WKS_TYPE && record.rdata.len() < WKS_HEADER_LEN {
                    return Rcode::FORMERR;
                }
                if record.rtype == Type::SOA {
                    // RFC 1035 §5.2: The zone SOA must appear at the zone top.
                    // RFC 2136 §§4.2 and 7.11: require the apex and a nonzero SOA serial.
                    let serial = record
                        .rdata
                        .len()
                        .checked_sub(20)
                        .and_then(|offset| record.rdata.get(offset..offset + 4))
                        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                        .map(u32::from_be_bytes);
                    if &record.owner != zone.apex() || serial.is_none_or(|n| n == 0) {
                        return Rcode::FORMERR;
                    }
                }
            }
            // RFC 2136 §3.4.1.2: ANY-class deletion requires empty received RDATA.
            Class::ANY => {
                if record.ttl != 0
                    || expanded.rdata_len != 0
                    || query_metatype(record.rtype) && record.rtype != Type::ANY
                {
                    return Rcode::FORMERR;
                }
            }
            Class::NONE => {
                if record.ttl != 0 || query_metatype(record.rtype) {
                    return Rcode::FORMERR;
                }
                // RFC 1035 §3.4.2: a WKS deletion names its complete address/protocol key.
                if record.rtype == WKS_TYPE && record.rdata.len() < WKS_HEADER_LEN {
                    return Rcode::FORMERR;
                }
            }
            _ => return Rcode::FORMERR,
        }
        // RFC 3007 §4.4: Dynamic updates must not modify NXT records.
        if super::setup::unsupported(record.rtype) {
            return Rcode::NOTIMP;
        }
        // RFC 7208 §14.1: reject type 99 in UPDATE while retaining seed-zone compatibility.
        if record.rtype == Type::SPF {
            return Rcode::NOTIMP;
        }
    }
    Rcode::NOERROR
}

// RFC 2136 §3.2: evaluate all prerequisite forms against the transaction's current snapshot.
pub(super) fn prerequisites(zone: &Zone, records: &[ExpandedRecord]) -> Rcode {
    let mut values: BTreeMap<(Name, Type), Vec<&ExpandedRecord>> = BTreeMap::new();
    for expanded in records {
        let record = &expanded.record;
        // RFC 2136 §3.2: reject malformed prerequisite fields before checking zone state.
        if record.ttl != 0 {
            return Rcode::FORMERR;
        }
        if !record.owner.is_subdomain_of(zone.apex()) {
            return Rcode::NOTZONE;
        }
        match record.class {
            // RFC 2136 §§3.2.1–3.2.2: ANY and NONE prerequisites require empty RDATA.
            Class::ANY | Class::NONE => {
                if expanded.rdata_len != 0
                    || !known(record.rtype)
                    || (query_metatype(record.rtype) && record.rtype != Type::ANY)
                {
                    return Rcode::FORMERR;
                }
                let exists = zone.records().iter().any(|rr| {
                    rr.owner == record.owner
                        && (record.rtype == Type::ANY || rr.rtype == record.rtype)
                });
                match (record.class, record.rtype, exists) {
                    (Class::ANY, Type::ANY, false) => return Rcode::NXDOMAIN,
                    (Class::ANY, _, false) => return Rcode::NXRRSET,
                    (Class::NONE, Type::ANY, true) => return Rcode::YXDOMAIN,
                    (Class::NONE, _, true) => return Rcode::YXRRSET,
                    _ => {}
                }
            }
            // RFC 2136 §3.2.3: Group ZCLASS prerequisites by owner and type for comparison.
            Class::IN => {
                if !known(record.rtype) || query_metatype(record.rtype) {
                    return Rcode::FORMERR;
                }
                // RFC 1035 §3.4.2: value-dependent WKS prerequisites need its address/protocol key.
                if record.rtype == WKS_TYPE && record.rdata.len() < WKS_HEADER_LEN {
                    return Rcode::FORMERR;
                }
                values
                    .entry((record.owner.clone(), record.rtype))
                    .or_default()
                    .push(expanded);
            }
            _ => return Rcode::FORMERR,
        }
    }
    // RFC 2136 §2.4.2: value-dependent prerequisites compare entire RRsets, not TTL or order.
    for ((owner, kind), requested) in values {
        let mut want: Vec<&ExpandedRecord> = Vec::new();
        for rr in requested {
            if !want.iter().any(|other| {
                same_record_with_rdata_lengths(
                    &other.record,
                    other.rdata_len,
                    &rr.record,
                    rr.rdata_len,
                )
            }) {
                want.push(rr);
            }
        }
        let mut have: Vec<&ZoneRecord> = Vec::new();
        for rr in zone
            .records()
            .iter()
            .filter(|rr| rr.owner == owner && rr.rtype == kind)
        {
            if !have.iter().any(|other| {
                same_record_with_rdata_lengths(other, other.rdata.len(), rr, rr.rdata.len())
            }) {
                have.push(rr);
            }
        }
        if have.len() != want.len()
            || want.iter().any(|rr| {
                !have.iter().any(|actual| {
                    same_record_with_rdata_lengths(
                        &rr.record,
                        rr.rdata_len,
                        actual,
                        actual.rdata.len(),
                    )
                })
            })
        {
            return Rcode::NXRRSET;
        }
    }
    Rcode::NOERROR
}

#[cfg(test)]
mod tests;
