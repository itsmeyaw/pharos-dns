use crate::zone::{Zone, update::same_record};
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
    kind != Type::NONE && kind != Type::RESERVED && !kind.to_string().starts_with("TYPE")
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
        if rr.class != Class::IN
            || !rr.owner.is_subdomain_of(&origin)
            || super::setup::unsupported(rr.rtype)
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
    Zone::from_records(origin, records)
}

// RFC 2136 §3.4.1: prescan the complete Update section before changing the Zone.
pub(super) fn validate_updates(zone: &Zone, records: &[ZoneRecord]) -> Rcode {
    for record in records {
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
                if record.rtype == Type::SOA {
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
            Class::ANY => {
                if record.ttl != 0
                    || !record.rdata.is_empty()
                    || query_metatype(record.rtype) && record.rtype != Type::ANY
                {
                    return Rcode::FORMERR;
                }
            }
            Class::NONE => {
                if record.ttl != 0 || query_metatype(record.rtype) {
                    return Rcode::FORMERR;
                }
            }
            _ => return Rcode::FORMERR,
        }
        if super::setup::unsupported(record.rtype) {
            return Rcode::NOTIMP;
        }
    }
    Rcode::NOERROR
}

// RFC 2136 §3.2: evaluate all prerequisite forms against the transaction's current snapshot.
pub(super) fn prerequisites(zone: &Zone, records: &[ZoneRecord]) -> Rcode {
    let mut values: BTreeMap<(Name, Type), Vec<&ZoneRecord>> = BTreeMap::new();
    for record in records {
        if record.ttl != 0 {
            return Rcode::FORMERR;
        }
        if !record.owner.is_subdomain_of(zone.apex()) {
            return Rcode::NOTZONE;
        }
        if super::setup::unsupported(record.rtype) {
            return Rcode::NOTIMP;
        }
        match record.class {
            Class::ANY | Class::NONE => {
                if !record.rdata.is_empty()
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
            Class::IN => {
                if !known(record.rtype) || query_metatype(record.rtype) {
                    return Rcode::FORMERR;
                }
                values
                    .entry((record.owner.clone(), record.rtype))
                    .or_default()
                    .push(record);
            }
            _ => return Rcode::FORMERR,
        }
    }
    // RFC 2136 §2.4.2: value-dependent prerequisites compare entire RRsets, not TTL or order.
    for ((owner, kind), requested) in values {
        let mut want: Vec<&ZoneRecord> = Vec::new();
        for rr in requested {
            if !want.iter().any(|other| same_record(other, rr)) {
                want.push(rr);
            }
        }
        let mut have: Vec<&ZoneRecord> = Vec::new();
        for rr in zone
            .records()
            .iter()
            .filter(|rr| rr.owner == owner && rr.rtype == kind)
        {
            if !have.iter().any(|other| same_record(other, rr)) {
                have.push(rr);
            }
        }
        if have.len() != want.len()
            || want
                .iter()
                .any(|rr| !have.iter().any(|actual| same_record(actual, rr)))
        {
            return Rcode::NXRRSET;
        }
    }
    Rcode::NOERROR
}

#[cfg(test)]
mod tests {
    use super::{build_zone, prerequisites, validate_updates};
    use crate::zone::Zone;
    use pharos_proto::{
        Class, Name, Rcode, Type,
        zone::{ZoneParser, ZoneRecord},
    };

    fn zone() -> Zone {
        let origin: Name = "example.org.".parse().unwrap();
        let text = "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n@ 60 IN NS ns.example.org.\nwww 60 IN A 192.0.2.1\nwww 60 IN A 192.0.2.2\n";
        let records = ZoneParser::new(text.as_bytes(), origin.clone(), "test")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        Zone::from_records(origin, records).unwrap()
    }

    fn rr(owner: &str, kind: Type, class: Class, data: &[u8]) -> ZoneRecord {
        ZoneRecord {
            owner: owner.parse().unwrap(),
            class,
            rtype: kind,
            ttl: 0,
            rdata: data.to_vec(),
        }
    }

    #[test]
    fn coredns_prerequisite_cases() {
        let zone = zone();
        for (record, expected) in [
            (
                rr("www.example.org.", Type::ANY, Class::ANY, &[]),
                Rcode::NOERROR,
            ),
            (
                rr("missing.example.org.", Type::ANY, Class::NONE, &[]),
                Rcode::NOERROR,
            ),
            (
                rr("www.example.org.", Type::A, Class::ANY, &[]),
                Rcode::NOERROR,
            ),
            (
                rr("missing.example.org.", Type::A, Class::ANY, &[]),
                Rcode::NXRRSET,
            ),
            (
                rr("missing.example.org.", Type::A, Class::NONE, &[]),
                Rcode::NOERROR,
            ),
            (
                rr("www.example.org.", Type::A, Class::NONE, &[]),
                Rcode::YXRRSET,
            ),
            (
                rr("www.example.org.", Type::ANY, Class::NONE, &[]),
                Rcode::YXDOMAIN,
            ),
            (
                rr("outside.test.", Type::A, Class::ANY, &[]),
                Rcode::NOTZONE,
            ),
            (
                rr("www.example.org.", Type::RRSIG, Class::ANY, &[]),
                Rcode::NOTIMP,
            ),
        ] {
            assert_eq!(prerequisites(&zone, &[record]), expected);
        }
        let first = rr("www.example.org.", Type::A, Class::IN, &[192, 0, 2, 1]);
        let second = rr("www.example.org.", Type::A, Class::IN, &[192, 0, 2, 2]);
        assert_eq!(
            prerequisites(&zone, std::slice::from_ref(&first)),
            Rcode::NXRRSET
        );
        assert_eq!(
            prerequisites(&zone, &[first.clone(), second, first]),
            Rcode::NOERROR
        );
    }

    #[test]
    fn coredns_update_prescan_cases() {
        let zone = zone();
        let mut bad_ttl = rr("www.example.org.", Type::A, Class::ANY, &[]);
        bad_ttl.ttl = 1;
        for (record, expected) in [
            (
                rr("www.example.org.", Type::A, Class::IN, &[192, 0, 2, 9]),
                Rcode::NOERROR,
            ),
            (
                rr("outside.test.", Type::A, Class::IN, &[192, 0, 2, 9]),
                Rcode::NOTZONE,
            ),
            (bad_ttl, Rcode::FORMERR),
            (
                rr("www.example.org.", Type::ANY, Class::NONE, &[]),
                Rcode::FORMERR,
            ),
            (
                rr("www.example.org.", Type::RRSIG, Class::IN, &[]),
                Rcode::NOTIMP,
            ),
            (
                rr("www.example.org.", Type::SOA, Class::IN, &[0; 20]),
                Rcode::FORMERR,
            ),
            (
                rr("example.org.", Type::SOA, Class::IN, &[0; 20]),
                Rcode::FORMERR,
            ),
        ] {
            assert_eq!(validate_updates(&zone, &[record]), expected);
        }
    }

    #[test]
    fn coredns_zone_validation_and_limits() {
        let existing = zone();
        let origin = existing.apex().clone();
        let records = existing.records().to_vec();
        assert!(build_zone(origin.clone(), records.clone(), 100, 10000).is_ok());
        assert!(build_zone(origin.clone(), records.clone(), 1, 10000).is_err());
        assert!(build_zone(origin.clone(), records.clone(), 100, 1).is_err());
        let mut out_of_zone = records.clone();
        out_of_zone[1].owner = "other.test.".parse().unwrap();
        assert!(build_zone(origin.clone(), out_of_zone, 100, 10000).is_err());
        let mut unsupported = records.clone();
        unsupported[1].rtype = Type::RRSIG;
        assert!(build_zone(origin.clone(), unsupported, 100, 10000).is_err());
        let mut duplicate_soa = records.clone();
        duplicate_soa.push(records[0].clone());
        assert!(build_zone(origin.clone(), duplicate_soa, 100, 10000).is_err());
        let mut cname_conflict = records.clone();
        let mut cname = records[2].clone();
        cname.rtype = Type::CNAME;
        cname.rdata = "target.example.org."
            .parse::<Name>()
            .unwrap()
            .as_wire()
            .to_vec();
        cname_conflict.push(cname);
        assert!(build_zone(origin, cname_conflict, 100, 10000).is_err());
    }
}
