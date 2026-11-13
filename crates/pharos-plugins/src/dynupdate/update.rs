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

// RFC 2136 §3.2: evaluate all prerequisite forms against the transaction's current snapshot.
fn prerequisites(zone: &Zone, records: &[ZoneRecord]) -> Rcode {
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
    use super::prerequisites;
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
}
