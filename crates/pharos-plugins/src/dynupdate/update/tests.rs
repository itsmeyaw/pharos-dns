use super::{ExpandedRecord, build_zone, prerequisites, validate_updates};
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

#[test]
fn dynamic_zone_rejects_missing_apex_ns() {
    let origin: Name = "example.org.".parse().unwrap();
    let records = ZoneParser::new(
        "@ 60 IN SOA ns.example.org. hostmaster.example.org. 10 60 60 60 60\n".as_bytes(),
        origin.clone(),
        "test",
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();

    assert!(build_zone(origin, records, 100, 10000).is_err());
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

fn expanded(record: &ZoneRecord) -> ExpandedRecord {
    ExpandedRecord {
        record: record.clone(),
        rdata_len: record.rdata.len(),
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
            Rcode::NXRRSET,
        ),
        (
            rr("missing.example.org.", Type::RRSIG, Class::NONE, &[]),
            Rcode::NOERROR,
        ),
        (
            rr("www.example.org.", Type::RRSIG, Class::ANY, &[1]),
            Rcode::FORMERR,
        ),
        (
            rr("wks.example.org.", Type(11), Class::IN, &[1, 2, 3, 4]),
            Rcode::FORMERR,
        ),
    ] {
        assert_eq!(prerequisites(&zone, &[expanded(&record)]), expected);
    }
    let first = rr("www.example.org.", Type::A, Class::IN, &[192, 0, 2, 1]);
    let second = rr("www.example.org.", Type::A, Class::IN, &[192, 0, 2, 2]);
    assert_eq!(prerequisites(&zone, &[expanded(&first)]), Rcode::NXRRSET);
    assert_eq!(
        prerequisites(
            &zone,
            &[expanded(&first), expanded(&second), expanded(&first)],
        ),
        Rcode::NOERROR
    );
}

#[test]
fn validates_received_rdlength_for_any_and_none_fields() {
    let zone = zone();
    for class in [Class::ANY, Class::NONE] {
        let record = rr("www.example.org.", Type::A, class, &[]);
        let expanded = ExpandedRecord {
            record,
            rdata_len: 1,
        };
        assert_eq!(prerequisites(&zone, &[expanded]), Rcode::FORMERR);
    }

    let record = rr("www.example.org.", Type::A, Class::ANY, &[]);
    assert_eq!(
        validate_updates(
            &zone,
            &[ExpandedRecord {
                record,
                rdata_len: 1,
            }],
        ),
        Rcode::FORMERR
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
        (
            rr("wks.example.org.", Type(11), Class::IN, &[1, 2, 3, 4]),
            Rcode::FORMERR,
        ),
    ] {
        assert_eq!(validate_updates(&zone, &[expanded(&record)]), expected);
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
    let mut malformed_wks = records.clone();
    malformed_wks.push(rr("wks.example.org.", Type(11), Class::IN, &[1, 2, 3, 4]));
    assert!(build_zone(origin.clone(), malformed_wks, 100, 10000).is_err());
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

#[test]
fn coredns_rejects_every_unsupported_metadata_type() {
    let original = zone();
    for kind in [
        Type::SIG,
        Type::KEY,
        Type::NXT,
        Type::DS,
        Type::RRSIG,
        Type::NSEC,
        Type::DNSKEY,
        Type::NSEC3,
        Type::NSEC3PARAM,
        Type::TALINK,
        Type::CDS,
        Type::CDNSKEY,
        Type::ZONEMD,
        Type::TA,
        Type::DLV,
    ] {
        let record = rr("record.example.org.", kind, Class::IN, &[]);
        assert_eq!(
            validate_updates(&original, &[expanded(&record)]),
            Rcode::NOTIMP,
            "{kind}"
        );
        let mut records = original.records().to_vec();
        records.push(record);
        assert!(
            build_zone(original.apex().clone(), records, 100, 10000).is_err(),
            "{kind}"
        );
    }
}

#[test]
fn keeps_spf_seed_data_but_rejects_spf_updates() {
    let original = zone();
    let spf = rr("record.example.org.", Type::SPF, Class::IN, &[1, b'x']);
    let mut records = original.records().to_vec();
    records.push(spf.clone());

    let seeded = build_zone(original.apex().clone(), records, 100, 10000).unwrap();
    assert!(
        seeded
            .records()
            .iter()
            .any(|record| record.rtype == Type::SPF)
    );
    assert_eq!(
        validate_updates(&original, &[expanded(&spf)]),
        Rcode::NOTIMP
    );
}

#[test]
fn zone_mutator_supports_every_coredns_policy_type() {
    let original = zone();
    let mut tested = 0;
    for number in (1..=261).chain([32768, 32769]) {
        let kind = Type(number);
        if !super::known(kind)
            || super::query_metatype(kind)
            || super::super::setup::unsupported(kind)
            || kind == Type::SPF
        {
            continue;
        }
        let mut rdata = match kind {
            Type::A => vec![192, 0, 2, 1],
            Type::AAAA => vec![0; 16],
            Type::NS | Type::CNAME | Type::DNAME | Type::PTR => vec![0],
            Type::MX | Type::SVCB | Type::HTTPS => vec![0, 0, 0],
            Type::SRV => vec![0; 7],
            Type::SOA => vec![0; 22],
            super::WKS_TYPE => vec![0; super::WKS_HEADER_LEN],
            _ => vec![0],
        };
        if kind == Type::SOA {
            rdata[5] = 11;
        }
        let owner = if kind == Type::SOA {
            original.apex().clone()
        } else {
            "record.example.org.".parse().unwrap()
        };
        let record = ZoneRecord {
            owner,
            rtype: kind,
            class: Class::IN,
            ttl: 60,
            rdata,
        };
        let (changed, was_changed) = original
            .apply_updates(std::slice::from_ref(&record))
            .unwrap_or_else(|error| panic!("{kind}: {error}"));
        assert!(was_changed, "{kind}");
        let (_, repeated) = changed
            .apply_updates(std::slice::from_ref(&record))
            .unwrap();
        assert!(!repeated, "{kind}");
        tested += 1;
    }
    assert!(tested >= 50, "tested {tested} types");
}

#[test]
fn accepts_opaque_rfc3597_types_in_updates_and_prerequisites() {
    let original = zone();
    let mut opaque = rr("opaque.example.org.", Type(65280), Class::IN, &[1, 2, 3]);
    opaque.ttl = 60;
    assert_eq!(
        validate_updates(&original, &[expanded(&opaque)]),
        Rcode::NOERROR
    );
    let (updated, changed) = original.apply_updates(&[opaque.clone()]).unwrap();
    assert!(changed);

    opaque.ttl = 0;
    assert_eq!(
        prerequisites(&updated, &[expanded(&opaque)]),
        Rcode::NOERROR
    );
}

#[test]
fn replaces_wks_rr_with_same_address_and_protocol() {
    let original = zone();
    let first = rr(
        "wks.example.org.",
        Type(11),
        Class::IN,
        &[192, 0, 2, 1, 6, 0x01],
    );
    let second = rr(
        "wks.example.org.",
        Type(11),
        Class::IN,
        &[192, 0, 2, 1, 6, 0xff],
    );
    let (added, changed) = original.apply_updates(&[first]).unwrap();
    assert!(changed);
    let (replaced, changed) = added.apply_updates(std::slice::from_ref(&second)).unwrap();
    assert!(changed);
    let wks: Vec<_> = replaced
        .records()
        .iter()
        .filter(|record| record.rtype == Type(11))
        .collect();
    assert_eq!(wks.len(), 1);
    assert_eq!(wks[0].rdata, second.rdata);
}

#[test]
fn replaces_existing_dname_target() {
    let original = zone();
    let first = rr(
        "alias.example.org.",
        Type::DNAME,
        Class::IN,
        "old.example.org.".parse::<Name>().unwrap().as_wire(),
    );
    let second = rr(
        "alias.example.org.",
        Type::DNAME,
        Class::IN,
        "new.example.org.".parse::<Name>().unwrap().as_wire(),
    );
    let (added, _) = original.apply_updates(&[first]).unwrap();
    let (replaced, changed) = added.apply_updates(std::slice::from_ref(&second)).unwrap();
    assert!(changed);
    let dnames: Vec<_> = replaced
        .records()
        .iter()
        .filter(|record| record.rtype == Type::DNAME)
        .collect();
    assert_eq!(dnames.len(), 1);
    assert_eq!(dnames[0].rdata, second.rdata);
}

#[test]
fn ignores_cname_added_at_existing_dname_owner() {
    let original = zone();
    let mut dname = rr(
        "alias.example.org.",
        Type::DNAME,
        Class::IN,
        "target.example.org.".parse::<Name>().unwrap().as_wire(),
    );
    dname.ttl = 60;
    let (with_dname, changed) = original.apply_updates(&[dname]).unwrap();
    assert!(changed);

    let cname = rr(
        "alias.example.org.",
        Type::CNAME,
        Class::IN,
        "other.example.org.".parse::<Name>().unwrap().as_wire(),
    );
    let (unchanged, changed) = with_dname.apply_updates(&[cname]).unwrap();

    assert!(!changed);
    assert_eq!(unchanged.serial(), Some(11));
    assert_eq!(
        unchanged
            .records()
            .iter()
            .filter(|record| record.owner.to_string() == "alias.example.org."
                && record.rtype == Type::DNAME)
            .count(),
        1
    );
    assert!(
        !unchanged
            .records()
            .iter()
            .any(|record| record.owner.to_string() == "alias.example.org."
                && record.rtype == Type::CNAME)
    );
}

#[test]
fn updates_dname_ttl_without_changing_target() {
    let original = zone();
    let mut first = rr(
        "alias.example.org.",
        Type::DNAME,
        Class::IN,
        "target.example.org.".parse::<Name>().unwrap().as_wire(),
    );
    first.ttl = 60;
    let (with_dname, _) = original.apply_updates(&[first.clone()]).unwrap();
    first.ttl = 120;

    let (updated, changed) = with_dname.apply_updates(&[first]).unwrap();

    assert!(changed);
    assert_eq!(updated.serial(), Some(12));
    let dnames: Vec<_> = updated
        .records()
        .iter()
        .filter(|record| record.rtype == Type::DNAME)
        .collect();
    assert_eq!(dnames.len(), 1);
    assert_eq!(dnames[0].ttl, 120);
}

#[test]
fn compressed_duplicate_ns_add_does_not_duplicate_rr() {
    let original = zone();
    let ns = original
        .records()
        .iter()
        .find(|record| record.owner == *original.apex() && record.rtype == Type::NS)
        .unwrap();

    let (unchanged, changed) = original
        .apply_updates_with_rdata_lengths(std::iter::once((ns, 2)))
        .unwrap();

    assert!(!changed);
    assert_eq!(
        unchanged
            .records()
            .iter()
            .filter(|record| record.owner == *original.apex() && record.rtype == Type::NS)
            .count(),
        1
    );
}

#[test]
fn coredns_serial_arithmetic_and_explicit_soa_updates() {
    for (old, new, changed) in [
        (10u32, 10u32, false),
        (10, 11, true),
        (u32::MAX, 1, true),
        (11, 10, false),
        (10, (1u32 << 31) + 10, false),
    ] {
        let base = zone();
        let mut records = base.records().to_vec();
        let soa = records.iter_mut().find(|rr| rr.rtype == Type::SOA).unwrap();
        let offset = soa.rdata.len() - 20;
        soa.rdata[offset..offset + 4].copy_from_slice(&old.to_be_bytes());
        let original = Zone::from_records(base.apex().clone(), records).unwrap();
        let mut update = original
            .records()
            .iter()
            .find(|rr| rr.rtype == Type::SOA)
            .unwrap()
            .clone();
        let offset = update.rdata.len() - 20;
        update.rdata[offset..offset + 4].copy_from_slice(&new.to_be_bytes());
        let (candidate, actual) = original.apply_updates(&[update]).unwrap();
        assert_eq!(actual, changed, "{old} -> {new}");
        assert_eq!(candidate.serial(), Some(if changed { new } else { old }));
    }
}

#[test]
fn coredns_add_duplicate_ttl_and_apex_deletes() {
    let original = zone();
    let mut txt = rr("new.example.org.", Type::TXT, Class::IN, &[1, b'x']);
    txt.ttl = 60;
    let (added, changed) = original.apply_updates(std::slice::from_ref(&txt)).unwrap();
    assert!(changed);
    assert_eq!(added.serial(), Some(11));
    let (unchanged, changed) = added.apply_updates(std::slice::from_ref(&txt)).unwrap();
    assert!(!changed);
    assert_eq!(unchanged.serial(), Some(11));
    txt.ttl = 120;
    let (updated, changed) = unchanged.apply_updates(&[txt]).unwrap();
    assert!(changed);
    assert_eq!(updated.serial(), Some(12));
    let apex = updated.apex().clone();
    let delete_all = ZoneRecord {
        owner: apex.clone(),
        rtype: Type::ANY,
        class: Class::ANY,
        ttl: 0,
        rdata: Vec::new(),
    };
    let ns = updated
        .records()
        .iter()
        .find(|rr| rr.owner == apex && rr.rtype == Type::NS)
        .unwrap();
    let mut delete_ns = ns.clone();
    delete_ns.class = Class::NONE;
    delete_ns.ttl = 0;
    let (protected, _) = updated.apply_updates(&[delete_all, delete_ns]).unwrap();
    assert_eq!(
        protected
            .records()
            .iter()
            .filter(|rr| rr.owner == apex && rr.rtype == Type::NS)
            .count(),
        1
    );
    assert_eq!(
        protected
            .records()
            .iter()
            .filter(|rr| rr.owner == apex && rr.rtype == Type::SOA)
            .count(),
        1
    );
}

#[test]
fn coredns_cname_update_rules() {
    let original = zone();
    let www: Name = "www.example.org.".parse().unwrap();
    let target = "target.example.org.".parse::<Name>().unwrap();
    let mut cname = rr("www.example.org.", Type::CNAME, Class::IN, target.as_wire());
    cname.ttl = 60;
    let (same, changed) = original
        .apply_updates(std::slice::from_ref(&cname))
        .unwrap();
    assert!(!changed);
    assert_eq!(same.serial(), Some(10));
    let mut updates = [
        rr("www.example.org.", Type::A, Class::NONE, &[192, 0, 2, 1]),
        rr("www.example.org.", Type::A, Class::NONE, &[192, 0, 2, 2]),
    ]
    .to_vec();
    updates.push(cname.clone());
    let (added, changed) = original.apply_updates(&updates).unwrap();
    assert!(changed);
    assert_eq!(added.serial(), Some(11));
    assert!(
        added
            .records()
            .iter()
            .any(|rr| rr.owner == www && rr.rtype == Type::CNAME)
    );
    let (again, changed) = added.apply_updates(std::slice::from_ref(&cname)).unwrap();
    assert!(!changed);
    assert_eq!(again.serial(), Some(11));
}

#[test]
fn coredns_delete_rrset_and_specific_record() {
    let original = zone();
    let mut txt = rr("www.example.org.", Type::TXT, Class::IN, &[1, b'x']);
    txt.ttl = 60;
    let (zone, _) = original.apply_updates(&[txt]).unwrap();
    let exact = rr("www.example.org.", Type::A, Class::NONE, &[192, 0, 2, 1]);
    let (zone, changed) = zone.apply_updates(&[exact]).unwrap();
    assert!(changed);
    assert_eq!(
        zone.records()
            .iter()
            .filter(|rr| rr.owner.to_string() == "www.example.org." && rr.rtype == Type::A)
            .count(),
        1
    );
    let all_a = rr("www.example.org.", Type::A, Class::ANY, &[]);
    let (zone, changed) = zone.apply_updates(&[all_a]).unwrap();
    assert!(changed);
    assert!(
        !zone
            .records()
            .iter()
            .any(|rr| rr.owner.to_string() == "www.example.org." && rr.rtype == Type::A)
    );
    assert!(
        zone.records()
            .iter()
            .any(|rr| rr.owner.to_string() == "www.example.org." && rr.rtype == Type::TXT)
    );
    let all_txt = rr("www.example.org.", Type::TXT, Class::ANY, &[]);
    let (zone, changed) = zone.apply_updates(&[all_txt]).unwrap();
    assert!(changed);
    assert!(
        !zone
            .records()
            .iter()
            .any(|rr| rr.owner.to_string() == "www.example.org.")
    );
}
