use std::path::PathBuf;

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use pharos_dnssec::{
    canonical::{CanonicalRecord, signed_data},
    keys::KeyPair,
};
use pharos_proto::{Name, NameRef, Rdata, Type};

use super::sign;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn key() -> KeyPair {
    KeyPair::from_files(
        fixture("dnssec/miek-ed25519-ksk.key"),
        fixture("dnssec/miek-ed25519-ksk.private"),
    )
    .unwrap()
}

#[test]
fn signs_authoritative_records_and_preserves_unsigned_glue() {
    let apex: Name = "miek.nl.".parse().unwrap();
    let delegation: Name = "delegated.miek.nl.".parse().unwrap();
    let glue: Name = "a.delegated.miek.nl.".parse().unwrap();
    let key = key();
    let records = sign(
        &apex,
        &fixture("file/coredns-delegation.zone"),
        &[key],
        1_700_000_000,
        0,
        0,
    )
    .unwrap();
    assert_eq!(records[0].rtype, Type::SOA);
    assert_eq!(records[1].rtype, Type::RRSIG);
    assert!(records[1].rdata.starts_with(&Type::SOA.0.to_be_bytes()));
    assert!(
        records
            .iter()
            .any(|r| r.owner == glue && r.rtype == Type::A)
    );
    assert!(
        !records
            .iter()
            .any(|r| r.owner == glue && matches!(r.rtype, Type::RRSIG | Type::NSEC))
    );
    assert!(
        records
            .iter()
            .any(|r| r.owner == delegation && r.rtype == Type::NSEC)
    );
    assert!(!records.iter().any(|r| r.owner == delegation
        && r.rtype == Type::RRSIG
        && r.rdata.starts_with(&Type::NS.0.to_be_bytes())));
    let soa = records.iter().find(|r| r.rtype == Type::SOA).unwrap();
    assert!(matches!(
        Rdata::parse(Type::SOA, &soa.rdata).unwrap(),
        Rdata::Soa {
            serial: 1_700_000_000,
            ..
        }
    ));
    for kind in [Type::DNSKEY, Type::CDNSKEY, Type::CDS] {
        assert!(records.iter().any(|r| r.owner == apex && r.rtype == kind));
    }
    let cds = records.iter().find(|r| r.rtype == Type::CDS).unwrap();
    assert_eq!(cds.rdata[3], 2);
}

// RFC 1982 §3.2; RFC 4033 §8.2: Time-based signing must advance non-newer serials.
#[test]
fn soa_serial_advances_when_unix_time_is_not_newer() {
    let path = std::env::temp_dir().join(format!("pharos-sign-serial-{}", std::process::id()));
    let apex: Name = "miek.nl.".parse().unwrap();
    for (previous, now, expected) in [(100, 100, 101), (100, 99, 101), (u32::MAX - 1, 1, 1)] {
        std::fs::write(
                &path,
                format!(
                    "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. ({previous} 4H 1H 7D 4H)\n@ IN NS ns.\n"
                ),
            )
            .unwrap();
        let records = sign(&apex, &path, &[key()], now, 0, 0).unwrap();
        let soa = records.iter().find(|rr| rr.rtype == Type::SOA).unwrap();
        assert!(matches!(
            Rdata::parse(Type::SOA, &soa.rdata).unwrap(),
            Rdata::Soa { serial, .. } if serial == expected
        ));
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn signatures_verify_against_canonical_rrsets() {
    let apex: Name = "miek.nl.".parse().unwrap();
    let key = key();
    let records = sign(
        &apex,
        &fixture("file/coredns-miek.zone"),
        std::slice::from_ref(&key),
        1_700_000_000,
        13,
        29,
    )
    .unwrap();
    for rr in records.iter().filter(|r| r.rtype == Type::RRSIG) {
        let signature = Rdata::parse(Type::RRSIG, &rr.rdata).unwrap();
        let Rdata::Rrsig {
            type_covered,
            signature: bytes,
            inception,
            expiration,
            ..
        } = signature
        else {
            unreachable!()
        };
        assert_eq!(inception, 1_700_000_000 - 3 * 60 * 60 - 13);
        assert_eq!(expiration, 1_700_000_000 + 32 * 24 * 60 * 60 + 29);
        let rrset: Vec<_> = records
            .iter()
            .filter(|r| r.owner == rr.owner && r.rtype == type_covered)
            .map(|r| CanonicalRecord {
                owner: NameRef::parse(r.owner.as_wire(), 0).unwrap(),
                class: r.class,
                data: Rdata::parse(r.rtype, &r.rdata).unwrap(),
            })
            .collect();
        let data = signed_data(&signature, &rrset).unwrap();
        UnparsedPublicKey::new(&ED25519, &key.public.public_key)
            .verify(&data, bytes)
            .unwrap();
    }
    assert!(records.iter().any(|r| r.rtype == Type::RRSIG));
}

#[test]
fn nsec_chain_is_circular_in_canonical_order() {
    let apex: Name = "miek.nl.".parse().unwrap();
    let records = sign(
        &apex,
        &fixture("file/coredns-miek.zone"),
        &[key()],
        1_700_000_000,
        0,
        0,
    )
    .unwrap();
    let mut nsecs: Vec<_> = records.iter().filter(|r| r.rtype == Type::NSEC).collect();
    nsecs.sort_by(|a, b| a.owner.cmp(&b.owner));
    for (i, rr) in nsecs.iter().enumerate() {
        let Rdata::Nsec { next, .. } = Rdata::parse(Type::NSEC, &rr.rdata).unwrap() else {
            unreachable!()
        };
        assert_eq!(next.to_name(), nsecs[(i + 1) % nsecs.len()].owner);
        assert_eq!(rr.ttl, 1_800);
    }
    assert!(!nsecs.is_empty());
}

// RFC 4035 §2.3; RFC 4592 §2.2.2; RFC 7129 §5: ENTs exist but own no NSEC.
#[test]
fn nsec_chain_omits_wildcard_and_plain_empty_nonterminals() {
    let path =
        std::env::temp_dir().join(format!("pharos-sign-wildcard-ent-{}", std::process::id()));
    std::fs::write(
            &path,
            "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n@ IN NS ns.\nleaf.* IN A 192.0.2.1\na.b IN A 192.0.2.2\n",
        )
        .unwrap();
    let apex: Name = "miek.nl.".parse().unwrap();
    let records = sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).unwrap();
    std::fs::remove_file(path).unwrap();
    for owner in ["*.miek.nl.", "b.miek.nl."] {
        let owner: Name = owner.parse().unwrap();
        assert!(
            !records
                .iter()
                .any(|rr| { rr.owner == owner && matches!(rr.rtype, Type::NSEC | Type::RRSIG) })
        );
    }
    for owner in ["leaf.*.miek.nl.", "a.b.miek.nl."] {
        let owner: Name = owner.parse().unwrap();
        assert!(
            records
                .iter()
                .any(|rr| rr.owner == owner && rr.rtype == Type::NSEC)
        );
    }
}

#[test]
fn replaces_existing_signatures_and_dnskeys() {
    let apex: Name = "miek.nl.".parse().unwrap();
    let records = sign(
        &apex,
        &fixture("file/coredns-miek-signed.zone"),
        &[key()],
        1_700_000_000,
        0,
        0,
    )
    .unwrap();
    assert_eq!(
        records.iter().filter(|r| r.rtype == Type::DNSKEY).count(),
        1
    );
    for rr in records.iter().filter(|r| r.rtype == Type::RRSIG) {
        assert_eq!(rr.rdata[2], 15);
    }
}

#[test]
fn invalid_zone_path_returns_error() {
    let apex: Name = "miek.nl.".parse().unwrap();
    assert!(
        sign(
            &apex,
            &fixture("file/missing.zone"),
            &[key()],
            1_700_000_000,
            0,
            0
        )
        .is_err()
    );
}

#[test]
fn rejects_a_zone_whose_soa_owner_differs_from_origin() {
    let apex: Name = "example.org.".parse().unwrap();
    assert!(
        sign(
            &apex,
            &fixture("file/coredns-miek.zone"),
            &[key()],
            1_700_000_000,
            0,
            0,
        )
        .is_err()
    );
}

#[test]
fn coredns_nsec_chain_includes_delegation_but_not_glue() {
    let apex: Name = "miek.nl.".parse().unwrap();
    let records = sign(
        &apex,
        &fixture("sign/db.miek.nl_ns"),
        &[key()],
        1_700_000_000,
        0,
        0,
    )
    .unwrap();
    let child: Name = "child.miek.nl.".parse().unwrap();
    let nsec = records
        .iter()
        .find(|rr| rr.owner == child && rr.rtype == Type::NSEC)
        .unwrap();
    let Rdata::Nsec { next, bitmap } = Rdata::parse(Type::NSEC, &nsec.rdata).unwrap() else {
        panic!("expected NSEC")
    };
    assert_eq!(next.to_name().to_string(), "www.miek.nl.");
    assert_eq!(nsec.ttl, 1800);
    let nsec = pharos_dnssec::denial::Nsec {
        owner: child.clone(),
        next: next.to_name(),
        bitmap: bitmap.to_vec(),
    };
    for kind in [Type::NS, Type::DS, Type::RRSIG, Type::NSEC] {
        assert!(nsec.bitmap_contains(kind));
    }
    assert!(!nsec.bitmap_contains(Type::A));
    assert!(!nsec.bitmap_contains(Type::AAAA));
    assert_eq!(
        records
            .iter()
            .filter(|rr| rr.owner == child && rr.rtype == Type::RRSIG)
            .count(),
        2
    );
    assert!(
        !records
            .iter()
            .any(|rr| rr.owner.to_string() == "ns.child.miek.nl." && rr.rtype == Type::RRSIG)
    );
}

#[test]
fn coredns_signs_apex_only_and_sets_key_ttl() {
    let path = std::env::temp_dir().join(format!("pharos-sign-apex-{}", std::process::id()));
    std::fs::write(
        &path,
        "$TTL 30M\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n IN NS ns.\n",
    )
    .unwrap();
    let apex: Name = "miek.nl.".parse().unwrap();
    let records = sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).unwrap();
    std::fs::remove_file(path).unwrap();
    let nsec = records.iter().find(|rr| rr.rtype == Type::NSEC).unwrap();
    assert!(
        matches!(Rdata::parse(Type::NSEC, &nsec.rdata).unwrap(), Rdata::Nsec { next, .. } if next.to_name() == apex)
    );
    assert_eq!(
        records
            .iter()
            .find(|rr| rr.rtype == Type::DNSKEY)
            .unwrap()
            .ttl,
        1800
    );
    assert!(records.iter().any(|rr| rr.rtype == Type::RRSIG
        && rr.rdata.starts_with(&Type::DNSKEY.0.to_be_bytes())
        && rr.ttl == 1800));
}

#[test]
fn apex_ns_signature_and_nsec_use_their_required_ttls() {
    let path = std::env::temp_dir().join(format!("pharos-sign-ttls-{}", std::process::id()));
    std::fs::write(
        &path,
        "$TTL 1H\n$ORIGIN miek.nl.\n@ 3600 IN SOA ns. host. (1 4H 1H 7D 4H)\n@ 900 IN NS ns.\n",
    )
    .unwrap();
    let apex: Name = "miek.nl.".parse().unwrap();
    let records = sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).unwrap();
    std::fs::remove_file(path).unwrap();
    let ns_signature = records
        .iter()
        .find(|rr| rr.rtype == Type::RRSIG && rr.rdata.starts_with(&Type::NS.0.to_be_bytes()))
        .unwrap();
    assert_eq!(ns_signature.ttl, 900);
    assert!(
        records
            .iter()
            .filter(|rr| rr.rtype == Type::NSEC)
            .all(|rr| rr.ttl == 3600)
    );
}

#[test]
fn mixed_ttl_rrset_uses_minimum_for_records_and_signature() {
    let path = std::env::temp_dir().join(format!("pharos-sign-mixed-ttl-{}", std::process::id()));
    std::fs::write(
            &path,
            "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n@ IN NS ns.\nwww 900 IN A 192.0.2.1\nwww 300 IN A 192.0.2.2\n",
        )
        .unwrap();
    let apex: Name = "miek.nl.".parse().unwrap();
    let records = sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).unwrap();
    std::fs::remove_file(path).unwrap();
    let owner: Name = "www.miek.nl.".parse().unwrap();
    assert!(
        records
            .iter()
            .filter(|rr| rr.owner == owner && rr.rtype == Type::A)
            .all(|rr| rr.ttl == 300)
    );
    let signature = records
        .iter()
        .find(|rr| rr.owner == owner && rr.rtype == Type::RRSIG)
        .unwrap();
    assert_eq!(signature.ttl, 300);
    assert!(matches!(
        Rdata::parse(Type::RRSIG, &signature.rdata).unwrap(),
        Rdata::Rrsig {
            type_covered: Type::A,
            original_ttl: 300,
            ..
        }
    ));
}

#[test]
fn delegation_ds_ttl_matches_parent_ns_ttl() {
    let path = std::env::temp_dir().join(format!("pharos-sign-ds-ttl-{}", std::process::id()));
    std::fs::write(
            &path,
            "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n@ IN NS ns.\ndeleg 600 IN NS ns.deleg.\ndeleg 1800 IN DS 34385 13 2 fc7397c77afbccb6742fcff19c7b1410d0044661e7085fc200ae1ab3d15a5842\nns.deleg 600 IN A 192.0.2.1\n",
        )
        .unwrap();
    let apex: Name = "miek.nl.".parse().unwrap();
    let records = sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).unwrap();
    std::fs::remove_file(path).unwrap();
    let child: Name = "deleg.miek.nl.".parse().unwrap();
    let ns_ttl = records
        .iter()
        .find(|rr| rr.owner == child && rr.rtype == Type::NS)
        .unwrap()
        .ttl;
    let ds_ttl = records
        .iter()
        .find(|rr| rr.owner == child && rr.rtype == Type::DS)
        .unwrap()
        .ttl;
    assert_eq!(ds_ttl, ns_ttl);
    assert_eq!(ns_ttl, 600);
}

#[test]
fn rejects_apex_ds_and_cname_mixed_data() {
    let path = std::env::temp_dir().join(format!("pharos-sign-invalid-{}", std::process::id()));
    let apex: Name = "miek.nl.".parse().unwrap();
    for text in [
        "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n@ IN NS ns.\n@ IN DS 34385 13 2 fc7397c77afbccb6742fcff19c7b1410d0044661e7085fc200ae1ab3d15a5842\n",
        "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n@ IN NS ns.\nalias IN CNAME target.\nalias IN A 192.0.2.1\n",
    ] {
        std::fs::write(&path, text).unwrap();
        assert!(sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).is_err());
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn preserves_and_signs_cds_and_cdnskey_delete_signals() {
    let path = std::env::temp_dir().join(format!("pharos-sign-delete-{}", std::process::id()));
    std::fs::write(
            &path,
            "$TTL 1H\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n@ IN NS ns.\n@ IN CDS 0 0 0 00\n@ IN CDNSKEY 0 3 0 AA==\n",
        )
        .unwrap();
    let apex: Name = "miek.nl.".parse().unwrap();
    let records = sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(
        records
            .iter()
            .any(|rr| rr.rtype == Type::CDS && rr.rdata == [0, 0, 0, 0, 0])
    );
    assert!(
        records
            .iter()
            .any(|rr| rr.rtype == Type::CDNSKEY && rr.rdata == [0, 0, 3, 0, 0])
    );
    assert!(
        records
            .iter()
            .any(|rr| rr.rtype == Type::RRSIG && rr.rdata.starts_with(&Type::CDS.0.to_be_bytes()))
    );
    assert!(
        records
            .iter()
            .any(|rr| rr.rtype == Type::RRSIG
                && rr.rdata.starts_with(&Type::CDNSKEY.0.to_be_bytes()))
    );
}

#[test]
fn coredns_rejects_bad_missing_soa_and_missing_apex_ns() {
    let path = std::env::temp_dir().join(format!("pharos-sign-bad-soa-{}", std::process::id()));
    let apex: Name = "example.org.".parse().unwrap();
    for text in [
        "$TTL 1M\n$ORIGIN example.org.\n@ IN SOA ns. admin. foobarbaz 1200 144 1814400 2h\n",
        "$TTL 1M\n$ORIGIN example.org.\nwww IN A 192.0.2.14\n",
    ] {
        std::fs::write(&path, text).unwrap();
        assert!(sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).is_err());
    }
    std::fs::write(
        &path,
        "$TTL 1M\n$ORIGIN example.org.\n@ IN SOA ns. admin. 1 1200 144 1814400 2h\n",
    )
    .unwrap();
    let error = sign(&apex, &path, &[key()], 1_700_000_000, 0, 0).unwrap_err();
    assert!(error.contains("Zone apex has no NS record"), "{error}");
    assert!(
        error.contains("add an NS RRset at the Zone apex"),
        "{error}"
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn coredns_without_keys_accepts_apex_only_zone() {
    let path = std::env::temp_dir().join(format!("pharos-sign-no-keys-{}", std::process::id()));
    std::fs::write(
        &path,
        "$TTL 30M\n$ORIGIN miek.nl.\n@ IN SOA ns. host. (1 4H 1H 7D 4H)\n IN NS ns.\n",
    )
    .unwrap();
    let apex: Name = "miek.nl.".parse().unwrap();
    let records = sign(&apex, &path, &[], 1_700_000_000, 0, 0).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(records.len(), 2);
    assert!(
        !records
            .iter()
            .any(|rr| matches!(rr.rtype, Type::NSEC | Type::RRSIG))
    );
}
