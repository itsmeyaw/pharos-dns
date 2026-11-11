use pharos_dnssec::canonical::{CanonicalRecord, canonical_rdata, canonical_rr, signed_data};
use pharos_proto::{Class, Name, NameRef, Rdata, Type};

fn name(value: &str) -> Name {
    value.parse().unwrap()
}

fn name_ref(name: &Name) -> NameRef<'_> {
    NameRef::parse(name.as_wire(), 0).unwrap()
}

fn signature(signer: NameRef<'_>, labels: u8) -> Rdata<'_> {
    Rdata::Rrsig {
        type_covered: Type::A,
        algorithm: 15,
        labels,
        original_ttl: 300,
        expiration: 2,
        inception: 1,
        key_tag: 0x1234,
        signer,
        signature: &[99, 100],
    }
}

#[test]
fn canonical_name_order_matches_rfc_4034_example() {
    let text = [
        "example.",
        "a.example.",
        "yljkjljk.a.example.",
        "Z.a.example.",
        "zABC.a.EXAMPLE.",
        "z.example.",
        "\\001.z.example.",
        "*.z.example.",
        "\\200.z.example.",
    ];
    let expected: Vec<_> = text.iter().map(|value| name(value)).collect();
    let mut actual = expected.clone();
    actual.reverse();
    actual.sort();
    assert_eq!(actual, expected);
}

#[test]
fn canonical_rdata_expands_compressed_names_and_only_folds_domain_fields() {
    let wire = b"\x07EXAMPLE\x03COM\0\x00\x0a\x02Mx\xc0\x00";
    let exchange = NameRef::parse(wire, 15).unwrap();
    let mx = Rdata::Mx {
        preference: 10,
        exchange,
    };
    assert_eq!(
        canonical_rdata(&mx).unwrap(),
        b"\0\x0a\x02mx\x07example\x03com\0"
    );
    assert_eq!(
        canonical_rdata(&Rdata::Txt(b"\x03ABC")).unwrap(),
        b"\x03ABC"
    );
}

#[test]
fn canonical_dname_target_is_lowercase() {
    let target = name("Target.Example.");
    assert_eq!(
        canonical_rdata(&Rdata::Dname(name_ref(&target))).unwrap(),
        b"\x06target\x07example\0"
    );
}

#[test]
fn nsec_and_svcb_names_preserve_case() {
    let next = name("Next.Example.");
    let next = name_ref(&next);
    let nsec = Rdata::Nsec {
        next,
        bitmap: &[0, 1, 0x40],
    };
    assert_eq!(
        canonical_rdata(&nsec).unwrap(),
        b"\x04Next\x07Example\0\0\x01\x40"
    );
    let svcb = Rdata::Svcb {
        priority: 1,
        target: next,
        params: &[],
    };
    assert_eq!(
        canonical_rdata(&svcb).unwrap(),
        b"\0\x01\x04Next\x07Example\0"
    );
}

#[test]
fn canonical_rr_uses_original_ttl_and_expanded_lowercase_owner() {
    let owner = name("WWW.Example.");
    let data = Rdata::A("192.0.2.1".parse().unwrap());
    assert_eq!(
        canonical_rr(name_ref(&owner), Class::IN, 300, &data).unwrap(),
        b"\x03www\x07example\0\0\x01\0\x01\0\0\x01\x2c\0\x04\xc0\0\x02\x01"
    );
}

#[test]
fn signed_data_sorts_by_rdata_and_removes_duplicates() {
    let owner = name("WWW.Example.");
    let signer = name("Example.");
    let owner = name_ref(&owner);
    let a = Rdata::A("192.0.2.2".parse().unwrap());
    let b = Rdata::A("192.0.2.1".parse().unwrap());
    let records = [a, b, a].map(|data| CanonicalRecord {
        owner,
        class: Class::IN,
        data,
    });
    let mut expected =
        b"\0\x01\x0f\x02\0\0\x01\x2c\0\0\0\x02\0\0\0\x01\x12\x34\x07example\0".to_vec();
    expected.extend_from_slice(&canonical_rr(owner, Class::IN, 300, &b).unwrap());
    expected.extend_from_slice(&canonical_rr(owner, Class::IN, 300, &a).unwrap());
    assert_eq!(
        signed_data(&signature(name_ref(&signer), 2), &records).unwrap(),
        expected
    );
}

#[test]
fn signed_data_reconstructs_wildcard_and_rejects_mismatched_rrsets() {
    let expanded = name("A.B.Example.");
    let wildcard = name("*.Example.");
    let signer = name("Example.");
    let data = Rdata::A("192.0.2.1".parse().unwrap());
    let record = CanonicalRecord {
        owner: name_ref(&expanded),
        class: Class::IN,
        data,
    };
    let bytes = signed_data(&signature(name_ref(&signer), 1), &[record]).unwrap();
    let expected_rr = canonical_rr(name_ref(&wildcard), Class::IN, 300, &data).unwrap();
    assert!(bytes.ends_with(&expected_rr));
    assert!(signed_data(&signature(name_ref(&signer), 4), &[record]).is_err());
    let other = CanonicalRecord {
        owner: name_ref(&signer),
        ..record
    };
    assert!(signed_data(&signature(name_ref(&signer), 1), &[record, other]).is_err());
    assert!(signed_data(&signature(name_ref(&signer), 1), &[]).is_err());
}

#[test]
fn rejects_malformed_and_unsupported_rdata() {
    assert!(canonical_rdata(&Rdata::Txt(b"\x05x")).is_err());
    assert!(canonical_rdata(&Rdata::Unknown(Type::DNAME, b"\x01A\0")).is_err());
    assert!(canonical_rdata(&Rdata::Unknown(Type::A, &[1, 2, 3, 4])).is_err());
}

#[test]
fn rrset_order_uses_rdata_octets_not_rdlength() {
    let owner = name("Example.");
    let owner = name_ref(&owner);
    let high = Rdata::Unknown(Type(65000), &[2]);
    let low = Rdata::Unknown(Type(65000), &[1, 255]);
    let sig = Rdata::Rrsig {
        type_covered: Type(65000),
        algorithm: 15,
        labels: 1,
        original_ttl: 42,
        expiration: 2,
        inception: 1,
        key_tag: 3,
        signer: owner,
        signature: &[],
    };
    let records = [high, low].map(|data| CanonicalRecord {
        owner,
        class: Class::IN,
        data,
    });
    let bytes = signed_data(&sig, &records).unwrap();
    let mut suffix = canonical_rr(owner, Class::IN, 42, &low).unwrap();
    suffix.extend(canonical_rr(owner, Class::IN, 42, &high).unwrap());
    assert!(bytes.ends_with(&suffix));
}

#[test]
fn rrset_rejects_wrong_class_and_covered_type() {
    let owner = name("Example.");
    let owner = name_ref(&owner);
    let a = CanonicalRecord {
        owner,
        class: Class::IN,
        data: Rdata::A("192.0.2.1".parse().unwrap()),
    };
    let bad_class = CanonicalRecord {
        class: Class(3),
        ..a
    };
    let bad_type = CanonicalRecord {
        data: Rdata::Txt(b"\x01a"),
        ..a
    };
    assert!(signed_data(&signature(owner, 1), &[a, bad_class]).is_err());
    assert!(signed_data(&signature(owner, 1), &[a, bad_type]).is_err());
}

#[test]
fn canonical_rrsig_rdata_folds_signer_but_keeps_signature() {
    let signer = name("Example.");
    let encoded = canonical_rdata(&signature(name_ref(&signer), 1)).unwrap();
    assert!(encoded.ends_with(b"\x07example\0cd"));
}
