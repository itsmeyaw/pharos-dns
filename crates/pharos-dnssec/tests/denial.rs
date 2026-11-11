use pharos_dnssec::denial::{
    BlackLieKind, DenialError, ZoneName, black_lie, nsec_chain, nsec3_chain, nsec3_hash,
    nsec3_hash_label, type_bitmap,
};
use pharos_proto::{Name, Rdata, Type};

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

fn entry(s: &str, types: &[Type]) -> ZoneName {
    ZoneName {
        name: name(s),
        types: types.to_vec(),
    }
}

#[test]
fn bitmap_windows_are_sorted_compact_and_deduplicated() {
    assert_eq!(
        type_bitmap(&[Type(257), Type::A, Type::RRSIG, Type::A, Type(65534)]).unwrap(),
        vec![
            0, 6, 0x40, 0, 0, 0, 0, 0x02, 1, 1, 0x40, 255, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02
        ]
    );
    assert_eq!(type_bitmap(&[Type::ANY]), Err(DenialError::InvalidType));
    assert_eq!(type_bitmap(&[Type(130)]), Err(DenialError::InvalidType));
    assert_eq!(
        type_bitmap(&[Type::NXNAME]).unwrap(),
        [0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80]
    );
}

#[test]
fn nsec_chain_uses_canonical_order_merges_names_and_wraps() {
    let chain = nsec_chain(
        &name("example."),
        &[
            entry("z.example.", &[Type::AAAA]),
            entry("EXAMPLE.", &[Type::SOA, Type::NS]),
            entry("A.example.", &[Type::A]),
            entry("a.EXAMPLE.", &[Type::TXT]),
        ],
    )
    .unwrap();
    assert_eq!(chain.len(), 3);
    assert_eq!(
        chain
            .iter()
            .map(|r| r.owner.canonical())
            .collect::<Vec<_>>(),
        ["example.", "a.example.", "z.example."]
    );
    assert_eq!(
        chain.iter().map(|r| r.next.canonical()).collect::<Vec<_>>(),
        ["a.example.", "z.example.", "example."]
    );
    assert_eq!(
        chain[1].bitmap,
        type_bitmap(&[Type::A, Type::TXT, Type::NSEC, Type::RRSIG]).unwrap()
    );
    assert!(matches!(chain[1].rdata(), Rdata::Nsec { .. }));
    assert_eq!(
        nsec_chain(&name("example."), &[entry("other.", &[Type::A])]),
        Err(DenialError::OutOfZone)
    );
    assert_eq!(
        nsec_chain(&name("example."), &[]),
        Err(DenialError::MissingApex)
    );
    assert_eq!(
        nsec_chain(&name("example."), &[entry("a.example.", &[Type::A])]),
        Err(DenialError::MissingApex)
    );
}

#[test]
fn black_lies_match_coredns_denial_and_referral() {
    let qname = name("www.example.");
    let lie = black_lie(&qname, &name("example."), Type::A, BlackLieKind::Negative).unwrap();
    assert_eq!(lie.owner, qname);
    assert_eq!(lie.next, name("\\000.www.example."));
    assert!(!lie.bitmap_contains(Type::A));
    assert!(lie.bitmap_contains(Type::NSEC));
    let referral = black_lie(
        &name("child.example."),
        &name("example."),
        Type::DS,
        BlackLieKind::Referral,
    )
    .unwrap();
    assert_eq!(referral.next, name("child\\000.example."));
    assert!(referral.bitmap_contains(Type::NS));
    assert!(!referral.bitmap_contains(Type::DS));
    let root = black_lie(&name("."), &name("."), Type::AAAA, BlackLieKind::Negative).unwrap();
    assert_eq!(root.next, name("\\000."));
    assert!(root.bitmap_contains(Type::SOA));
    assert!(!root.bitmap_contains(Type::AAAA));
}

#[test]
fn nsec3_hash_rfc5155_appendix_a_and_case_insensitive_wire() {
    let salt = [0xaa, 0xbb, 0xcc, 0xdd];
    for (owner, expected) in [
        ("example.", "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM"),
        ("a.example.", "35MTHGPGCU1QG68FAB165KLNSNK3DPVL"),
        ("*.w.example.", "R53BQ7CC2UVMUBFU5OCMM6PERS9TK9EN"),
    ] {
        assert_eq!(
            nsec3_hash_label(&nsec3_hash(&name(owner), 12, &salt).unwrap()),
            expected
        );
    }
    assert_eq!(
        nsec3_hash(&name("A.EXAMPLE."), 12, &salt),
        nsec3_hash(&name("a.example."), 12, &salt)
    );
    assert_eq!(
        nsec3_hash(&name("example."), 0, &[0; 256]),
        Err(DenialError::SaltTooLong)
    );
}

#[test]
fn nsec3_chain_has_empty_nonterminals_and_wraps_in_hash_order() {
    let apex = name("example.");
    let chain = nsec3_chain(
        &apex,
        &[
            entry(
                "example.",
                &[Type::SOA, Type::NS, Type::RRSIG, Type::NSEC3PARAM],
            ),
            entry("x.y.example.", &[Type::A, Type::RRSIG]),
            entry("X.Y.example.", &[Type::TXT]),
        ],
        0,
        &[],
    )
    .unwrap();
    assert_eq!(chain.len(), 3);
    assert!(chain.windows(2).all(|w| w[0].hash < w[1].hash));
    for i in 0..chain.len() {
        assert_eq!(chain[i].next_hash, chain[(i + 1) % chain.len()].hash);
        assert_eq!(
            chain[i].owner,
            name(&format!("{}.example.", nsec3_hash_label(&chain[i].hash)))
        );
        assert!(matches!(
            chain[i].rdata(),
            Rdata::Nsec3 {
                hash_algorithm: 1,
                flags: 0,
                ..
            }
        ));
    }
    let empty = chain
        .iter()
        .find(|r| r.original == name("y.example."))
        .unwrap();
    assert!(empty.bitmap.is_empty());
    let leaf = chain
        .iter()
        .find(|r| r.original == name("x.y.example."))
        .unwrap();
    assert_eq!(
        leaf.bitmap,
        type_bitmap(&[Type::A, Type::TXT, Type::RRSIG]).unwrap()
    );
    assert_eq!(
        nsec3_chain(&apex, &[entry("outside.", &[Type::A])], 0, &[]),
        Err(DenialError::OutOfZone)
    );
    assert_eq!(
        nsec3_chain(&apex, &[entry("x.example.", &[Type::A])], 0, &[]),
        Err(DenialError::MissingApex)
    );
}

#[test]
fn generated_denial_rdata_is_accepted_by_proto() {
    let records = nsec_chain(&name("example."), &[entry("example.", &[Type::SOA])]).unwrap();
    let mut wire = records[0].next.as_wire().to_vec();
    wire.extend_from_slice(&records[0].bitmap);
    assert_eq!(Rdata::parse(Type::NSEC, &wire).unwrap(), records[0].rdata());

    let records = nsec3_chain(
        &name("example."),
        &[entry("example.", &[Type::SOA])],
        12,
        &[1, 2],
    )
    .unwrap();
    let record = &records[0];
    let mut wire = vec![1, 0, 0, 12, 2, 1, 2, 20];
    wire.extend_from_slice(&record.next_hash);
    wire.extend_from_slice(&record.bitmap);
    assert_eq!(Rdata::parse(Type::NSEC3, &wire).unwrap(), record.rdata());
}

#[test]
fn black_lies_reject_overlong_synthetic_names() {
    let long_label = "a".repeat(63);
    let qname = name(&format!("{long_label}.example."));
    assert_eq!(
        black_lie(&qname, &name("example."), Type::DS, BlackLieKind::Referral),
        Err(DenialError::NameTooLong)
    );
    let long_apex = name(&format!(
        "{}.{}.{}.{}.",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    ));
    assert_eq!(
        black_lie(&long_apex, &long_apex, Type::A, BlackLieKind::Negative),
        Err(DenialError::NameTooLong)
    );
    assert_eq!(
        nsec3_chain(
            &long_apex,
            &[ZoneName {
                name: long_apex.clone(),
                types: vec![Type::SOA]
            }],
            0,
            &[]
        ),
        Err(DenialError::NameTooLong)
    );
}
