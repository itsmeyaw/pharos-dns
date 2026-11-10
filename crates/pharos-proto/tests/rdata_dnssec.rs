#![forbid(unsafe_code)]

use pharos_proto::{
    BuildError, Class, Message, MessageBuilder, Name, NameRef, Rdata, Section, Type,
};
use proptest::prelude::*;

#[test]
fn dnssec_digest_and_key_presentations() {
    for rtype in [Type::DS, Type::CDS] {
        assert_eq!(
            Rdata::parse(rtype, &[0x12, 0x34, 8, 2, 0x12, 0xab])
                .unwrap()
                .to_string(),
            "4660 8 2 12AB"
        );
    }
    for rtype in [Type::DNSKEY, Type::CDNSKEY] {
        assert_eq!(
            Rdata::parse(rtype, &[1, 0, 3, 8, 1, 2, 3])
                .unwrap()
                .to_string(),
            "256 3 8 AQID"
        );
    }
}

#[test]
fn dnssec_signature_dates_and_bitmap_presentation() {
    let signature = [
        0, 1, 8, 2, 0, 0, 0x0e, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0, 1, 2, 3,
    ];
    assert_eq!(
        Rdata::parse(Type::RRSIG, &signature).unwrap().to_string(),
        "A 8 2 3600 19700101000000 19700101000000 4660 . AQID"
    );
    assert_eq!(
        Rdata::parse(Type::NSEC, &[0, 0, 1, 0x40])
            .unwrap()
            .to_string(),
        ". A"
    );
    assert_eq!(
        Rdata::parse(Type::NSEC3PARAM, &[1, 0, 0, 10, 0])
            .unwrap()
            .to_string(),
        "1 0 10 -"
    );
    assert_eq!(
        Rdata::parse(
            Type::NSEC3,
            &[1, 0, 0, 10, 2, 0x0a, 0x0b, 1, 0x66, 0, 1, 0x40]
        )
        .unwrap()
        .to_string(),
        "1 0 10 0A0B CO A"
    );
}

#[test]
fn dnssec_rejects_truncated_fixed_fields_and_malformed_bitmaps() {
    for rtype in [Type::DS, Type::CDS, Type::DNSKEY, Type::CDNSKEY] {
        for len in 0..4 {
            assert!(
                Rdata::parse(rtype, &[0; 4][..len]).is_err(),
                "{rtype} {len}"
            );
        }
    }
    for bytes in [
        &[0, 0][..],
        &[0, 1, 0][..],
        &[0, 0, 1, 0x40, 0, 1, 0x40][..],
        &[0, 1, 1, 0x40, 0, 1, 0x40][..],
    ] {
        assert!(Rdata::parse(Type::NSEC, bytes).is_err(), "{bytes:02x?}");
    }
    assert!(Rdata::parse(Type::NSEC3PARAM, &[1, 0, 0, 0, 2, 1]).is_err());
    assert!(Rdata::parse(Type::NSEC3, &[1, 0, 0, 0, 0, 2, 1]).is_err());
}

#[test]
fn dnssec_rejects_noncanonical_bitmap_windows() {
    for bitmap in [&[0, 1, 0][..], &[0, 2, 0x40, 0][..], &[1, 1, 0][..]] {
        let mut nsec = vec![0];
        nsec.extend_from_slice(bitmap);
        assert!(Rdata::parse(Type::NSEC, &nsec).is_err());
        let mut nsec3 = vec![1, 0, 0, 0, 0, 0];
        nsec3.extend_from_slice(bitmap);
        assert!(Rdata::parse(Type::NSEC3, &nsec3).is_err());
    }
}

#[test]
fn bitmap_boundaries_and_rdata_name_boundaries() {
    for bitmap in [&[0, 0][..], &[0, 33][..], &[0, 2, 0x40][..], &[0][..]] {
        let mut nsec = vec![0];
        nsec.extend_from_slice(bitmap);
        assert!(Rdata::parse(Type::NSEC, &nsec).is_err());
        let mut nsec3 = vec![0; 6];
        nsec3.extend_from_slice(bitmap);
        assert!(Rdata::parse(Type::NSEC3, &nsec3).is_err());
    }
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    for (rtype, prefix) in [(Type::RRSIG, &[0; 18][..]), (Type::NSEC, &[][..])] {
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        builder
            .record(Section::Answer, root, rtype, Class::IN, 0, prefix)
            .unwrap();
        builder
            .record(
                Section::Answer,
                root,
                Type::A,
                Class::IN,
                0,
                &[127, 0, 0, 1],
            )
            .unwrap();
        assert!(
            Message::parse(builder.finish())
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .data()
                .is_err()
        );
    }
}

proptest! {
    #[test]
    fn arbitrary_dnssec_data_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        for rtype in [Type::DS, Type::CDS, Type::DNSKEY, Type::CDNSKEY, Type::RRSIG, Type::NSEC, Type::NSEC3, Type::NSEC3PARAM] {
            if let Ok(data) = Rdata::parse(rtype, &bytes) {
                let _ = data.to_string();
            }
        }
    }
}

#[test]
fn lengths_empty_tails_and_encodings() {
    for (rtype, min) in [(Type::RRSIG, 19), (Type::NSEC3, 6), (Type::NSEC3PARAM, 5)] {
        for len in 0..min {
            assert!(Rdata::parse(rtype, &vec![0; len]).is_err(), "{rtype} {len}");
        }
        assert!(Rdata::parse(rtype, &vec![0; min]).is_ok());
    }
    for (tail, expected) in [
        (&b""[..], ""),
        (&b"a"[..], "YQ=="),
        (&b"ab"[..], "YWI="),
        (&b"abc"[..], "YWJj"),
        (&b"abcdef"[..], "YWJjZGVm"),
    ] {
        let mut wire = vec![0, 0, 3, 8];
        wire.extend_from_slice(tail);
        assert_eq!(
            Rdata::parse(Type::DNSKEY, &wire).unwrap().to_string(),
            format!("0 3 8 {expected}")
        );
    }
    assert!(Rdata::parse(Type::NSEC, &[0]).is_err());
    assert_eq!(
        Rdata::parse(Type::NSEC3, &[0; 6]).unwrap().to_string(),
        "0 0 0 - "
    );
    assert!(Rdata::parse(Type::NSEC3PARAM, &[0, 0, 0, 0, 0, 0]).is_err());
}

// Adapted from miekg/dns v1.1.73 parse_test.go and msg_helpers_test.go.
#[test]
fn miekg_dnssec_examples() {
    let mut ds = vec![0x9e, 0xf4, 12, 3];
    ds.extend_from_slice(&[
        34, 38, 26, 139, 14, 13, 121, 145, 131, 227, 94, 36, 226, 173, 107, 181, 133, 51, 203, 167,
        227, 177, 77, 101, 158, 156, 160, 155, 32, 113, 57, 143,
    ]);
    assert_eq!(
        Rdata::parse(Type::DS, &ds).unwrap().to_string(),
        "40692 12 3 22261A8B0E0D799183E35E24E2AD6BB58533CBA7E3B14D659E9CA09B2071398F"
    );
    let salt = [0x30, 0x92, 0x3c, 0x44, 0xc6, 0xcb, 0xbb, 0x8f];
    let mut param = vec![1, 0, 0, 5, 8];
    param.extend_from_slice(&salt);
    assert_eq!(
        Rdata::parse(Type::NSEC3PARAM, &param).unwrap().to_string(),
        "1 0 5 30923C44C6CBBB8F"
    );
    let mut nsec3 = vec![1, 1, 0, 5, 8];
    nsec3.extend_from_slice(&salt);
    nsec3.push(20);
    nsec3.extend_from_slice(&[
        202, 64, 216, 6, 142, 70, 156, 171, 129, 96, 9, 130, 58, 199, 77, 128, 57, 137, 131, 170,
    ]);
    nsec3.extend_from_slice(&[0, 7, 34, 0, 0x80, 0, 0, 2, 0x90]);
    assert_eq!(
        Rdata::parse(Type::NSEC3, &nsec3).unwrap().to_string(),
        "1 1 5 30923C44C6CBBB8F P90DG1KE8QEAN0B01613LHQDG0SOJ0TA NS SOA TXT RRSIG DNSKEY NSEC3PARAM"
    );
    let mut no_types = vec![1, 0, 0, 0, 0, 20];
    no_types.extend_from_slice(&[
        33, 49, 21, 104, 87, 154, 193, 38, 223, 248, 175, 83, 8, 118, 63, 229, 2, 224, 251, 234,
    ]);
    assert_eq!(
        Rdata::parse(Type::NSEC3, &no_types).unwrap().to_string(),
        "1 0 0 - 44OHAQ2NJB0IDNVOLT9GGTHVSK1E1UVA"
    );
    let mut nsec = b"\x03www\x06dnssex\x02nl\0".to_vec();
    nsec.extend_from_slice(&[0, 6, 64, 0, 0, 0, 0, 3, 255, 32]);
    nsec.extend_from_slice(&[0; 31]);
    nsec.push(2);
    assert_eq!(
        Rdata::parse(Type::NSEC, &nsec).unwrap().to_string(),
        "www.dnssex.nl. A RRSIG NSEC TYPE65534"
    );
    for (timestamp, expected) in [
        (0u32, "19700101000000"),
        (1 << 31, "20380119031408"),
        (u32::MAX, "21060207062815"),
    ] {
        let mut sig = vec![0; 19];
        sig[8..12].copy_from_slice(&timestamp.to_be_bytes());
        assert!(
            Rdata::parse(Type::RRSIG, &sig)
                .unwrap()
                .to_string()
                .contains(expected)
        );
    }
    let simple = Rdata::parse(Type::NSEC, &[0, 0, 1, 64]).unwrap();
    assert_eq!(simple.to_string(), ". A");
    let multiple = Rdata::parse(Type::NSEC, &[0, 0, 7, 34, 0, 0, 0, 0, 2, 144]).unwrap();
    assert_eq!(multiple.to_string(), ". NS SOA RRSIG DNSKEY NSEC3PARAM");
}

#[test]
fn builder_roundtrips_and_relocates_compressed_names() {
    let owner: Name = "example.com.".parse().unwrap();
    let owner = NameRef::parse(owner.as_wire(), 0).unwrap();
    for (rtype, prefix, suffix) in [
        (Type::RRSIG, &[0; 18][..], &[1, 2][..]),
        (Type::NSEC, &[][..], &[0, 1, 0x40][..]),
    ] {
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        builder.question(owner, rtype, Class::IN).unwrap();
        builder
            .record_with(Section::Answer, owner, rtype, Class::IN, 0, |w| {
                w.write_bytes(prefix)?;
                w.write_name(owner)?;
                w.write_bytes(suffix)
            })
            .unwrap();
        let record = Message::parse(builder.finish())
            .unwrap()
            .answers()
            .next()
            .unwrap();
        assert_eq!(&record.rdata[prefix.len()..prefix.len() + 2], &[0xc0, 12]);
        let data = record.data().unwrap();
        let mut rebuilt = Vec::new();
        let mut builder = MessageBuilder::new(&mut rebuilt, 512, 0, 0).unwrap();
        builder.question(owner, rtype, Class::IN).unwrap();
        builder
            .record_with(Section::Answer, owner, rtype, Class::IN, 0, |w| {
                data.write(w)
            })
            .unwrap();
        let record = Message::parse(builder.finish())
            .unwrap()
            .answers()
            .next()
            .unwrap();
        assert_eq!(
            &record.rdata[prefix.len()..prefix.len() + owner.wire_len()],
            owner.to_name().as_wire()
        );
        assert_eq!(record.data().unwrap().to_string(), data.to_string());
    }
    for (rtype, bytes) in [
        (Type::DS, &b"\x12\x34\x08\x02\xaa"[..]),
        (Type::CDS, &b"\x12\x34\x08\x02\xaa"[..]),
        (Type::DNSKEY, &b"\x01\x00\x03\x08\x01"[..]),
        (Type::CDNSKEY, &b"\x01\x00\x03\x08\x01"[..]),
        (
            Type::NSEC3,
            &b"\x01\x00\x00\x05\x01\xaa\x01\xbb\x00\x01\x40"[..],
        ),
        (Type::NSEC3PARAM, &b"\x01\x00\x00\x05\x01\xaa"[..]),
    ] {
        let data = Rdata::parse(rtype, bytes).unwrap();
        assert_eq!(data.rtype(), rtype);
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        builder
            .record_with(Section::Answer, owner, rtype, Class::IN, 0, |w| {
                data.write(w)
            })
            .unwrap();
        let record = Message::parse(builder.finish())
            .unwrap()
            .answers()
            .next()
            .unwrap();
        assert_eq!(record.rdata, bytes);
        assert_eq!(record.data().unwrap(), data);
    }
}

#[test]
fn builder_rejects_invalid_typed_values_and_unknown_impersonation() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let too_long = [0; 256];
    for data in [
        Rdata::Nsec {
            next: root,
            bitmap: &[0, 1, 0],
        },
        Rdata::Nsec3 {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: &[],
            next_owner: &[],
            bitmap: &[0, 1, 0],
        },
        Rdata::Nsec3param {
            hash_algorithm: 1,
            flags: 0,
            iterations: 0,
            salt: &too_long,
        },
    ] {
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        assert_eq!(
            builder.record_with(Section::Answer, root, data.rtype(), Class::IN, 0, |w| data
                .write(w)),
            Err(BuildError::InvalidRdata)
        );
    }
    for rtype in [
        Type::DS,
        Type::CDS,
        Type::DNSKEY,
        Type::CDNSKEY,
        Type::RRSIG,
        Type::NSEC,
        Type::NSEC3,
        Type::NSEC3PARAM,
    ] {
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        assert_eq!(
            builder.record_with(Section::Answer, root, rtype, Class::IN, 0, |w| {
                Rdata::Unknown(rtype, &[]).write(w)
            }),
            Err(BuildError::InvalidRdata)
        );
    }
}
