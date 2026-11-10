#![forbid(unsafe_code)]
#![recursion_limit = "512"]

use pharos_proto::{Message, NameRef, NameWirePart, Type};

fn message(rtype: Type, data: &[u8]) -> Vec<u8> {
    let mut wire = vec![
        0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1, 0xc0, 12,
    ];
    wire.extend_from_slice(&rtype.0.to_be_bytes());
    wire.extend_from_slice(&[0, 1, 0, 0, 0, 30]);
    wire.extend_from_slice(&(data.len() as u16).to_be_bytes());
    wire.extend_from_slice(data);
    wire
}

#[test]
fn finds_all_receivable_compressed_name_layouts() {
    let pointer = [0xc0, 12];
    for rtype in [
        Type::NS,
        Type::CNAME,
        Type::PTR,
        Type::MD,
        Type::MF,
        Type::MB,
        Type::MG,
        Type::MR,
    ] {
        let wire = message(rtype, &pointer);
        let message = Message::parse(&wire).unwrap();
        let names = message
            .answers()
            .next()
            .unwrap()
            .compressible_names()
            .unwrap();
        assert_eq!(names.into_iter().flatten().count(), 1, "{rtype}");
    }
    for rtype in [Type::MX, Type::AFSDB, Type::RT] {
        let wire = message(rtype, &[0, 1, 0xc0, 12]);
        let message = Message::parse(&wire).unwrap();
        assert_eq!(
            message
                .answers()
                .next()
                .unwrap()
                .compressible_names()
                .unwrap()
                .into_iter()
                .flatten()
                .count(),
            1,
            "{rtype}"
        );
    }
    for rtype in [Type::MINFO, Type::RP] {
        let wire = message(rtype, &[0xc0, 12, 0xc0, 12]);
        let message = Message::parse(&wire).unwrap();
        assert_eq!(
            message
                .answers()
                .next()
                .unwrap()
                .compressible_names()
                .unwrap()
                .into_iter()
                .flatten()
                .count(),
            2,
            "{rtype}"
        );
    }
    for (rtype, data, expected) in [
        (Type::SOA, [&[0xc0, 12, 0xc0, 12][..], &[0; 20]].concat(), 2),
        (Type::PX, vec![0, 1, 0xc0, 12, 0xc0, 12], 2),
        (Type::SIG, [&[0; 18][..], &[0xc0, 12, 9]].concat(), 1),
        (Type::NXT, vec![0xc0, 12, 1], 1),
        (Type::SRV, vec![0, 0, 0, 0, 0, 1, 0xc0, 12], 1),
        (Type::NAPTR, vec![0, 0, 0, 0, 0, 0, 0, 0xc0, 12], 1),
        (Type::TXT, vec![0xc0, 12], 0),
    ] {
        let wire = message(rtype, &data);
        let message = Message::parse(&wire).unwrap();
        let names = message
            .answers()
            .next()
            .unwrap()
            .compressible_names()
            .unwrap();
        assert_eq!(names.iter().flatten().count(), expected, "{rtype}");
        for name in names.into_iter().flatten() {
            assert_eq!(name.to_string(), "a.", "{rtype}");
        }
    }
}

#[test]
fn rejects_name_fields_crossing_rdata_and_walks_pointer_chains() {
    let mut wire = message(Type::MX, &[0, 1, 0xc0]);
    wire.push(12);
    let parsed = Message::parse(&wire).unwrap();
    assert!(
        parsed
            .answers()
            .next()
            .unwrap()
            .compressible_names()
            .is_err()
    );
    let name = NameRef::parse(&wire, 19).unwrap();
    assert_eq!(
        name.wire_parts().collect::<Vec<_>>(),
        [
            NameWirePart::Pointer {
                offset: 19,
                target: 12
            },
            NameWirePart::Label { offset: 12, len: 2 },
            NameWirePart::Root { offset: 14 }
        ]
    );
    let chain = [1, b'a', 0, 0xc0, 0, 0xc0, 3];
    assert_eq!(
        NameRef::parse(&chain, 5)
            .unwrap()
            .wire_parts()
            .collect::<Vec<_>>(),
        [
            NameWirePart::Pointer {
                offset: 5,
                target: 3
            },
            NameWirePart::Pointer {
                offset: 3,
                target: 0
            },
            NameWirePart::Label { offset: 0, len: 2 },
            NameWirePart::Root { offset: 2 },
        ]
    );
}
