#![forbid(unsafe_code)]

use pharos_proto::{
    BuildError, Class, Message, MessageBuilder, Name, NameRef, Rdata, Section, Type,
};

#[test]
fn manually_constructed_invalid_txt_does_not_panic_when_printed() {
    assert_eq!(Rdata::Txt(b"\x02x").to_string(), "\\# 2 0278");
}

#[test]
fn caa_tag_follows_rfc_8659_syntax() {
    assert!(Rdata::parse(Type::CAA, &[0, 0]).is_err());
    assert!(Rdata::parse(Type::CAA, &[0, 3, b'a', b' ', b'b']).is_err());
    assert!(Rdata::parse(Type::CAA, &[0, 3, b'A', b'0', b'z']).is_ok());
    assert!(Rdata::parse(Type::CAA, &[1, 3, b'a', b'b', b'c']).is_ok());
    assert!(Rdata::parse(Type::CAA, b"\0\x10abcdefghijklmnop").is_ok());

    let name: Name = ".".parse().unwrap();
    let name = NameRef::parse(name.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    let data = Rdata::Caa {
        flags: 0,
        tag: b"bad tag",
        value: b"",
    };
    assert_eq!(
        builder.record_with(Section::Answer, name, Type::CAA, Class::IN, 0, |writer| {
            data.write(writer)
        }),
        Err(BuildError::InvalidRdata)
    );
}

#[test]
fn wire_relay_ignores_caa_and_dnskey_reserved_fields() {
    let root: Name = ".".parse().unwrap();
    let root_ref = NameRef::parse(root.as_wire(), 0).unwrap();
    for (rtype, data) in [
        (Type::DNSKEY, &[0, 2, 1, 8, 1, 2, 3][..]),
        (Type::CAA, &[1, 3, b'a', b'b', b'c'][..]),
    ] {
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        builder.question(root_ref, Type::A, Class::IN).unwrap();
        builder
            .record(Section::Answer, root_ref, rtype, Class::IN, 0, data)
            .unwrap();
        let _ = builder.finish();

        let received = Message::parse(&wire).unwrap();
        let original = received.answers().next().unwrap().data().unwrap();
        match original {
            Rdata::Dnskey {
                flags, protocol, ..
            } if rtype == Type::DNSKEY => {
                assert_eq!((flags, protocol), (2, 1));
            }
            Rdata::Caa { flags, .. } if rtype == Type::CAA => assert_eq!(flags, 1),
            _ => panic!("unexpected {rtype} RDATA"),
        }
        let relayed = received.with_question(&root, Type::A).unwrap();
        let relayed = Message::parse(&relayed).unwrap();
        match relayed.answers().next().unwrap().data().unwrap() {
            Rdata::Dnskey {
                flags, protocol, ..
            } if rtype == Type::DNSKEY => {
                assert_eq!((flags, protocol), (0, 1));
            }
            Rdata::Caa { flags, .. } if rtype == Type::CAA => assert_eq!(flags, 0),
            _ => panic!("unexpected {rtype} RDATA"),
        }
    }
}

#[test]
fn wire_parse_ignores_type0_bitmap_bits() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    for (rtype, bytes) in [
        (Type::NSEC, &[0, 0, 1, 0x80][..]),
        (Type::NSEC3, &[1, 0, 0, 1, 0, 1, 0, 0, 1, 0x80][..]),
        (Type::CSYNC, &[0, 0, 0, 0, 0, 2, 0, 1, 0x80][..]),
    ] {
        let data = Rdata::parse(rtype, bytes).unwrap();
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        builder
            .record_with(Section::Answer, root, rtype, Class::IN, 0, |writer| {
                data.write(writer)
            })
            .unwrap();
        let _ = builder.finish();
        assert_eq!(
            Message::parse(&wire)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rdata,
            bytes
        );
    }
    assert_eq!(
        Rdata::parse(Type::NSEC, &[0, 0, 1, 0x80])
            .unwrap()
            .to_string(),
        "."
    );
}

#[test]
fn wire_parse_ignores_nsec3param_flags_and_writer_clears_them() {
    let parsed = Rdata::parse(Type::NSEC3PARAM, &[1, 0xff, 0, 1, 0]).unwrap();
    assert!(matches!(parsed, Rdata::Nsec3param { flags: 0, .. }));
    let data = Rdata::Nsec3param {
        hash_algorithm: 1,
        flags: 0xff,
        iterations: 1,
        salt: &[],
    };
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    builder
        .record_with(
            Section::Answer,
            root,
            Type::NSEC3PARAM,
            Class::IN,
            0,
            |writer| data.write(writer),
        )
        .unwrap();
    let _ = builder.finish();
    assert_eq!(&wire[23..], &[1, 0, 0, 1, 0]);
}

#[test]
fn csync_accepts_soaminimum_flag_on_wire() {
    assert!(Rdata::parse(Type::CSYNC, &[0, 0, 0, 0, 0, 2, 0, 1, 0x40]).is_ok());
    assert!(Rdata::parse(Type::CSYNC, &[0, 0, 0, 0, 0, 4, 0, 1, 0x40]).is_err());
}
