#![forbid(unsafe_code)]

use pharos_proto::{BuildError, Class, MessageBuilder, Name, NameRef, Rdata, Section, Type};

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
fn wire_parse_ignores_reserved_caa_and_dnskey_fields() {
    let dnskey = Rdata::parse(Type::DNSKEY, &[0, 2, 1, 8, 1, 2, 3]).unwrap();
    let caa = Rdata::parse(Type::CAA, &[1, 3, b'a', b'b', b'c']).unwrap();
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    for (rtype, data) in [(Type::DNSKEY, dnskey), (Type::CAA, caa)] {
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        assert_eq!(
            builder.record_with(Section::Answer, root, rtype, Class::IN, 0, |writer| {
                data.write(writer)
            }),
            Err(BuildError::InvalidRdata)
        );
    }
}

#[test]
fn csync_accepts_soaminimum_flag_on_wire() {
    assert!(Rdata::parse(Type::CSYNC, &[0, 0, 0, 0, 0, 2, 0, 1, 0x40]).is_ok());
    assert!(Rdata::parse(Type::CSYNC, &[0, 0, 0, 0, 0, 4, 0, 1, 0x40]).is_err());
}
