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
