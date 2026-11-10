#![forbid(unsafe_code)]

use pharos_proto::{BuildError, Class, MessageBuilder, Name, NameRef, Rdata, Section, Type};

#[test]
fn zonemd_digest_must_have_at_least_twelve_octets() {
    for len in 0..12 {
        let mut bytes = vec![0; 6];
        bytes.extend(vec![0xab; len]);
        assert!(Rdata::parse(Type::ZONEMD, &bytes).is_err(), "{len}");
    }
    let mut bytes = vec![0; 6];
    bytes.extend([0xab; 12]);
    assert!(Rdata::parse(Type::ZONEMD, &bytes).is_ok());

    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let data = Rdata::Zonemd {
        serial: 0,
        scheme: 0,
        hash_algorithm: 0,
        digest: &[0; 11],
    };
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    assert_eq!(
        builder.record_with(
            Section::Answer,
            root,
            Type::ZONEMD,
            Class::IN,
            0,
            |writer| data.write(writer)
        ),
        Err(BuildError::InvalidRdata)
    );
}
