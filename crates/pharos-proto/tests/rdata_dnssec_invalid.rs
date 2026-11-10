#![forbid(unsafe_code)]

use pharos_proto::{BuildError, Class, MessageBuilder, Name, NameRef, Rdata, Section, Type};

#[test]
fn manually_constructed_invalid_nsec_bitmaps_do_not_panic_when_printed() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let bitmap = &[0, 1, 0];
    let nsec = Rdata::Nsec { next: root, bitmap };
    let nsec3 = Rdata::Nsec3 {
        hash_algorithm: 1,
        flags: 0,
        iterations: 0,
        salt: &[],
        next_owner: &[],
        bitmap,
    };
    assert_eq!(nsec.to_string(), ". <invalid bitmap>");
    assert_eq!(nsec3.to_string(), "1 0 0 -  <invalid bitmap>");
}

#[test]
fn nsec_requires_a_bitmap_but_nsec3_allows_an_empty_nonterminal() {
    assert!(Rdata::parse(Type::NSEC, &[0]).is_err());
    assert!(Rdata::parse(Type::NSEC3, &[0; 6]).is_ok());
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let data = Rdata::Nsec {
        next: root,
        bitmap: &[],
    };
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    assert_eq!(
        builder.record_with(Section::Answer, root, Type::NSEC, Class::IN, 0, |writer| {
            data.write(writer)
        }),
        Err(BuildError::InvalidRdata)
    );
}
