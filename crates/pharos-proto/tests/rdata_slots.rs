#![forbid(unsafe_code)]

use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Section, Type};

#[test]
fn repeated_uncompressed_suffixes_do_not_exhaust_compression_slots() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 4096, 0, 0).unwrap();
    for index in 0..40 {
        let target: Name = format!("h{index}.svc.corp.example.").parse().unwrap();
        let target = NameRef::parse(target.as_wire(), 0).unwrap();
        builder
            .record_with(Section::Answer, root, Type::SRV, Class::IN, 0, |writer| {
                writer.write_bytes(&[0; 6])?;
                writer.write_uncompressed_name(target)
            })
            .unwrap();
    }
    let target: Name = "ns.fresh-zone.test.".parse().unwrap();
    let target = NameRef::parse(target.as_wire(), 0).unwrap();
    for _ in 0..2 {
        builder
            .record_with(Section::Answer, root, Type::NS, Class::IN, 0, |writer| {
                writer.write_name(target)
            })
            .unwrap();
    }
    let message = Message::parse(builder.finish()).unwrap();
    let first = message.answers().nth(40).unwrap();
    let second = message.answers().nth(41).unwrap();
    assert!(first.rdata.len() > 2);
    assert_eq!(second.rdata.len(), 2);
}
