#![forbid(unsafe_code)]

use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rdata, Section, Type};

#[test]
fn unknown_type_and_rfc3597_presentation() {
    assert_eq!(Type(731).to_string(), "TYPE731");
    assert_eq!(Type(62347).to_string(), "TYPE62347");
    assert_eq!(Type(11).to_string(), "TYPE11");
    assert_eq!(Type(65534).to_string(), "TYPE65534");
    assert_eq!(Type(0).to_string(), "None");
    assert_eq!(Type(u16::MAX).to_string(), "Reserved");
    assert_eq!(
        Rdata::parse(Type(731), &[0xab, 0xcd, 0xef, 1, 0x23, 0x45])
            .unwrap()
            .to_string(),
        "\\# 6 abcdef012345"
    );
    assert_eq!(
        Rdata::parse(Type(62347), &[]).unwrap().to_string(),
        "\\# 0 "
    );
    for number in [0, 11, 731, 62347, 65534, u16::MAX] {
        let data = Rdata::parse(Type(number), &[0xc0, 0xff]).unwrap();
        assert_eq!(data, Rdata::Unknown(Type(number), &[0xc0, 0xff]));
        assert_eq!(data.rtype(), Type(number));
    }
}

#[test]
fn all_type_mnemonics_match_miekg_or_use_type_number() {
    let known: std::collections::BTreeMap<u16, &str> = include_str!("corpus/miekg-types.txt")
        .lines()
        .map(|line| {
            let (number, name) = line.split_once(' ').unwrap();
            (number.parse().unwrap(), name)
        })
        .collect();
    assert_eq!(known.len(), 88);
    for number in 0..=u16::MAX {
        let actual = Type(number).to_string();
        if let Some(name) = known.get(&number) {
            assert_eq!(actual, *name, "type {number}");
        } else {
            assert_eq!(actual, format!("TYPE{number}"));
        }
    }
}

#[test]
fn unknown_data_preserves_arbitrary_octets_on_relocation() {
    let bytes = &[0xc0, 0x0c, 0, 0xff];
    let data = Rdata::parse(Type(731), bytes).unwrap();
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    builder
        .record_with(Section::Answer, root, data.rtype(), Class::IN, 0, |w| {
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
