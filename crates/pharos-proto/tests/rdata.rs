#![forbid(unsafe_code)]

use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rdata, Section, Type};
use std::net::{Ipv4Addr, Ipv6Addr};

fn message(rtype: Type, data: &[u8]) -> Vec<u8> {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    builder
        .record(Section::Answer, root, rtype, Class::IN, 0, data)
        .unwrap();
    let _ = builder.finish();
    wire
}

#[test]
fn address_and_unknown_rdata_views_and_presentation() {
    for (rtype, data, expected, presentation) in [
        (
            Type::A,
            vec![192, 0, 2, 1],
            Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
            "192.0.2.1",
        ),
        (
            Type::AAAA,
            Ipv6Addr::LOCALHOST.octets().to_vec(),
            Rdata::Aaaa(Ipv6Addr::LOCALHOST),
            "::1",
        ),
    ] {
        let wire = message(rtype, &data);
        let record = Message::parse(&wire).unwrap().answers().next().unwrap();
        let actual = record.data().unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.to_string(), presentation);
    }
    let wire = message(Type(65000), &[0xab, 0xcd]);
    let record = Message::parse(&wire).unwrap().answers().next().unwrap();
    assert_eq!(record.data().unwrap().to_string(), "\\# 2 abcd");
}

#[test]
fn address_rdata_rejects_short_and_long_lengths() {
    for (rtype, valid) in [(Type::A, 4), (Type::AAAA, 16)] {
        for len in [0, valid - 1, valid + 1] {
            let wire = message(rtype, &vec![0; len]);
            assert!(
                Message::parse(&wire)
                    .unwrap()
                    .answers()
                    .next()
                    .unwrap()
                    .data()
                    .is_err()
            );
        }
    }
}

#[test]
fn address_and_unknown_data_write_through_record_hook() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    for data in [
        Rdata::A(Ipv4Addr::new(192, 0, 2, 1)),
        Rdata::Aaaa(Ipv6Addr::LOCALHOST),
        Rdata::Unknown(Type(65000), &[0xab, 0xcd]),
    ] {
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        assert!(
            builder
                .record_with(
                    Section::Answer,
                    root,
                    data.rtype(),
                    Class::IN,
                    0,
                    |writer| data.write(writer)
                )
                .unwrap()
        );
        let record = Message::parse(builder.finish())
            .unwrap()
            .answers()
            .next()
            .unwrap();
        assert_eq!(record.data().unwrap(), data);
    }
}

#[test]
fn compressed_ns_name_is_parsed_and_reencoded() {
    let name: Name = "example.com.".parse().unwrap();
    let name = NameRef::parse(name.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    builder.question(name, Type::NS, Class::IN).unwrap();
    builder
        .record_with(Section::Answer, name, Type::NS, Class::IN, 0, |writer| {
            writer.write_name(name)
        })
        .unwrap();
    let record = Message::parse(builder.finish())
        .unwrap()
        .answers()
        .next()
        .unwrap();
    assert_eq!(record.rdata, &[0xc0, 12]);
    let data = record.data().unwrap();
    assert_eq!(data.to_string(), "example.com.");
    assert_eq!(data.rtype(), Type::NS);
    let mut rebuilt = Vec::new();
    let mut builder = MessageBuilder::new(&mut rebuilt, 512, 0, 0).unwrap();
    builder.question(name, Type::NS, Class::IN).unwrap();
    builder
        .record_with(
            Section::Answer,
            name,
            data.rtype(),
            Class::IN,
            0,
            |writer| data.write(writer),
        )
        .unwrap();
    let record = Message::parse(builder.finish())
        .unwrap()
        .answers()
        .next()
        .unwrap();
    assert_eq!(record.rdata, &[0xc0, 12]);
    assert_eq!(record.data().unwrap(), data);
}

#[test]
fn names_cannot_cross_the_rdlength_boundary() {
    let wire = message(Type::NS, &[3, b'w', b'w']);
    assert!(
        Message::parse(&wire)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .data()
            .is_err()
    );
    let wire = message(Type::NS, &[0, 0]);
    assert!(
        Message::parse(&wire)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .data()
            .is_err()
    );
}

#[test]
fn mx_and_soa_parse_compressed_names_and_roundtrip() {
    let name: Name = "example.com.".parse().unwrap();
    let name = NameRef::parse(name.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut b = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    b.question(name, Type::SOA, Class::IN).unwrap();
    b.record_with(Section::Answer, name, Type::MX, Class::IN, 0, |w| {
        w.write_bytes(&10u16.to_be_bytes())?;
        w.write_name(name)
    })
    .unwrap();
    b.record_with(Section::Answer, name, Type::SOA, Class::IN, 0, |w| {
        w.write_name(name)?;
        w.write_name(name)?;
        for n in [1u32, 2, 3, 4, 5] {
            w.write_bytes(&n.to_be_bytes())?;
        }
        Ok(())
    })
    .unwrap();
    let message = Message::parse(b.finish()).unwrap();
    let data: Vec<_> = message.answers().map(|r| r.data().unwrap()).collect();
    assert_eq!(data[0].to_string(), "10 example.com.");
    assert_eq!(data[1].to_string(), "example.com. example.com. 1 2 3 4 5");
    let mut out = Vec::new();
    let mut b = MessageBuilder::new(&mut out, 512, 0, 0).unwrap();
    b.question(name, Type::SOA, Class::IN).unwrap();
    for item in &data {
        b.record_with(Section::Answer, name, item.rtype(), Class::IN, 0, |w| {
            item.write(w)
        })
        .unwrap();
    }
    let rebuilt = Message::parse(b.finish()).unwrap();
    assert_eq!(
        rebuilt
            .answers()
            .map(|r| r.data().unwrap())
            .collect::<Vec<_>>(),
        data
    );
}

#[test]
fn mx_and_soa_reject_truncated_fields_and_extra_bytes() {
    for (rtype, data) in [
        (Type::MX, vec![0, 1, 0]),
        (Type::SOA, [vec![0, 0], vec![0; 20]].concat()),
    ] {
        for len in 0..data.len() {
            let wire = message(rtype, &data[..len]);
            assert!(
                Message::parse(&wire)
                    .unwrap()
                    .answers()
                    .next()
                    .unwrap()
                    .data()
                    .is_err(),
                "{rtype}, {len}"
            );
        }
        let mut trailing = data;
        trailing.push(0);
        let wire = message(rtype, &trailing);
        assert!(
            Message::parse(&wire)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .data()
                .is_err()
        );
    }
}

#[test]
fn unsupported_name_bearing_rdata_cannot_be_relocated_as_opaque_bytes() {
    for rtype in [Type::MB, Type::SRV, Type::RRSIG, Type::SVCB, Type::TSIG] {
        let wire = message(rtype, &[0xc0, 12]);
        assert!(
            Message::parse(&wire)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .data()
                .is_err()
        );
        let root: Name = ".".parse().unwrap();
        let root = NameRef::parse(root.as_wire(), 0).unwrap();
        let mut out = Vec::new();
        let mut builder = MessageBuilder::new(&mut out, 512, 0, 0).unwrap();
        let data = Rdata::Unknown(rtype, &[0xc0, 12]);
        assert_eq!(
            builder.record_with(Section::Answer, root, rtype, Class::IN, 0, |w| data
                .write(w)),
            Err(pharos_proto::BuildError::InvalidRdata)
        );
    }
}

#[test]
fn opaque_data_cannot_impersonate_supported_name_records() {
    for rtype in [Type::NS, Type::CNAME, Type::PTR, Type::MX, Type::SOA] {
        let root: Name = ".".parse().unwrap();
        let root = NameRef::parse(root.as_wire(), 0).unwrap();
        let mut out = Vec::new();
        let mut builder = MessageBuilder::new(&mut out, 512, 0, 0).unwrap();
        let data = Rdata::Unknown(rtype, &[0xc0, 12]);
        assert_eq!(
            builder.record_with(Section::Answer, root, rtype, Class::IN, 0, |w| data
                .write(w)),
            Err(pharos_proto::BuildError::InvalidRdata)
        );
    }
}
