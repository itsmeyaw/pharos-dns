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
fn txt_views_preserve_character_strings_and_miekg_presentation() {
    let bytes = b"\x03abc\x00\x05\"\\\n\x00\xff";
    let data = Rdata::parse(Type::TXT, bytes).unwrap();
    assert_eq!(data, Rdata::Txt(bytes));
    assert_eq!(
        data.txt_strings().unwrap().collect::<Vec<_>>(),
        vec![&b"abc"[..], &b""[..], &b"\"\\\n\x00\xff"[..]]
    );
    assert_eq!(data.to_string(), r#""abc" "" "\"\\\010\000\255""#);
    assert_eq!(data.rtype(), Type::TXT);
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let mut out = Vec::new();
    let mut builder = MessageBuilder::new(&mut out, 512, 0, 0).unwrap();
    builder
        .record_with(Section::Answer, root, Type::TXT, Class::IN, 0, |w| {
            data.write(w)
        })
        .unwrap();
    assert_eq!(
        Message::parse(builder.finish())
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata,
        bytes
    );
    for invalid in [&b""[..], &b"\x01"[..], &b"\x00\x02x"[..]] {
        assert!(Rdata::parse(Type::TXT, invalid).is_err());
    }
}

#[test]
fn hinfo_borrowed_fields_and_malformed_lengths() {
    let bytes = b"\x03CPU\x05a\"\\\x00\xff";
    let data = Rdata::parse(Type::HINFO, bytes).unwrap();
    assert_eq!(
        data,
        Rdata::Hinfo {
            cpu: b"CPU",
            os: b"a\"\\\x00\xff"
        }
    );
    assert_eq!(data.to_string(), r#""CPU" "a\"\\\000\255""#);
    assert_eq!(data.rtype(), Type::HINFO);
    for len in 0..bytes.len() {
        assert!(Rdata::parse(Type::HINFO, &bytes[..len]).is_err());
    }
    assert!(Rdata::parse(Type::HINFO, &[0, 0, 0]).is_err());
}

#[test]
fn caa_and_uri_fields_and_miekg_octet_escaping() {
    let caa = b"\x80\x05issuea\\046\\.\\255\\";
    let data = Rdata::parse(Type::CAA, caa).unwrap();
    assert_eq!(
        data,
        Rdata::Caa {
            flags: 128,
            tag: b"issue",
            value: b"a\\046\\.\\255\\"
        }
    );
    assert_eq!(data.to_string(), r#"128 issue "a.\.\255""#);
    let uri = b"\x00\x0a\x00\x01http://example/\\\"\x00";
    let data = Rdata::parse(Type::URI, uri).unwrap();
    assert_eq!(
        data,
        Rdata::Uri {
            priority: 10,
            weight: 1,
            target: b"http://example/\\\"\x00"
        }
    );
    assert_eq!(data.to_string(), r#"10 1 "http://example/\"\000""#);
    for invalid in [&b""[..], &b"\x00"[..], &b"\x00\x03ab"[..]] {
        assert!(Rdata::parse(Type::CAA, invalid).is_err());
    }
    for len in 0..4 {
        assert!(Rdata::parse(Type::URI, &uri[..len]).is_err());
    }
}

#[test]
fn text_record_types_roundtrip_and_borrow_message_data() {
    let cases: &[(Type, &[u8])] = &[
        (Type::TXT, b"\x00\x03abc"),
        (Type::HINFO, b"\x03cpu\x02os"),
        (Type::CAA, b"\x00\x05issueca.example"),
        (Type::URI, b"\x00\x01\x00\x02https://example/"),
    ];
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    for &(rtype, raw) in cases {
        let wire = message(rtype, raw);
        let record = Message::parse(&wire).unwrap().answers().next().unwrap();
        let data = record.data().unwrap();
        assert_eq!(data.rtype(), rtype);
        match data {
            Rdata::Txt(text) => assert!(std::ptr::eq(text.as_ptr(), record.rdata.as_ptr())),
            Rdata::Hinfo { cpu, .. } => {
                assert!(std::ptr::eq(cpu.as_ptr(), record.rdata[1..].as_ptr()))
            }
            Rdata::Caa { tag, .. } => {
                assert!(std::ptr::eq(tag.as_ptr(), record.rdata[2..].as_ptr()))
            }
            Rdata::Uri { target, .. } => {
                assert!(std::ptr::eq(target.as_ptr(), record.rdata[4..].as_ptr()))
            }
            _ => panic!("unexpected type"),
        }
        let mut out = Vec::new();
        let mut builder = MessageBuilder::new(&mut out, 512, 0, 0).unwrap();
        assert!(
            builder
                .record_with(Section::Answer, root, rtype, Class::IN, 0, |w| data
                    .write(w))
                .unwrap()
        );
        assert_eq!(
            Message::parse(builder.finish())
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rdata,
            raw
        );
    }
}

#[test]
fn text_builders_reject_unrepresentable_fields_and_opaque_impersonation() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let long = [0; 256];
    let invalid = [
        Rdata::Txt(b"\x02x"),
        Rdata::Txt(b""),
        Rdata::Hinfo {
            cpu: &long,
            os: b"",
        },
        Rdata::Hinfo {
            cpu: b"",
            os: &long,
        },
        Rdata::Caa {
            flags: 0,
            tag: &long,
            value: b"",
        },
        Rdata::Unknown(Type::TXT, b"\x00"),
        Rdata::Unknown(Type::HINFO, b"\x00\x00"),
        Rdata::Unknown(Type::CAA, b"\x00\x00"),
        Rdata::Unknown(Type::URI, b"\x00\x00\x00\x00"),
    ];
    for data in invalid {
        let mut out = Vec::new();
        let mut builder = MessageBuilder::new(&mut out, 1024, 0, 0).unwrap();
        assert_eq!(
            builder.record_with(Section::Answer, root, data.rtype(), Class::IN, 0, |w| data
                .write(w)),
            Err(pharos_proto::BuildError::InvalidRdata)
        );
        assert_eq!(Message::parse(builder.finish()).unwrap().answer_count(), 0);
    }
    let max = [b'x'; 255];
    for data in [
        Rdata::Hinfo { cpu: &max, os: b"" },
        Rdata::Caa {
            flags: 0,
            tag: &max,
            value: b"",
        },
    ] {
        let mut out = Vec::new();
        let mut builder = MessageBuilder::new(&mut out, 1024, 0, 0).unwrap();
        assert!(
            builder
                .record_with(Section::Answer, root, data.rtype(), Class::IN, 0, |w| data
                    .write(w))
                .unwrap()
        );
        assert_eq!(
            Message::parse(builder.finish())
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .data()
                .unwrap(),
            data
        );
    }
}

#[test]
fn miekg_wire_string_escape_cases() {
    // Adapted from miekg/dns parse_test.go TestDomainNameAndTXTEscapes.
    for (byte, text) in [
        (b'.', "."),
        (b'(', "("),
        (b')', ")"),
        (b';', ";"),
        (b' ', " "),
        (b'@', "@"),
        (b'"', "\\\""),
        (b'\\', "\\\\"),
        (9, "\\009"),
        (13, "\\013"),
        (10, "\\010"),
        (0, "\\000"),
        (255, "\\255"),
    ] {
        assert_eq!(
            Rdata::parse(Type::TXT, &[1, byte]).unwrap().to_string(),
            format!("\"{text}\"")
        );
    }
    assert!(Rdata::parse(Type::CAA, b"\x00\x03a\"\\x").is_err());
    assert_eq!(
        Rdata::parse(Type::URI, b"\x00\x00\x00\x00\\256\\\\\\.")
            .unwrap()
            .to_string(),
        r#"0 0 "\000\\\.""#
    );
    assert_eq!(
        Rdata::parse(Type::URI, b"\x00\x00\x00\x00")
            .unwrap()
            .to_string(),
        "0 0 \"\""
    );
}

#[test]
fn character_strings_cannot_extend_into_the_next_record() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    for (rtype, bytes) in [
        (Type::TXT, &b"\x04x"[..]),
        (Type::HINFO, &b"\x00\x04x"[..]),
        (Type::CAA, &b"\x00\x04x"[..]),
    ] {
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        builder
            .record(Section::Answer, root, rtype, Class::IN, 0, bytes)
            .unwrap();
        builder
            .record(Section::Answer, root, Type::A, Class::IN, 0, &[1, 2, 3, 4])
            .unwrap();
        let message = Message::parse(builder.finish()).unwrap();
        let mut records = message.answers();
        assert!(records.next().unwrap().data().is_err());
        assert!(records.next().unwrap().data().is_ok());
    }
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
    for rtype in [Type::MB, Type::RRSIG, Type::SVCB, Type::TSIG] {
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
    for rtype in [
        Type::NS,
        Type::CNAME,
        Type::PTR,
        Type::MX,
        Type::SOA,
        Type::SRV,
        Type::NAPTR,
    ] {
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
