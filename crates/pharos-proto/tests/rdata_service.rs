#![forbid(unsafe_code)]

use pharos_proto::{
    BuildError, Class, Message, MessageBuilder, Name, NameRef, Rdata, Section, Type,
};

#[test]
fn srv_presentation_and_lengths() {
    let data = [0, 10, 0, 5, 0x21, 0x35, 0];
    assert_eq!(
        Rdata::parse(Type::SRV, &data).unwrap().to_string(),
        "10 5 8501 ."
    );
    for end in 0..data.len() {
        assert!(Rdata::parse(Type::SRV, &data[..end]).is_err(), "{end}");
    }
    let mut extra = data.to_vec();
    extra.push(0);
    assert!(Rdata::parse(Type::SRV, &extra).is_err());
}

#[test]
fn naptr_presentation_and_lengths() {
    let data = [
        0, 100, 0, 10, 1, b's', 7, b'S', b'I', b'P', b'+', b'D', b'2', b'U', 3, b'/', b'\\', b'"',
        0,
    ];
    assert_eq!(
        Rdata::parse(Type::NAPTR, &data).unwrap().to_string(),
        r#"100 10 "s" "SIP+D2U" "/\\\"" ."#
    );
    for end in 0..data.len() {
        assert!(Rdata::parse(Type::NAPTR, &data[..end]).is_err(), "{end}");
    }
    let mut extra = data.to_vec();
    extra.push(0);
    assert!(Rdata::parse(Type::NAPTR, &extra).is_err());
    for invalid in [
        &b"\x00\x00\x00\x00\x02a"[..],
        &b"\x00\x00\x00\x00\x00\x02a"[..],
        &b"\x00\x00\x00\x00\x00\x00\x02a"[..],
    ] {
        assert!(Rdata::parse(Type::NAPTR, invalid).is_err());
    }
}

#[test]
fn service_names_accept_pointers_but_are_written_uncompressed() {
    let owner: Name = "example.com.".parse().unwrap();
    let owner = NameRef::parse(owner.as_wire(), 0).unwrap();
    for (rtype, prefix) in [
        (Type::SRV, &[0, 1, 0, 2, 0, 53][..]),
        (Type::NAPTR, &[0, 1, 0, 2, 0, 0, 0][..]),
    ] {
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        builder.question(owner, rtype, Class::IN).unwrap();
        builder
            .record_with(Section::Answer, owner, rtype, Class::IN, 0, |writer| {
                writer.write_bytes(prefix)?;
                writer.write_name(owner)
            })
            .unwrap();
        let record = Message::parse(builder.finish())
            .unwrap()
            .answers()
            .next()
            .unwrap();
        assert_eq!(&record.rdata[prefix.len()..], &[0xc0, 12]);
        let data = record.data().unwrap();
        let mut rebuilt = Vec::new();
        let mut builder = MessageBuilder::new(&mut rebuilt, 512, 0, 0).unwrap();
        builder.question(owner, rtype, Class::IN).unwrap();
        builder
            .record_with(Section::Answer, owner, rtype, Class::IN, 0, |writer| {
                data.write(writer)
            })
            .unwrap();
        let record = Message::parse(builder.finish())
            .unwrap()
            .answers()
            .next()
            .unwrap();
        assert_eq!(&record.rdata[prefix.len()..], owner.to_name().as_wire());
        assert_eq!(record.data().unwrap().to_string(), data.to_string());
    }
}

#[test]
fn literal_rdata_names_are_available_for_later_compression() {
    let root: Name = ".".parse().unwrap();
    let target: Name = "ns.example.com.".parse().unwrap();
    let suffix: Name = "example.com.".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let target = NameRef::parse(target.as_wire(), 0).unwrap();
    let suffix = NameRef::parse(suffix.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    builder
        .record_with(Section::Answer, root, Type::SRV, Class::IN, 0, |writer| {
            writer.write_bytes(&[0; 6])?;
            writer.write_uncompressed_name(target)
        })
        .unwrap();
    builder
        .record_with(Section::Answer, root, Type::NS, Class::IN, 0, |writer| {
            writer.write_name(suffix)
        })
        .unwrap();
    builder
        .record_with(Section::Answer, root, Type::MX, Class::IN, 0, |writer| {
            writer.write_bytes(&[0; 2])?;
            writer.write_name(target)
        })
        .unwrap();
    let message = Message::parse(builder.finish()).unwrap();
    let srv = message.answers().next().unwrap();
    let mx = message.answers().nth(2).unwrap();
    let target_offset = u16::try_from(srv.rdata_offset + 6).unwrap();
    assert_eq!(&mx.rdata[2..], &(0xc000 | target_offset).to_be_bytes());
    assert_eq!(
        message.answers().nth(1).unwrap().rdata,
        &(0xc000 | (target_offset + 3)).to_be_bytes()
    );
}

// Adapted from miekg/dns v1.1.73 parse_test.go and dns_test.go.
#[test]
fn miekg_service_record_examples_roundtrip() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    for (order, preference, flags, services, replacement, expected) in [
        (
            100,
            50,
            "s",
            "z3950+I2L+I2C",
            "_z3950._tcp.gatech.edu.",
            "100 50 \"s\" \"z3950+I2L+I2C\" \"\" _z3950._tcp.gatech.edu.",
        ),
        (
            100,
            50,
            "s",
            "rcds+I2C",
            "_rcds._udp.gatech.edu.",
            "100 50 \"s\" \"rcds+I2C\" \"\" _rcds._udp.gatech.edu.",
        ),
        (
            100,
            50,
            "s",
            "http+I2L+I2C+I2R",
            "_http._tcp.gatech.edu.",
            "100 50 \"s\" \"http+I2L+I2C+I2R\" \"\" _http._tcp.gatech.edu.",
        ),
        (
            100,
            50,
            "se",
            "SIP+D2U",
            "_sip._udp.apple.com.",
            "100 50 \"se\" \"SIP+D2U\" \"\" _sip._udp.apple.com.",
        ),
        (
            90,
            50,
            "se",
            "SIP+D2T",
            "_sip._tcp.apple.com.",
            "90 50 \"se\" \"SIP+D2T\" \"\" _sip._tcp.apple.com.",
        ),
        (
            50,
            50,
            "se",
            "SIPS+D2T",
            "_sips._tcp.apple.com.",
            "50 50 \"se\" \"SIPS+D2T\" \"\" _sips._tcp.apple.com.",
        ),
    ] {
        let name: Name = replacement.parse().unwrap();
        let data = Rdata::Naptr {
            order,
            preference,
            flags: flags.as_bytes(),
            services: services.as_bytes(),
            regexp: b"",
            replacement: NameRef::parse(name.as_wire(), 0).unwrap(),
        };
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        assert!(
            builder
                .record_with(Section::Answer, root, Type::NAPTR, Class::IN, 0, |w| data
                    .write(w))
                .unwrap()
        );
        let record = Message::parse(builder.finish())
            .unwrap()
            .answers()
            .next()
            .unwrap();
        assert_eq!(record.data().unwrap().to_string(), expected);
        assert_eq!(record.data().unwrap().rtype(), Type::NAPTR);
    }
    for (priority, target) in [(0, "1.2.3.4."), (1, "45.45.45.45."), (2, "84.84.84.84.")] {
        let name: Name = target.parse().unwrap();
        let data = Rdata::Srv {
            priority,
            weight: 5,
            port: 8484,
            target: NameRef::parse(name.as_wire(), 0).unwrap(),
        };
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        assert!(
            builder
                .record_with(Section::Answer, root, Type::SRV, Class::IN, 0, |w| data
                    .write(w))
                .unwrap()
        );
        let parsed = Message::parse(builder.finish())
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .data()
            .unwrap();
        assert_eq!(parsed.to_string(), format!("{priority} 5 8484 {target}"));
        assert_eq!(parsed.rtype(), Type::SRV);
    }
}

#[test]
fn naptr_fields_borrow_input_and_enforce_character_string_limits() {
    let bytes = b"\x00\x01\x00\x02\x01a\x02bc\x03def\x00";
    let Rdata::Naptr {
        flags,
        services,
        regexp,
        ..
    } = Rdata::parse(Type::NAPTR, bytes).unwrap()
    else {
        panic!("expected NAPTR")
    };
    assert!(std::ptr::eq(flags.as_ptr(), bytes[5..].as_ptr()));
    assert!(std::ptr::eq(services.as_ptr(), bytes[7..].as_ptr()));
    assert!(std::ptr::eq(regexp.as_ptr(), bytes[10..].as_ptr()));
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let long = [b'x'; 256];
    let max = [b'x'; 255];
    for index in 0..3 {
        for (field, valid) in [(&max[..], true), (&long[..], false)] {
            let mut fields = [&b""[..]; 3];
            fields[index] = field;
            let data = Rdata::Naptr {
                order: 0,
                preference: 0,
                flags: fields[0],
                services: fields[1],
                regexp: fields[2],
                replacement: root,
            };
            let mut wire = Vec::new();
            let mut builder = MessageBuilder::new(&mut wire, 1024, 0, 0).unwrap();
            let result =
                builder.record_with(Section::Answer, root, Type::NAPTR, Class::IN, 0, |w| {
                    data.write(w)
                });
            if valid {
                assert_eq!(result, Ok(true));
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
            } else {
                assert_eq!(result, Err(BuildError::InvalidRdata));
                assert_eq!(Message::parse(builder.finish()).unwrap().answer_count(), 0);
            }
        }
    }
}

#[test]
fn name_must_end_within_rdata_not_in_next_record() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    for (rtype, prefix) in [(Type::SRV, &[0; 6][..]), (Type::NAPTR, &[0; 7][..])] {
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        builder
            .record(Section::Answer, root, rtype, Class::IN, 0, prefix)
            .unwrap();
        builder
            .record(
                Section::Answer,
                root,
                Type::A,
                Class::IN,
                0,
                &[127, 0, 0, 1],
            )
            .unwrap();
        assert!(
            Message::parse(builder.finish())
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
fn literal_name_offsets_are_rolled_back_on_error() {
    let root: Name = ".".parse().unwrap();
    let target: Name = "unique.example.".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let target = NameRef::parse(target.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    assert_eq!(
        builder.record_with(Section::Answer, root, Type::SRV, Class::IN, 0, |w| {
            w.write_uncompressed_name(target)?;
            Err(BuildError::InvalidRdata)
        }),
        Err(BuildError::InvalidRdata)
    );
    builder
        .record_with(Section::Answer, root, Type::NS, Class::IN, 0, |w| {
            w.write_name(target)
        })
        .unwrap();
    let record = Message::parse(builder.finish())
        .unwrap()
        .answers()
        .next()
        .unwrap();
    assert_eq!(record.rdata, target.to_name().as_wire());
}

#[test]
fn literal_name_obeys_message_size_limit() {
    let root: Name = ".".parse().unwrap();
    let target: Name = "unique.example.".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let target = NameRef::parse(target.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    builder.reserve(480).unwrap();
    assert!(
        !builder
            .record_with(Section::Answer, root, Type::SRV, Class::IN, 0, |w| {
                w.write_bytes(&[0; 6])?;
                w.write_uncompressed_name(target)
            })
            .unwrap()
    );
    let message = Message::parse(builder.finish()).unwrap();
    assert_eq!(message.answer_count(), 0);
    assert!(message.tc());
}
