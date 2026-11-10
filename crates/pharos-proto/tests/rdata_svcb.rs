#![forbid(unsafe_code)]

use pharos_proto::{
    BuildError, Class, Message, MessageBuilder, Name, NameRef, Rdata, Section, Type,
};

fn one_param(key: u16, value: &[u8]) -> Vec<u8> {
    let mut wire = vec![0, 1, 0];
    wire.extend_from_slice(&key.to_be_bytes());
    wire.extend_from_slice(&u16::try_from(value.len()).unwrap().to_be_bytes());
    wire.extend_from_slice(value);
    wire
}

#[test]
fn svcb_and_https_print_named_and_unknown_keys() {
    let wire = [
        0, 16, 3, b'f', b'o', b'o', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o',
        b'm', 0, 0, 3, 0, 2, 0, 53, 2, 155, 0, 5, b'h', b'e', b'l', b'l', b'o',
    ];
    for rtype in [Type::SVCB, Type::HTTPS] {
        let data = Rdata::parse(rtype, &wire).unwrap();
        assert_eq!(data.rtype(), rtype);
        assert_eq!(
            data.to_string(),
            "16 foo.example.com. port=\"53\" key667=\"hello\""
        );
    }
}

#[test]
fn svcb_rejects_bad_parameter_framing_and_order() {
    for params in [
        &[0, 3, 0][..],
        &[0, 3, 0, 2, 1][..],
        &[0, 3, 0, 2, 0, 53, 0, 3, 0, 2, 0, 53][..],
        &[0, 3, 0, 2, 0, 53, 0, 2, 0, 0][..],
        &[0xff, 0xff, 0, 0][..],
    ] {
        let mut wire = vec![0, 1, 0];
        wire.extend_from_slice(params);
        for rtype in [Type::SVCB, Type::HTTPS] {
            assert!(Rdata::parse(rtype, &wire).is_err(), "{rtype} {params:02x?}");
        }
    }
}

#[test]
fn svcb_parameter_presentations_follow_miekg() {
    let ipv6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    for (key, value, expected) in [
        (0, &[0, 1, 0, 3][..], "1 . mandatory=\"alpn,port\""),
        (
            1,
            &[2, b'h', b'2', 3, b'f', b',', b'x'][..],
            r#"1 . alpn="h2,f\\\044x""#,
        ),
        (2, &[][..], "1 . no-default-alpn=\"\""),
        (3, &[0, 53][..], "1 . port=\"53\""),
        (4, &[192, 0, 2, 1][..], "1 . ipv4hint=\"192.0.2.1\""),
        (5, &[1, 2, 3][..], "1 . ech=\"AQID\""),
        (6, &ipv6[..], "1 . ipv6hint=\"2001:db8::1\""),
        (
            7,
            b"/dns-query{?dns}".as_slice(),
            "1 . dohpath=\"/dns-query{?dns}\"",
        ),
        (8, &[][..], "1 . ohttp=\"\""),
    ] {
        assert_eq!(
            Rdata::parse(Type::SVCB, &one_param(key, value))
                .unwrap()
                .to_string(),
            expected,
            "key {key}"
        );
    }
}

#[test]
fn svcb_rejects_invalid_parameter_values() {
    for (key, value) in [
        (0, &[][..]),
        (0, &[1][..]),
        (0, &[0, 0][..]),
        (0, &[0xff, 0xff][..]),
        (0, &[0, 1, 0, 1][..]),
        (0, &[0, 3, 0, 1][..]),
        (1, &[][..]),
        (1, &[0][..]),
        (1, &[2, b'h'][..]),
        (2, &[1][..]),
        (3, &[1][..]),
        (4, &[][..]),
        (4, &[1, 2, 3][..]),
        (6, &[][..]),
        (6, &[0; 15][..]),
        (8, &[1][..]),
    ] {
        assert!(
            Rdata::parse(Type::SVCB, &one_param(key, value)).is_err(),
            "key {key}"
        );
    }
}

// Adapted from miekg/dns v1.1.73 parse_test.go and svcb_test.go.
#[test]
fn miekg_parameter_examples() {
    for (key, value, expected) in [
        (0, &b"\x00\x01\xfd\xe8"[..], r#"mandatory="alpn,key65000""#),
        (1, &b"\x02h2\x03h2c"[..], r#"alpn="h2,h2c""#),
        (
            1,
            &b"\x08f\\oo,bar\x02h2"[..],
            r#"alpn="f\\\092oo\\\044bar,h2""#,
        ),
        (1, &b"\x04\xfa\"; "[..], r#"alpn="\250\"\;\ ""#),
        (
            4,
            &[3, 4, 3, 2, 1, 1, 1, 1][..],
            r#"ipv4hint="3.4.3.2,1.1.1.1""#,
        ),
        (
            6,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1][..],
            r#"ipv6hint="::c000:201""#,
        ),
        (5, &b"aGVsbG8="[..], r#"ech="YUdWc2JHOD0=""#),
        (5, &[1][..], r#"ech="AQ==""#),
        (65000, &b"4 3"[..], r#"key65000="4\ 3""#),
        (65001, &b"\" "[..], r#"key65001="\"\ ""#),
        (
            65004,
            &[254, 32, 32, 30, 0, b';', b'\\'][..],
            r#"key65004="\254\ \ \030\000\;\\""#,
        ),
    ] {
        assert_eq!(
            Rdata::parse(Type::SVCB, &one_param(key, value))
                .unwrap()
                .to_string(),
            format!("1 . {expected}")
        );
    }
}

#[test]
fn compressed_targets_and_borrowed_parameters_are_relocated() {
    let owner: Name = "example.com.".parse().unwrap();
    let owner = NameRef::parse(owner.as_wire(), 0).unwrap();
    for rtype in [Type::SVCB, Type::HTTPS] {
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        builder.question(owner, rtype, Class::IN).unwrap();
        builder
            .record_with(Section::Answer, owner, rtype, Class::IN, 0, |w| {
                w.write_bytes(&[0, 0])?;
                w.write_name(owner)?;
                w.write_bytes(&[0, 2, 0, 0, 0, 3, 0, 2, 1, 187])
            })
            .unwrap();
        let message = Message::parse(builder.finish()).unwrap();
        let record = message.answers().next().unwrap();
        assert_eq!(&record.rdata[2..4], &[0xc0, 12]);
        let data = record.data().unwrap();
        let params = data.svc_params().unwrap();
        assert!(std::ptr::eq(
            params.as_bytes().as_ptr(),
            record.rdata[4..].as_ptr()
        ));
        let pairs: Vec<_> = params.iter().collect();
        assert_eq!(pairs, [(2, &b""[..]), (3, &b"\x01\xbb"[..])]);
        assert!(std::ptr::eq(
            pairs[1].1.as_ptr(),
            record.rdata[12..].as_ptr()
        ));
        let mut rebuilt = Vec::new();
        let mut builder = MessageBuilder::new(&mut rebuilt, 512, 0, 0).unwrap();
        builder.question(owner, rtype, Class::IN).unwrap();
        builder
            .record_with(Section::Answer, owner, rtype, Class::IN, 0, |w| {
                data.write(w)
            })
            .unwrap();
        let message = Message::parse(builder.finish()).unwrap();
        let record = message.answers().next().unwrap();
        assert_eq!(
            &record.rdata[2..2 + owner.to_name().as_wire().len()],
            owner.to_name().as_wire()
        );
        assert_eq!(record.data().unwrap().to_string(), data.to_string());
    }
}

#[test]
fn rejects_malformed_values_and_handles_public_variants_safely() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let mapped = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 192, 0, 2, 1];
    assert!(Rdata::parse(Type::HTTPS, &one_param(6, &mapped)).is_err());
    assert!(Rdata::parse(Type::SVCB, &one_param(1, &[1, b'h', 0])).is_err());
    for bad in [&b"\x00"[..], &b"\x00\x03\x00\x01\x00"[..]] {
        let data = Rdata::Svcb {
            priority: 1,
            target: root,
            params: bad,
        };
        assert!(data.svc_params().is_none());
        assert!(!data.to_string().is_empty());
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        assert_eq!(
            builder.record_with(Section::Answer, root, Type::SVCB, Class::IN, 0, |w| data
                .write(w)),
            Err(BuildError::InvalidRdata)
        );
    }
    for rtype in [Type::SVCB, Type::HTTPS] {
        let mut wire = Vec::new();
        let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
        let data = Rdata::Unknown(rtype, b"\x00\x01\x00");
        assert_eq!(
            builder.record_with(Section::Answer, root, rtype, Class::IN, 0, |w| data
                .write(w)),
            Err(BuildError::InvalidRdata)
        );
    }
}

#[test]
fn target_cannot_extend_past_rdata_boundary() {
    let root: Name = ".".parse().unwrap();
    let root = NameRef::parse(root.as_wire(), 0).unwrap();
    let mut wire = Vec::new();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0).unwrap();
    builder
        .record(Section::Answer, root, Type::HTTPS, Class::IN, 0, &[0, 1])
        .unwrap();
    builder
        .record(Section::Answer, root, Type::A, Class::IN, 0, &[1, 2, 3, 4])
        .unwrap();
    let message = Message::parse(builder.finish()).unwrap();
    assert!(message.answers().next().unwrap().data().is_err());
}

#[test]
fn cross_key_consistency_is_left_to_consumers() {
    for rtype in [Type::SVCB, Type::HTTPS] {
        let mut wire = one_param(0, &[0, 1]); // mandatory lists an absent ALPN
        wire[1] = 0; // AliasMode retains parameters for the caller to ignore.
        assert_eq!(
            Rdata::parse(rtype, &wire).unwrap().to_string(),
            "0 . mandatory=\"alpn\""
        );
        assert!(Rdata::parse(rtype, &one_param(2, &[])).is_ok());
    }
}
