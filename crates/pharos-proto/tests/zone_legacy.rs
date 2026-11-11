use pharos_proto::{
    Name, Type,
    zone::{ZoneParser, parse_rdata},
};

fn parse(ty: Type, fields: &[&str]) -> Result<Vec<u8>, String> {
    parse_rdata(ty, fields, &"example.".parse::<Name>().unwrap())
}

#[test]
fn legacy_names_and_preferences() {
    for ty in [
        Type::NSAP_PTR,
        Type::MR,
        Type::MB,
        Type::MG,
        Type::MF,
        Type::MD,
    ] {
        assert_eq!(
            parse(ty, &["host"]).unwrap(),
            b"\x04host\x07example\0",
            "{ty}"
        );
        assert!(parse(ty, &[]).is_err(), "{ty}");
    }
    for ty in [Type::RP, Type::MINFO, Type::TALINK] {
        assert_eq!(
            parse(ty, &["a", "."]).unwrap(),
            b"\x01a\x07example\0\0",
            "{ty}"
        );
        assert!(parse(ty, &["a"]).is_err(), "{ty}");
    }
    for ty in [Type::RT, Type::AFSDB, Type::KX, Type::LP] {
        assert_eq!(parse(ty, &["10", "."]).unwrap(), b"\0\x0a\0", "{ty}");
        assert!(parse(ty, &["65536", "."]).is_err(), "{ty}");
    }
    assert_eq!(
        parse(Type::PX, &["1", "a", "."]).unwrap(),
        b"\0\x01\x01a\x07example\0\0"
    );
    assert!(parse(Type::PX, &["1", "a"]).is_err());
}

#[test]
fn strings_and_coordinates() {
    assert_eq!(
        parse(Type::X25, &["311061700956"]).unwrap(),
        b"\x0c311061700956"
    );
    assert_eq!(parse(Type::ISDN, &["A"]).unwrap(), b"\x01A\0");
    assert_eq!(parse(Type::ISDN, &[r"A\032B"]).unwrap(), b"\x03A B\0");
    assert_eq!(parse(Type::ISDN, &["A B"]).unwrap(), b"\x01A\x01B");
    assert_eq!(
        parse(Type::ISDN, &["A", "B", "C"]).unwrap(),
        b"\x01A\x03B C"
    );
    assert_eq!(
        parse(Type::GPOS, &["-32.6882", "116.8652", "10.0"]).unwrap(),
        b"\x08-32.6882\x08116.8652\x0410.0"
    );
    assert!(parse(Type::GPOS, &["north", "0", "0"]).is_err());
    assert_eq!(
        parse(Type::UINFO, &["first", "discard"]).unwrap(),
        b"\x05first"
    );
    assert!(parse(Type::UINFO, &[]).is_err());
    for ty in [Type::AVC, Type::NINFO, Type::RESINFO] {
        assert_eq!(
            parse(ty, &["a", r"b\032c"]).unwrap(),
            b"\x01a\x03b c",
            "{ty}"
        );
        assert!(parse(ty, &[]).is_err(), "{ty}");
        assert_eq!(parse(ty, &[&"x".repeat(256)]).unwrap().len(), 258, "{ty}");
    }
}

#[test]
fn eui_ilnp_and_user_numbers() {
    assert_eq!(
        parse(Type::EUI48, &["00-00-5e-90-01-2a"]).unwrap(),
        [0, 0, 0x5e, 0x90, 1, 0x2a]
    );
    assert_eq!(
        parse(Type::EUI64, &["00-00-5e-ef-00-00-00-2a"]).unwrap(),
        [0, 0, 0x5e, 0xef, 0, 0, 0, 0x2a]
    );
    assert!(parse(Type::EUI48, &["00:00:5e:90:01:2a"]).is_err());
    for ty in [Type::NID, Type::L64] {
        assert_eq!(
            parse(ty, &["10", "0014:4fff:ff20:ee64"]).unwrap(),
            [0, 10, 0, 0x14, 0x4f, 0xff, 0xff, 0x20, 0xee, 0x64],
            "{ty}"
        );
        assert!(parse(ty, &["10", "::1"]).is_err(), "{ty}");
        assert_eq!(
            parse(ty, &["10", "0014:4fffXff20Yee64suffix"]).unwrap(),
            [0, 10, 0, 0x14, 0x4f, 0xff, 0xff, 0x20, 0xee, 0x64],
            "{ty}"
        );
    }
    assert_eq!(
        parse(Type::L32, &["10", "192.0.2.1"]).unwrap(),
        [0, 10, 192, 0, 2, 1]
    );
    assert_eq!(
        parse(Type::L32, &["1", "::ffff:192.0.2.1"]).unwrap(),
        [0, 1, 192, 0, 2, 1]
    );
    assert!(parse(Type::L32, &["1", "2001:db8::1"]).is_err());
    for ty in [Type::UID, Type::GID] {
        assert_eq!(parse(ty, &["4294967295"]).unwrap(), [255; 4], "{ty}");
        assert!(parse(ty, &["4294967296"]).is_err(), "{ty}");
    }
}

#[test]
fn legacy_security_and_opaque_data() {
    for ty in [Type::DHCID, Type::OPENPGPKEY] {
        assert_eq!(parse(ty, &["AQID", "BA=="]).unwrap(), [1, 2, 3, 4], "{ty}");
        assert!(parse(ty, &["!!!"]).is_err(), "{ty}");
    }
    for ty in [Type::EID, Type::NIMLOC] {
        assert_eq!(parse(ty, &["AB", "cd"]).unwrap(), [0xab, 0xcd], "{ty}");
        assert!(parse(ty, &["xyz"]).is_err(), "{ty}");
    }
    for ty in [Type::KEY, Type::RKEY] {
        assert_eq!(
            parse(ty, &["257", "3", "8", "AQID"]).unwrap(),
            [1, 1, 3, 8, 1, 2, 3],
            "{ty}"
        );
        assert_eq!(parse(ty, &["257", "3", "8"]).unwrap(), [1, 1, 3, 8], "{ty}");
    }
    for ty in [Type::DLV, Type::TA] {
        assert_eq!(
            parse(ty, &["1", "RSASHA256", "2", "AABB"]).unwrap(),
            [0, 1, 8, 2, 0xaa, 0xbb],
            "{ty}"
        );
        assert_eq!(parse(ty, &["1", "8", "2"]).unwrap(), [0, 1, 8, 2], "{ty}");
    }
    assert_eq!(
        parse(
            Type::SIG,
            &["A", "8", "2", "3600", "0", "1", "123", "example.", "AQID"]
        )
        .unwrap(),
        b"\0\x01\x08\x02\0\0\x0e\x10\0\0\0\0\0\0\0\x01\0\x7b\x07example\0\x01\x02\x03"
    );
    assert_eq!(
        parse(Type::NXT, &["next.", "A", "NS"]).unwrap(),
        b"\x04next\0\0\x01\x60"
    );
    assert_eq!(parse(Type::NXT, &["next."]).unwrap(), b"\x04next\0");
    assert_eq!(
        parse(
            Type::SIG,
            &["A", "8", "2", "3600", "0", "1", "123", "example."]
        )
        .unwrap(),
        b"\0\x01\x08\x02\0\0\x0e\x10\0\0\0\0\0\0\0\x01\0\x7b\x07example\0"
    );
}

#[test]
fn legacy_errors_point_to_the_offending_field() {
    for (input, line, column) in [
        ("a 60 PX 1 bad.. .\n", 1, 11),
        ("a 60 PX ( 1 good.\n  bad.. )\n", 2, 3),
        ("a 60 GPOS ( 1 2\n  bad )\n", 2, 3),
        ("a 60 KEY 257 bad 8 AQID\n", 1, 14),
        ("a 60 KEY 257 3 bad AQID\n", 1, 16),
        ("a 60 NXT next. A INVALID\n", 1, 18),
        ("a 60 DLV 1 8 2 AA ZZ\n", 1, 19),
        ("a 60 DHCID AQID !!!!\n", 1, 17),
        ("a 60 DHCID AQ== AAAA\n", 1, 12),
        ("a 60 NID 10 not-a-node\n", 1, 13),
        ("a 60 SIG A 8 bad 3600 0 1 123 example. AQID\n", 1, 14),
        ("a 60 SIG A 8 2 3600 0 1 123 example. AQ== AAAA\n", 1, 38),
    ] {
        let error = ZoneParser::new(input.as_bytes(), "example.".parse().unwrap(), "test")
            .next()
            .unwrap()
            .unwrap_err();
        assert_eq!(
            (error.line, error.column),
            (line, column),
            "{input}: {error}"
        );
    }
}
