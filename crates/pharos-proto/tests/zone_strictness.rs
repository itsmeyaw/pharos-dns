use pharos_proto::{Name, Type, zone::parse_rdata};

fn parse(rtype: Type, fields: &[&str]) -> Result<Vec<u8>, pharos_proto::zone::RdataParseError> {
    parse_rdata(rtype, fields, &"example.".parse::<Name>().unwrap())
}

#[test]
fn base64_matches_go_wire_decoding() {
    for (text, bytes) in [
        ("AQ==", vec![1]),
        ("AR==", vec![1]),
        ("AQI=", vec![1, 2]),
        ("AQJ=", vec![1, 2]),
    ] {
        let mut expected = vec![1, 1, 3, 8];
        expected.extend(bytes);
        assert_eq!(
            parse(Type::DNSKEY, &["257", "3", "8", text]).unwrap(),
            expected,
            "{text}"
        );
    }
    for text in ["A", "A===", "AQ=", "AQ==AA==", "!!!="] {
        assert!(
            parse(Type::DNSKEY, &["257", "3", "8", text]).is_err(),
            "{text}"
        );
    }
}

#[test]
fn zonemd_packs_unknown_hash_digest_lengths() {
    assert_eq!(
        parse(Type::ZONEMD, &["1", "2", "3", "AABB"]).unwrap(),
        [0, 0, 0, 1, 2, 3, 0xaa, 0xbb]
    );
    assert_eq!(
        parse(Type::ZONEMD, &["1", "2", "3"]).unwrap(),
        [0, 0, 0, 1, 2, 3]
    );
    assert!(parse(Type::ZONEMD, &["1", "2", "3", "ABC"]).is_err());
}

#[test]
fn nsec_requires_a_type_bitmap() {
    assert!(parse(Type::NSEC, &["next."]).is_err());
}

#[test]
fn nsec3_short_hash_keeps_miekg_fixed_length_octet() {
    assert_eq!(
        parse(Type::NSEC3, &["1", "0", "1", "-", "00", "A"]).unwrap(),
        [1, 0, 0, 1, 0, 1, 0, 0, 1, 0x40]
    );
}

#[test]
fn rrsig_dates_use_miekg_serial_arithmetic() {
    let result = parse(
        Type::RRSIG,
        &[
            "A",
            "8",
            "2",
            "3600",
            "19691231235959",
            "22000101000000",
            "123",
            "example.",
            "AQID",
        ],
    )
    .unwrap();
    assert_eq!(
        &result[8..16],
        &[0xff, 0xff, 0xff, 0xff, 0xb0, 0x9e, 0x19, 0x00]
    );
}

#[test]
fn generic_known_types_follow_wire_layouts() {
    for (rtype, length, data, expected) in [
        (Type::A, "4", "7f000001", vec![127, 0, 0, 1]),
        (Type::NS, "3", "016100", vec![1, b'a', 0]),
        (
            Type::NXT,
            "10",
            "046e6578740060000002",
            b"\x04next\0\x60\0\0\x02".to_vec(),
        ),
        (
            Type::ZONEMD,
            "18",
            "000000010203000000000000000000000000",
            vec![0, 0, 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            Type::URI,
            "10",
            "00010002615c30333262",
            b"\x00\x01\x00\x02a\\032b".to_vec(),
        ),
        (Type::SVCB, "3", "000100", vec![0, 1, 0]),
        (
            Type::OPT,
            "9",
            "000800050001010080",
            vec![0, 8, 0, 5, 0, 1, 1, 0, 128],
        ),
        (
            Type::OPT,
            "7",
            "000f00030001ff",
            vec![0, 15, 0, 3, 0, 1, 0xff],
        ),
        (Type(65000), "1", "ff", vec![255]),
    ] {
        assert_eq!(
            parse(rtype, &[r"\#", length, data]).unwrap(),
            expected,
            "{rtype} {data}"
        );
    }
    for (rtype, length, data) in [
        (Type::A, "0", ""),
        (Type::NSAP, "2", "4701"),
        (Type::NSEC, "6", "046e65787400"),
        (Type::NXT, "7", "046e6578740060"),
        (Type::NXT, "11", "046e657874006000000200"),
        (Type::URI, "4", "00000000"),
        (Type::A, "5", "7f000001ff"),
        (Type::MX, "2", "000a"),
        (Type::DS, "2", "0001"),
        (Type::SOA, "3", "00c000"),
        (Type::SOA, "3", "c00200"),
        (Type::A, "3", "7f0000"),
        (Type::AAAA, "4", "7f000001"),
        (Type::MX, "1", "00"),
        (Type::NS, "2", "0161"),
        (Type::NS, "4", "c0020000"),
        (Type::TXT, "2", "0261"),
        (Type(45), "4", "000100aa"),
        (Type(55), "5", "01010001aa"),
        (Type(42), "4", "00032000"),
        (Type(41), "2", "0001"),
        (Type::OPT, "8", "0008000400000000"),
    ] {
        assert!(
            parse(rtype, &[r"\#", length, data]).is_err(),
            "{rtype} {data}"
        );
    }
    assert!(parse(Type::URI, &["0", "0", ""]).is_err());
    assert!(parse(Type(65000), &[r"\#", "1", "A", "A"]).is_err());
}

#[test]
fn generic_nsec_rejects_an_all_zero_bitmap_window() {
    // RFC 4034 §4.1.2: A type-bitmap window cannot be all zeroes.
    assert!(parse(Type::NSEC, &[r"\#", "9", "046e65787400000100"]).is_err());
}

#[test]
fn generic_opt_preserves_zero_keepalive() {
    assert_eq!(
        parse(Type::OPT, &[r"\#", "6", "000b00020000"]).unwrap(),
        [0, 11, 0, 2, 0, 0]
    );
}

#[test]
fn generic_character_strings_reject_truncated_octets() {
    for rtype in [Type::HINFO, Type::X25, Type::ISDN, Type::GPOS, Type::UINFO] {
        assert!(parse(rtype, &[r"\#", "1", "c0"]).is_err(), "{rtype}");
    }
}

#[test]
fn generic_tsig_rejects_short_rdata_and_opt_expire_is_preserved() {
    assert!(parse(Type::TSIG, &[r"\#", "0"]).is_err());
    assert!(parse(Type::TSIG, &[r"\#", "1", "00"]).is_err());
    assert_eq!(
        parse(Type::OPT, &[r"\#", "8", "0009000400000001"]).unwrap(),
        [0, 9, 0, 4, 0, 0, 0, 1]
    );
}

#[test]
fn txt_chunks_and_hinfo_fields_match_miekg() {
    let long = "a".repeat(256);
    let mut expected = vec![255];
    expected.extend(vec![b'a'; 255]);
    expected.extend([1, b'a']);
    assert_eq!(parse(Type::TXT, &[&long]).unwrap(), expected);
    let escaped = format!("{}\\032b", "a".repeat(254));
    let mut expected = vec![255];
    expected.extend(vec![b'a'; 254]);
    expected.extend([b' ', 1, b'b']);
    assert_eq!(parse(Type::TXT, &[&escaped]).unwrap(), expected);
    assert!(parse(Type::HINFO, &[]).is_err());
    assert!(parse(Type::HINFO, &["cpu"]).is_err());
    assert!(parse(Type::HINFO, &["cpu os extra"]).is_err());
    assert!(parse(Type::HINFO, &["cpu", "unix", "linux"]).is_err());
    assert_eq!(
        parse(Type::HINFO, &[r"cpu\032arch", "os"]).unwrap(),
        b"\x08cpu arch\x02os"
    );
}

#[test]
fn caa_tag_and_value_follow_rfc_syntax() {
    assert!(parse(Type::CAA, &["0", "bad-tag", "x"]).is_err());
    assert_eq!(
        parse(Type::CAA, &["128", "tbs", "critical"]).unwrap(),
        b"\x80\x03tbscritical"
    );
    assert!(parse(Type::CAA, &["256", "issue", "x"]).is_err());
    assert!(parse(Type::CAA, &["1", "issue", "x"]).is_err());
    assert!(parse(Type::CAA, &["0", "issue", &"x".repeat(256)]).is_ok());
    assert!(parse(Type::CAA, &["0", "issue", "x", "y"]).is_err());
}

#[test]
fn txt_decimal_escapes_require_one_octet() {
    for input in [r"abc\32xyz", r"abc\02xyz", r"abc\03xyz"] {
        let plain = input.replace('\\', "");
        let mut expected = vec![plain.len() as u8];
        expected.extend(plain.bytes());
        assert_eq!(parse(Type::TXT, &[input]).unwrap(), expected);
    }
    assert!(parse(Type::TXT, &[r"\256\999"]).is_err());
}

#[test]
fn dnssec_algorithm_mnemonics() {
    for rtype in [Type::DS, Type::CDS] {
        assert_eq!(
            parse(rtype, &["1", "rsasha256", "0", "AB"]).unwrap(),
            [0, 1, 8, 0, 0xab]
        );
        assert_eq!(
            parse(rtype, &["1", "RSASHA256", "0"]).unwrap(),
            [0, 1, 8, 0]
        );
    }
    let fields = ["A", "RSASHA256", "2", "3600", "0", "1", "123", ".", "AQID"];
    assert_eq!(parse(Type::RRSIG, &fields).unwrap()[2], 8);
    let lower = ["A", "rsasha256", "2", "3600", "0", "1", "123", ".", "AQID"];
    assert!(parse(Type::RRSIG, &lower).is_err());
}

#[test]
fn svcb_enforces_cross_parameter_rules() {
    // RFC 9460 §7.1.1: alpn must list at least one protocol ID.
    assert!(parse(Type::SVCB, &["1", ".", "alpn="]).is_err());
    assert!(parse(Type::SVCB, &["1", ".", "mandatory=port"]).is_err());
    assert!(parse(Type::SVCB, &["1", ".", "mandatory=alpn,alpn"]).is_err());
    assert!(parse(Type::SVCB, &["1", ".", "mandatory=unknown"]).is_err());
    assert!(parse(Type::HTTPS, &["1", ".", "no-default-alpn"]).is_err());
    assert!(parse(Type::SVCB, &["1", ".", "no-default-alpn", "alpn=h2"]).is_ok());
    assert!(parse(Type::SVCB, &["1", ".", "\\044port=443"]).is_err());
    assert!(parse(Type::SVCB, &["1", ".", "port=\\052443"]).is_err());
    assert!(parse(Type::SVCB, &["1", ".", "ipv6hint=::ffff:192.0.2.1"]).is_ok());
}

#[test]
fn dnskey_and_nsec3_fields_are_constrained() {
    assert!(parse(Type::DNSKEY, &["257", "2", "8", "AQID"]).is_err());
    assert!(parse(Type::DNSKEY, &["65535", "3", "8", "AQID"]).is_err());
    assert!(parse(Type::NSEC3, &["1", "2", "1", "-", "00"]).is_err());
    assert!(parse(Type::NSEC3, &["1", "0", "1", "-", ""]).is_err());
    assert!(parse(Type::NSEC3PARAM, &["1", "1", "1", "-"]).is_err());
    assert!(parse(Type::NSEC3, &["1", "0", "1", "-", "00", "TYPE0"]).is_err());
}

#[test]
fn sha256_ds_digest_requires_32_octets() {
    assert!(parse(Type::DS, &["1", "8", "2", "AABB"]).is_err());
    assert_eq!(
        parse(Type::DS, &["1", "8", "2", &"AA".repeat(32)])
            .unwrap()
            .len(),
        36
    );
}

#[test]
fn eui_wire_lengths_and_csync_flags_are_checked() {
    assert!(parse(Type::EUI48, &[r"\#", "0"]).is_err());
    assert!(parse(Type::EUI64, &[r"\#", "6", "000000000000"]).is_err());
    assert!(parse(Type::CSYNC, &[r"\#", "6", "000000000000"]).is_err());
    assert_eq!(
        parse(Type::CSYNC, &[r"\#", "9", "000000000002000140"]).unwrap(),
        [0, 0, 0, 0, 0, 2, 0, 1, 0x40]
    );
    assert!(parse(Type::CSYNC, &[r"\#", "9", "000000000004000140"]).is_err());
}

#[test]
fn dnskey_accepts_registered_algorithm_mnemonic() {
    assert_eq!(
        parse(Type::DNSKEY, &["257", "3", "RSASHA256", "AQID"]).unwrap(),
        [1, 1, 3, 8, 1, 2, 3]
    );
    assert_eq!(
        parse(Type::DNSKEY, &["257", "03", "RSASHA256", "AQID"]).unwrap(),
        [1, 1, 3, 8, 1, 2, 3]
    );
}
