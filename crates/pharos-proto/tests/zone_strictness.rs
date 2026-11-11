use pharos_proto::{Name, Type, zone::parse_rdata};

fn parse(rtype: Type, fields: &[&str]) -> Result<Vec<u8>, String> {
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
fn zonemd_packs_any_hex_digest_length() {
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
fn nsec_without_bitmap_matches_miekg() {
    assert_eq!(parse(Type::NSEC, &["next."]).unwrap(), b"\x04next\0");
}

#[test]
fn nsec3_short_hash_keeps_miekg_fixed_length_octet() {
    assert_eq!(
        parse(Type::NSEC3, &["1", "0", "1", "-", "00", "A"]).unwrap(),
        [1, 0, 0, 1, 0, 20, 0, 0, 1, 0x40]
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
fn generic_known_types_unpack_like_miekg() {
    for (rtype, length, data, expected) in [
        (Type::A, "0", "", vec![]),
        (Type::A, "5", "7f000001ff", vec![127, 0, 0, 1]),
        (Type::MX, "2", "000a", vec![0, 10]),
        (Type::DS, "2", "0001", vec![0, 1, 0, 0]),
        (Type::DS, "0", "", vec![0, 0, 0, 0]),
        (Type::NS, "2", "00ff", vec![0]),
        (Type::SOA, "3", "00c000", vec![0; 22]),
        (Type::SOA, "3", "c00200", vec![0; 22]),
        (Type::ZONEMD, "6", "000000010203", vec![0, 0, 0, 1, 2, 3]),
        (
            Type::URI,
            "10",
            "00010002615c30333262",
            vec![0, 1, 0, 2, b'a', b' ', b'b'],
        ),
        (Type::SVCB, "7", "00010000000000", vec![0, 1, 0, 0, 0, 0, 0]),
        (
            Type::OPT,
            "9",
            "0008000500010100ff",
            vec![0, 8, 0, 5, 0, 1, 1, 0, 128],
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
        (Type::A, "3", "7f0000"),
        (Type::AAAA, "4", "7f000001"),
        (Type::MX, "1", "00"),
        (Type::NS, "2", "0161"),
        (Type::TXT, "2", "0261"),
        (Type(45), "4", "000100aa"),
        (Type(55), "5", "01010001aa"),
        (Type(42), "4", "00032000"),
        (Type(41), "2", "0001"),
    ] {
        assert!(
            parse(rtype, &[r"\#", length, data]).is_err(),
            "{rtype} {data}"
        );
    }
}

#[test]
fn generic_opt_normalizes_zero_keepalive() {
    assert_eq!(
        parse(Type::OPT, &[r"\#", "6", "000b00020000"]).unwrap(),
        [0, 11, 0, 0]
    );
}

#[test]
fn generic_character_strings_reject_truncated_octets() {
    for rtype in [Type::HINFO, Type::X25, Type::ISDN, Type::GPOS, Type::UINFO] {
        assert!(parse(rtype, &[r"\#", "1", "c0"]).is_err(), "{rtype}");
    }
}

#[test]
fn generic_tsig_and_expire_match_miekg_wire() {
    assert_eq!(parse(Type::TSIG, &[r"\#", "0"]).unwrap(), [0; 16]);
    assert_eq!(parse(Type::TSIG, &[r"\#", "1", "00"]).unwrap(), [0; 17]);
    assert_eq!(
        parse(Type::OPT, &[r"\#", "9", "000900050000000100"]).unwrap(),
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
    assert_eq!(parse(Type::HINFO, &[]).unwrap(), [0, 0]);
    assert_eq!(parse(Type::HINFO, &["cpu"]).unwrap(), b"\x03cpu\x00");
    assert_eq!(
        parse(Type::HINFO, &["cpu os extra"]).unwrap(),
        b"\x03cpu\x08os extra"
    );
    assert_eq!(
        parse(Type::HINFO, &["cpu", "unix", "linux"]).unwrap(),
        b"\x03cpu\x0aunix linux"
    );
    assert_eq!(
        parse(Type::HINFO, &[r"cpu\032arch", "os"]).unwrap(),
        b"\x08cpu arch\x02os"
    );
}

#[test]
fn caa_tag_and_value_match_miekg() {
    assert_eq!(
        parse(Type::CAA, &["0", "bad-tag", "x"]).unwrap(),
        b"\x00\x07bad-tagx"
    );
    assert_eq!(
        parse(Type::CAA, &["128", "tbs", "critical"]).unwrap(),
        b"\x80\x03tbscritical"
    );
    assert!(parse(Type::CAA, &["256", "issue", "x"]).is_err());
    assert!(parse(Type::CAA, &["0", "issue", &"x".repeat(256)]).is_err());
    assert!(parse(Type::CAA, &["0", "issue", "x", "y"]).is_err());
}

#[test]
fn txt_decimal_escapes_match_go_pack() {
    for input in [r"abc\32xyz", r"abc\02xyz", r"abc\03xyz"] {
        let plain = input.replace('\\', "");
        let mut expected = vec![plain.len() as u8];
        expected.extend(plain.bytes());
        assert_eq!(parse(Type::TXT, &[input]).unwrap(), expected);
    }
    assert_eq!(parse(Type::TXT, &[r"\256\999"]).unwrap(), [2, 0, 231]);
}

#[test]
fn dnssec_algorithm_mnemonics() {
    for rtype in [Type::DS, Type::CDS] {
        assert_eq!(
            parse(rtype, &["1", "rsasha256", "2", "AB"]).unwrap(),
            [0, 1, 8, 2, 0xab]
        );
        assert_eq!(
            parse(rtype, &["1", "RSASHA256", "2"]).unwrap(),
            [0, 1, 8, 2]
        );
    }
    let fields = ["A", "RSASHA256", "2", "3600", "0", "1", "123", ".", "AQID"];
    assert_eq!(parse(Type::RRSIG, &fields).unwrap()[2], 8);
    let lower = ["A", "rsasha256", "2", "3600", "0", "1", "123", ".", "AQID"];
    assert!(parse(Type::RRSIG, &lower).is_err());
}

#[test]
fn svcb_text_matches_packable_miekg_records() {
    assert_eq!(
        parse(Type::SVCB, &["1", ".", "mandatory=port"]).unwrap(),
        b"\x00\x01\x00\x00\x00\x00\x02\x00\x03"
    );
    assert_eq!(
        parse(Type::SVCB, &["1", ".", "mandatory=alpn,alpn"]).unwrap(),
        b"\x00\x01\x00\x00\x00\x00\x04\x00\x01\x00\x01"
    );
    assert_eq!(
        parse(Type::SVCB, &["1", ".", "mandatory=unknown"]).unwrap(),
        b"\x00\x01\x00\x00\x00\x00\x02\xff\xff"
    );
    assert_eq!(
        parse(Type::SVCB, &["1", ".", "alpn="]).unwrap(),
        b"\x00\x01\x00\x00\x01\x00\x00"
    );
    assert_eq!(
        parse(Type::HTTPS, &["1", ".", "no-default-alpn"]).unwrap(),
        b"\x00\x01\x00\x00\x02\x00\x00"
    );
    assert!(parse(Type::SVCB, &["1", ".", "port=443", "port=80"]).is_err());
    assert!(parse(Type::SVCB, &["1", ".", "key1=abc"]).is_err());
    assert!(parse(Type::SVCB, &["1", ".", "ALPN=h2"]).is_err());
}
