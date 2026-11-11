use std::io::{BufReader, Cursor};

use pharos_proto::{Class, zone::ZoneParser};

fn parser(input: &[u8]) -> ZoneParser<BufReader<Cursor<&[u8]>>> {
    ZoneParser::new(
        BufReader::with_capacity(2, Cursor::new(input)),
        ".".parse().unwrap(),
        "zone",
    )
}

#[test]
fn arbitrary_octets_are_preserved_in_names_and_character_strings() {
    let input = b"$ORIGIN \xff. ; \xfe\n$TTL 60\n\xc3\xa9 IN CNAME \\\xff\n  TXT ( \"a\xff\" ; \x80\n \"b\\\xfe\" \"\\255\" )\n";
    let records = parser(input).collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(records[0].owner.as_wire(), b"\x02\xc3\xa9\x01\xff\0");
    assert_eq!(records[0].rdata, b"\x01\xff\x01\xff\0");
    assert_eq!(records[1].rdata, b"\x02a\xff\x02b\xfe\x01\xff");
}

#[test]
fn decimal_escapes_wrap_like_miekg() {
    let records = parser(b"$TTL 1\n\\256. TXT \"\\999\\256\\255\"\n")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(records[0].owner.as_wire(), b"\x01\0\0");
    assert_eq!(records[0].rdata, [3, 231, 0, 255]);
    assert!(
        parser(b"a 1 HTTPS 1 . key65534=\\256\n")
            .next()
            .unwrap()
            .is_err()
    );
}

#[test]
fn quoted_newlines_carriage_returns_and_short_escapes_are_literal() {
    let input = b"a 1 TXT \"x\ny\rz\" \"abc\\32xyz\" \"abc\\02xyz\" \"abc\\03xyz\"\n";
    let record = parser(input).next().unwrap().unwrap();
    assert_eq!(
        record.rdata,
        b"\x05x\ny\rz\x08abc32xyz\x08abc02xyz\x08abc03xyz"
    );
}

#[test]
fn escaped_carriage_return_outside_quotes_matches_miekg() {
    assert!(parser(b"a\\\r 60 A 192.0.2.1\n").next().unwrap().is_err());
    let record = parser(b"a\\\rX 60 A 192.0.2.1\n").next().unwrap().unwrap();
    assert_eq!(record.owner.as_wire(), b"\x02aX\0");
}

#[test]
fn naptr_requires_quoted_character_strings() {
    let valid = b"a 60 NAPTR 1 2 \"s\" \"SIP\" \"\" .\n";
    assert!(parser(valid).next().unwrap().is_ok());
    for invalid in [
        &b"a 60 NAPTR 1 2 s \"SIP\" \"\" .\n"[..],
        &b"a 60 NAPTR 1 2 \"s\" SIP \"\" .\n"[..],
        &b"a 60 NAPTR 1 2 \"s\" \"SIP\" x .\n"[..],
    ] {
        assert!(parser(invalid).next().unwrap().is_err(), "{invalid:?}");
    }
}

#[test]
fn nested_parentheses_join_lines_and_extra_close_has_its_own_location() {
    let input = b"a 60 TXT ( \"one\" (\n \"two\" ) \"three\" )\n";
    let record = parser(input).next().unwrap().unwrap();
    assert_eq!(record.rdata, b"\x03one\x03two\x05three");
    let error = parser(b"a 60 TXT ( ( \"one\" ) ) )\n")
        .next()
        .unwrap()
        .unwrap_err();
    assert_eq!((error.line, error.column), (1, 24));
    let error = parser(b"a 60 TXT ( ( \"one\" )\n")
        .next()
        .unwrap()
        .unwrap_err();
    assert_eq!((error.line, error.column), (1, 10));
}

#[test]
fn unterminated_delimiters_point_to_the_opening_token() {
    for (input, line, column) in [
        (&b"a 60 TXT \"abc\ncontinuation"[..], 1, 10),
        (&b"a 60 TXT ( \"abc\"\n"[..], 1, 10),
        (&b"a 60 TXT ( ( \"abc\" )\n"[..], 1, 10),
    ] {
        let error = parser(input).next().unwrap().unwrap_err();
        assert_eq!((error.line, error.column), (line, column), "{error}");
    }
}

#[test]
fn quote_boundaries_match_miekg_character_strings() {
    for (value, expected) in [
        ("abc\"def\"", &b"\x03abc\x03def"[..]),
        ("\"abc\"def", &b"\x03abc\x03def"[..]),
        ("abc\"\"def", &b"\x03abc\x00\x03def"[..]),
        ("\"a\"\"b\"", &b"\x01a\x01b"[..]),
    ] {
        let input = format!("a 1 TXT {value}\n");
        assert_eq!(
            parser(input.as_bytes()).next().unwrap().unwrap().rdata,
            expected
        );
    }
    let record = parser(b"a 1 HINFO abc\"def\"\n").next().unwrap().unwrap();
    assert_eq!(record.rdata, b"\x03abc\x03def");
    for input in [
        &b"a 1 A \"192.0.2.1\"\n"[..],
        &b"a 1 MX \"5\" target.\n"[..],
        &b"\"a\" 1 A 192.0.2.1\n"[..],
        &b"a \"1\" A 192.0.2.1\n"[..],
        &b"$ORIGIN \"example.\"\na 1 A 192.0.2.1\n"[..],
        &b"$TTL \"1\"\na A 192.0.2.1\n"[..],
    ] {
        assert!(parser(input).next().unwrap().is_err());
    }
    assert!(
        parser(b"a 1 HTTPS 1 . alpn=\"h2\"\n")
            .next()
            .unwrap()
            .is_ok()
    );
    let record = parser(b"$GENERATE 1-1 x$ TXT \"$\"\"foo\"\n")
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(record.rdata, b"\x011\x03foo");
    let record = parser(b"$GENERATE 1-1 x$ TXT \"$\"\"$\"\n")
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(record.rdata, b"\x011\x011");
}

#[test]
fn uinfo_uses_the_first_quoted_character_string() {
    let record = parser(b"record.example. 60 IN UINFO \"info\"\n")
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(record.rdata, b"\x04info");
    let record = parser(b"a 60 UINFO abc\"def\" ignored\n")
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(record.rdata, b"\x03abc");
}

#[test]
fn errors_identify_the_offending_token_in_bytes() {
    let cases: &[(&[u8], usize, usize)] = &[
        (b"$TTL nope\n", 1, 6),
        (b"$ORIGIN a..\n", 1, 9),
        (b"$TTL 60\na IN BOGUS data\n", 2, 6),
        (b"$TTL 60\n\xff A nope\n", 2, 5),
        (b"$TTL 60\na SOA ( ns. host. 1\n  2 bad 4 5 )\n", 3, 5),
        (b"$TTL 60\na MX 10 bad..\n", 2, 9),
        (b"$TTL 60\na SRV 0 0 999999 bad..\n", 2, 11),
    ];
    for &(input, line, column) in cases {
        let error = parser(input).next().unwrap().unwrap_err();
        assert_eq!(
            (error.line, error.column),
            (line, column),
            "{input:?}: {error}"
        );
    }
}

#[test]
fn missing_rdata_points_to_the_record_end() {
    for (input, column) in [
        (&b"$TTL 60\na MX 10\n"[..], 8),
        (&b"$TTL 60\na MX 10 ; missing target\n"[..], 9),
    ] {
        let error = parser(input).next().unwrap().unwrap_err();
        assert_eq!((error.line, error.column), (2, column), "{error}");
    }
}

#[test]
fn malformed_multiline_hex_points_to_the_bad_token() {
    for input in [
        &b"a 1 DS ( 1 8 2 AA\n  ZZ )\n"[..],
        &b"a 1 ZONEMD ( 1 1 1 AA\n  ZZ )\n"[..],
        &b"a 1 TYPE65400 ( \\# 2 AA\n  ZZ )\n"[..],
    ] {
        let error = parser(input).next().unwrap().unwrap_err();
        assert_eq!((error.line, error.column), (2, 3), "{error}");
    }
}

#[test]
fn record_must_fit_the_dns_wire_limit() {
    let mut zone = format!(
        "a 1 TXT {}",
        format!("\"{}\" ", "x".repeat(255)).repeat(255)
    );
    zone.push_str(&format!("\"{}\"\n", "x".repeat(253)));
    assert!(parser(zone.as_bytes()).next().unwrap().is_err());
}

#[test]
fn empty_known_rdata_matches_packed_dynamic_update_records() {
    for (rtype, expected) in [
        ("A", vec![]),
        ("AAAA", vec![]),
        ("NS", vec![]),
        ("MX", vec![0; 2]),
        ("SOA", vec![0; 20]),
        ("HINFO", vec![0; 2]),
        ("SRV", vec![0; 6]),
        ("NAPTR", vec![0; 7]),
        ("TSIG", vec![0; 16]),
        ("NSEC3", vec![0; 6]),
        ("CAA", vec![0; 2]),
    ] {
        let input = format!("a 60 IN {rtype}\n");
        let record = parser(input.as_bytes()).next().unwrap().unwrap();
        assert_eq!(record.rdata, expected, "{rtype}");
    }
    assert!(parser(b"a 60 IN TYPE65400\n").next().unwrap().is_err());
    assert!(parser(b"a 1 TYPE1\n").next().unwrap().is_err());
    assert!(parser(b"a 1 TYPE28\n").next().unwrap().is_err());
    assert!(parser(b"a 60 IN A \n").next().unwrap().is_err());
}

#[test]
fn class_first_without_default_ttl_matches_miekg() {
    let record = parser(b"a IN A 192.0.2.1\n").next().unwrap().unwrap();
    assert_eq!((record.class, record.ttl), (Class::IN, 0));
    assert!(parser(b"a A 192.0.2.1\n").next().unwrap().is_err());
}

#[test]
fn ttl_unit_segments_and_machine_integer_wrap_match_miekg() {
    for (ttl, expected) in [("m", 0), ("1hms", 3600), ("18446744073709551616", 0)] {
        let input = format!("$TTL {ttl}\na A 192.0.2.1\n");
        assert_eq!(
            parser(input.as_bytes()).next().unwrap().unwrap().ttl,
            expected
        );
    }
    assert!(
        parser(b"$TTL 4294967296\na A 192.0.2.1\n")
            .next()
            .unwrap()
            .is_err()
    );
}

#[test]
fn generate_modifier_error_points_to_dollar() {
    let input = b"@ IN SOA ns.test. hostmaster.test. ( 1 8h 2h 7d 1d )\n$GENERATE 0-1 dhcp-${0,4,dd} A 10.0.0.$\n";
    let mut p = parser(input);
    p.next().unwrap().unwrap();
    let error = p.next().unwrap().unwrap_err();
    assert_eq!((error.line, error.column), (2, 20));
    assert_eq!(error.message, "bad base in $GENERATE");

    let input = b"$GENERATE 0-1 \xff-${0,4,dd} A 10.0.0.$\n";
    let error = parser(input).next().unwrap().unwrap_err();
    assert_eq!((error.line, error.column), (1, 17));
}

#[test]
#[cfg(unix)]
fn includes_preserve_path_bytes_and_enforce_depth() {
    use std::{ffi::OsString, fs, os::unix::ffi::OsStringExt};

    let dir = std::env::temp_dir().join(format!("pharos-zone-bytes-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let filename = OsString::from_vec(b"child-\xc3\xa9.zone".to_vec());
    let path = dir.join(&filename);
    fs::write(&path, b"a 60 A 192.0.2.1\n").unwrap();
    let mut input = b"$GENERATE 0-1 $$INCLUDE child-\xc3\xa9.zone\n".to_vec();
    let parent = dir.join("parent.zone");
    let mut p = ZoneParser::new(
        Cursor::new(&input),
        ".".parse().unwrap(),
        parent.to_str().unwrap(),
    );
    p.set_include_allowed(true);
    assert_eq!(p.collect::<Result<Vec<_>, _>>().unwrap().len(), 2);

    input = b"$GENERATE 0-1 $$INCLUDE child-\xc3\xa9.zone\n".to_vec();
    fs::write(&path, &input).unwrap();
    let mut p = ZoneParser::new(
        Cursor::new(&input),
        ".".parse().unwrap(),
        parent.to_str().unwrap(),
    );
    p.set_include_allowed(true);
    assert!(p.next().unwrap().unwrap_err().message.contains("$INCLUDE"));
    fs::remove_file(path).unwrap();
    fs::remove_dir(dir).unwrap();
}

#[test]
fn generated_include_respects_permission_and_depth() {
    let input = b"$GENERATE 0-1 $$INCLUDE tests/corpus/zone-include-child.zone\n";
    let error = parser(input).next().unwrap().unwrap_err();
    assert!(error.message.contains("$INCLUDE"), "{error}");

    let mut p = ZoneParser::new(
        Cursor::new(input),
        "example.".parse().unwrap(),
        concat!(env!("CARGO_MANIFEST_DIR"), "/parent.zone"),
    );
    p.set_include_allowed(true);
    assert_eq!(p.collect::<Result<Vec<_>, _>>().unwrap().len(), 2);
}
