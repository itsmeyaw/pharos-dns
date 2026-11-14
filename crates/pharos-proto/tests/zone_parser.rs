use std::io::Cursor;

use pharos_proto::{Class, Name, Type, zone::ZoneParser};

#[test]
fn parses_origin_ttl_and_inherited_owner() {
    let input = "$ORIGIN example.\n$TTL 1h30m\nwww IN A 192.0.2.1\n  AAAA 2001:db8::1\n";
    let origin: Name = ".".parse().unwrap();
    let records = ZoneParser::new(Cursor::new(input), origin, "example.zone")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].owner.to_string(), "www.example.");
    assert_eq!(records[0].ttl, 5400);
    assert_eq!(records[0].class, Class::IN);
    assert_eq!(records[0].rtype, Type::A);
    assert_eq!(records[0].rdata, [192, 0, 2, 1]);
    assert_eq!(records[1].owner, records[0].owner);
    assert_eq!(records[1].rtype, Type::AAAA);
}

#[test]
fn any_class_matches_miekg_rejection() {
    let parser = ZoneParser::new(
        Cursor::new("a 60 ANY A 192.0.2.1\n"),
        ".".parse().unwrap(),
        "any",
    );
    assert!(parser.collect::<Result<Vec<_>, _>>().is_err());
}

#[test]
fn known_type_mnemonic_accepts_generic_rdata() {
    let parser = ZoneParser::new(
        Cursor::new("a 60 IN A \\# 4 c0000201\n"),
        ".".parse().unwrap(),
        "generic",
    );
    let records = parser.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(records[0].rtype, Type::A);
    assert_eq!(records[0].rdata, [192, 0, 2, 1]);
}

#[test]
fn rejects_invalid_class_and_odd_generic_rdata_words() {
    // RFC 3597 §5: CLASS codes are decimal and each generic hexadecimal word has even length.
    for input in [
        "a 60 CLASS+1 A 192.0.2.1\n".to_owned(),
        r"a 60 TYPE65000 \# 1 A A".to_owned() + "\n",
    ] {
        assert!(
            ZoneParser::new(Cursor::new(input.as_bytes()), ".".parse().unwrap(), "strict")
                .collect::<Result<Vec<_>, _>>()
                .is_err(),
            "{input:?}"
        );
    }
}

#[test]
fn rejects_invalid_svcparam_digit_escapes_and_empty_alpn() {
    // RFC 9460 §§2.1, 7.1.1: digit escapes use exactly three digits and alpn lists are nonempty.
    for input in [
        r"a 60 SVCB 1 . key9=\9".to_owned() + "\n",
        r"a 60 SVCB 1 . key9=\99".to_owned() + "\n",
        r"a 60 SVCB 1 . key9=\12x".to_owned() + "\n",
        "a 60 SVCB 1 . alpn=\n".to_owned(),
        "a 60 SVCB 1 . alpn\n".to_owned(),
    ] {
        assert!(
        ZoneParser::new(Cursor::new(input.as_bytes()), ".".parse().unwrap(), "strict")
                .collect::<Result<Vec<_>, _>>()
                .is_err(),
            "{input:?}"
        );
    }
}

#[test]
fn rejects_non_utf8_naptr_character_strings() {
    // RFC 3403 §3: NAPTR flags, services, and regexp values are UTF-8.
    let input = "a 60 NAPTR 1 1 \"U\" \"\\255\" \"\" .\n";
    assert!(
        ZoneParser::new(Cursor::new(input), ".".parse().unwrap(), "strict")
            .collect::<Result<Vec<_>, _>>()
            .is_err()
    );
}

#[test]
fn tsig_presentation_is_rejected_like_miekg() {
    let input = "example. 3600 IN TSIG hmac. 1 300 0 42 0 0\n";
    let parser = ZoneParser::new(Cursor::new(input), ".".parse().unwrap(), "tsig");
    assert!(parser.collect::<Result<Vec<_>, _>>().is_err());
}

#[test]
fn handles_multiline_quoting_and_escapes() {
    let input = "$TTL 60\n@ IN TXT ( \"a;b\" ; comment\n \"c\\032d\" )\n";
    let mut parser = ZoneParser::new(Cursor::new(input), "example.".parse().unwrap(), "quoted");
    let record = parser.next().unwrap().unwrap();
    assert_eq!(record.rdata, b"\x03a;b\x03c d");
    assert!(parser.next().is_none());
}

#[test]
fn errors_stop_iteration_and_include_location() {
    let mut parser = ZoneParser::new(
        Cursor::new("$TTL 1h\na A nope\nb A 192.0.2.1\n"),
        ".".parse().unwrap(),
        "bad.zone",
    );
    let error = parser.next().unwrap().unwrap_err();
    assert_eq!((&*error.file, error.line), ("bad.zone", 2));
    assert!(error.column > 0);
    assert!(parser.next().is_none());
}

#[test]
fn generates_range_with_modifiers() {
    let input = "$TTL 1h\n$GENERATE 1-3/2 host${1,3,x} A 192.0.2.$\n";
    let records = ZoneParser::new(Cursor::new(input), "example.".parse().unwrap(), "gen")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        records
            .iter()
            .map(|r| r.owner.to_string())
            .collect::<Vec<_>>(),
        ["host002.example.", "host004.example."]
    );
    assert_eq!(records[1].rdata, [192, 0, 2, 3]);
}

#[test]
fn generate_unmodified_values_can_exceed_i32() {
    let input = "$GENERATE 2147483648-2147483648 host$ 1 A 192.0.2.1\n";
    let records = ZoneParser::new(Cursor::new(input), "example.".parse().unwrap(), "gen")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(records[0].owner.to_string(), "host2147483648.example.");
}

#[test]
fn include_is_opt_in_and_restores_origin() {
    let filename = format!("{}/tests/corpus/parent.zone", env!("CARGO_MANIFEST_DIR"));
    let input = "$TTL 300\n$INCLUDE zone-include-child.zone sub\nafter A 192.0.2.5\n";
    let origin = "example.".parse().unwrap();
    let mut denied = ZoneParser::new(Cursor::new(input), origin, &filename);
    assert!(denied.next().unwrap().is_err());
    let mut parser = ZoneParser::new(Cursor::new(input), "example.".parse().unwrap(), &filename);
    parser.set_include_allowed(true);
    let records = parser.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(records[0].owner.to_string(), "child.sub.example.");
    assert_eq!(records[1].owner.to_string(), "after.example.");
}

#[test]
fn generate_has_independent_default_ttl_and_owner() {
    let input = "$TTL 90\nfirst A 192.0.2.1\n$GENERATE 1-1 host$ A 192.0.2.$\n  A 192.0.2.2\n";
    let records = ZoneParser::new(Cursor::new(input), "example.".parse().unwrap(), "gen")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(records[1].ttl, 3600);
    assert_eq!(records[2].owner.to_string(), "first.example.");
    assert_eq!(records[2].ttl, 90);
}

#[test]
fn class_inherits_last_explicit_class_and_rejects_query_classes() {
    let records = ZoneParser::new(
        Cursor::new("a 60 CH A 192.0.2.1\nb A 192.0.2.2\n"),
        ".".parse().unwrap(),
        "class-inheritance",
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    assert_eq!(
        records
            .iter()
            .map(|record| record.class)
            .collect::<Vec<_>>(),
        [Class::CH, Class::CH]
    );

    for class in ["NONE", "CLASS255", "CLASS0"] {
        let parser = ZoneParser::new(
            Cursor::new(format!("a 60 {class} A 192.0.2.1\n")),
            ".".parse().unwrap(),
            "invalid-class",
        );
        assert!(parser.collect::<Result<Vec<_>, _>>().is_err(), "{class}");
    }
}

#[test]
fn rejects_ttl_overflow_and_oversized_decimal_escape() {
    for zone in [
        "a 18446744073709551616 A 192.0.2.1\n",
        "a 2147483648 A 192.0.2.1\n",
        "a 60 TXT \"\\999\"\n",
    ] {
        let parser = ZoneParser::new(Cursor::new(zone), ".".parse().unwrap(), "strict");
        assert!(parser.collect::<Result<Vec<_>, _>>().is_err(), "{zone}");
    }
}

#[test]
fn parses_wks_mnemonic_with_generic_rdata() {
    let parser = ZoneParser::new(
        Cursor::new("a 60 IN WKS \\# 0\n"),
        ".".parse().unwrap(),
        "wks",
    );
    let records = parser.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(records[0].rtype, Type::WKS);
}

#[test]
fn omitted_sig_ttl_uses_original_ttl_not_zone_default() {
    let input = "$TTL 99\na IN SIG A 8 2 3600 0 1 123 . AQID\n";
    let record = ZoneParser::new(Cursor::new(input), "example.".parse().unwrap(), "sig")
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(record.ttl, 3600);
}

#[test]
fn rejects_non_in_nsap_and_px_records() {
    for record in ["a 60 CH NSAP 0x47000580", "a 60 CH PX 1 . ."] {
        let parser = ZoneParser::new(Cursor::new(record), ".".parse().unwrap(), "class-specific");
        assert!(parser.collect::<Result<Vec<_>, _>>().is_err(), "{record}");
    }
}

#[test]
fn rejects_lp_target_equal_to_owner() {
    let parser = ZoneParser::new(
        Cursor::new("a.example. 60 IN LP 1 a.example.\n"),
        "example.".parse().unwrap(),
        "lp",
    );
    assert!(parser.collect::<Result<Vec<_>, _>>().is_err());
}

#[test]
fn rejects_obsolete_md_and_mf_zone_records() {
    for rtype in ["MD", "MF"] {
        let parser = ZoneParser::new(
            Cursor::new(format!("a 60 {rtype} target.example.\n")),
            "example.".parse().unwrap(),
            "obsolete",
        );
        assert!(parser.collect::<Result<Vec<_>, _>>().is_err(), "{rtype}");
    }
}
