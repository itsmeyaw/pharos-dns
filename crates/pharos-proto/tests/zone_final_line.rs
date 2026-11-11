#![forbid(unsafe_code)]

use std::io::Cursor;

use pharos_proto::{Name, zone::ZoneParser};

fn parse(zone: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, ()> {
    let origin: Name = "example.".parse().unwrap();
    ZoneParser::new(Cursor::new(zone), origin, "final.zone")
        .map(|record| record.map(|r| (r.rtype.0, r.rdata)).map_err(|_| ()))
        .collect()
}

#[test]
fn missing_final_newline_parses_as_if_present() {
    // RFC 1035 §5.1: an entry ends at the line end; EOF ends the last line the same way.
    for body in [
        "www",
        "www IN",
        "www 60",
        "www IN A",
        "www IN NS",
        "www IN TXT",
        "www IN A 192.0.2.1",
        "www 60 IN A 192.0.2.1 ; c",
        "n8\t",
        "m\tS\tNS",
    ] {
        for end in ["", " ", "\t"] {
            let zone = format!("{body}{end}");
            assert_eq!(
                parse(zone.as_bytes()),
                parse(format!("{zone}\n").as_bytes()),
                "{zone:?}"
            );
        }
    }
    assert_eq!(
        parse(b"www IN A 192.0.2.1").unwrap(),
        [(1, vec![192, 0, 2, 1])]
    );
    assert!(parse(b"www IN A ").is_err());
}

#[test]
fn only_space_and_tab_are_blanks_and_carriage_returns_are_discarded() {
    // RFC 1035 §5.1: tabs and spaces delimit items; other CRs are dropped as miekg/dns does.
    let a = |last: u8| (1, vec![192, 0, 2, last]);
    for (zone, expected) in [
        (
            b"a 1 I\r\rN TXT \"x\"\n".as_slice(),
            Ok(vec![(16, b"\x01x".to_vec())]),
        ),
        (b"a IN TXT \"x\ry\"\n", Ok(vec![(16, b"\x03x\ry".to_vec())])),
        (b"a IN TXT \r\x00\n", Ok(vec![(16, b"\x01\x00".to_vec())])),
        (b"a IN TXT \x0cx\n", Ok(vec![(16, b"\x02\x0cx".to_vec())])),
        (b"a IN A 192.0.2.1\r\n", Ok(vec![a(1)])),
        (b"\ra IN A 192.0.2.1\n", Ok(vec![a(1)])),
        (
            b"a IN A 192.0.2.1\n\r\tIN A 192.0.2.2\n",
            Ok(vec![a(1), a(2)]),
        ),
        (b"a IN A 192.0.2.1\n\r\n", Ok(vec![a(1)])),
        (b"a IN TXT\rx\n", Err(())),
        (b"a\rIN TXT x\n", Err(())),
        (b"a IN TXT\r\x00\n", Err(())),
        (b"a IN\x0cTXT x\n", Err(())),
        (b"a IN A 192.0.2.1\n\x0c\n", Err(())),
    ] {
        assert_eq!(parse(zone), expected, "{zone:?}");
    }
}

#[test]
fn generate_with_empty_template_yields_no_records() {
    assert_eq!(parse(b"$GENERATE 0-1 \n"), Ok(vec![]));
    assert_eq!(parse(b"$GENERATE 0-1 ;c\n"), parse(b"$GENERATE 0-1 \n"));
    assert!(parse(b"$GENERATE 0-1\n").is_err());
    assert!(parse(b"$GENERATE 0-1 a\n").is_err());
    assert!(parse(b"$GENERATE 1-2 N TXT \"x\ny IN A 192.0.2.1\n").is_err());
}

#[test]
fn indented_directives_are_not_control_entries() {
    // RFC 1035 §5.1: an entry starting with a blank inherits its owner.
    for zone in [
        b" $GENERATE 0-1 \n".as_slice(),
        b"\t$GENERATE 1-1 x IN A 192.0.2.1\n",
        b" $TTL 60\na IN A 192.0.2.1\n",
        b" $ORIGIN foo.\na IN A 192.0.2.1\n",
        b"a IN A 192.0.2.1\n $TTL 60\n",
    ] {
        assert!(parse(zone).is_err(), "{zone:?}");
    }
}

#[test]
fn parentheses_do_not_end_an_item() {
    // RFC 1035 §5.1: only tabs and spaces delimit items; parentheses only join lines.
    assert_eq!(
        parse(b"a IN TXT x(y)\n"),
        Ok(vec![(16, b"\x02xy".to_vec())])
    );
    assert_eq!(parse(b"a IN MX 1(0 mx)\n"), parse(b"a IN MX 10 mx\n"));
    assert_eq!(
        parse(b"a IN A 19(2.0.2.1\n)\n"),
        parse(b"a IN A 192.0.2.1\n")
    );
    assert_eq!(
        parse(b"a IN A (192.0.2\n.1)\n"),
        parse(b"a IN A 192.0.2.1\n")
    );
    assert_eq!(
        parse(b"a IN TXT (x\ny)\n"),
        Ok(vec![(16, b"\x02xy".to_vec())])
    );
    assert_eq!(
        parse(b"a IN TXT (x;c\ny)\n"),
        Ok(vec![(16, b"\x01x\x01y".to_vec())])
    );
    assert!(parse(b"a IN MX (10\nmx)\n").is_err());
    for zone in [
        b"a IN A(192.0.2.1)\n".as_slice(),
        b"a(IN A 192.0.2.1)\n",
        b"a 60(IN A 192.0.2.1)\n",
        b"a IN TXT(x)\n",
    ] {
        assert!(parse(zone).is_err(), "{zone:?}");
    }
}

#[test]
fn records_without_rdata_are_rejected() {
    // RFC 1035 §5.1: an RR entry is <type> <RDATA>; RFC 3597 §5 \# 0 is the empty form.
    for zone in [
        b"a IN A\n".as_slice(),
        b"a 60 IN TXT\n",
        b"a 2 TXT;\n",
        b"a 2 TXT ;\n",
        b"a IN MX\n",
        b"a IN (A)\n",
        b"a IN TXT()\n",
        b"a IN LOC\n",
        b"a IN SOA\n",
    ] {
        assert!(parse(zone).is_err(), "{zone:?}");
    }
    for zone in [
        b"a IN SOA ns h 3\n".as_slice(),
        b"a IN SSHFP 1 2\n",
        b"a IN TLSA 3 1 1\n",
        b"u IN MX 2\nb\n",
        b"u IN SVCB 2\nb\n",
    ] {
        assert!(parse(zone).is_err(), "{zone:?}");
    }
    assert_eq!(parse(b"a IN TYPE65400 \\# 0\n"), Ok(vec![(65400, vec![])]));
    // RFC 3123 §4: an APL RR may hold zero items.
    assert_eq!(parse(b"a IN APL\n"), Ok(vec![(42, vec![])]));
    // RFC 3597 §5: TYPE42 is an alternative spelling of APL.
    assert_eq!(parse(b"a IN TYPE42\n"), Ok(vec![(42, vec![])]));
}

#[test]
fn unknown_dollar_word_is_an_owner_name() {
    // RFC 1035 §5.1: only $ORIGIN and $INCLUDE are control entries (plus $TTL, $GENERATE).
    let a = Ok(vec![(1, vec![192, 0, 2, 1])]);
    assert_eq!(parse(b"$FOO IN A 192.0.2.1\n"), a);
    assert_eq!(parse(b"$ IN A 192.0.2.1\n"), a);
    assert!(parse(b"$TTL\n").is_err());
}

#[test]
fn unmatched_closing_parenthesis_is_rejected() {
    // RFC 1035 §5.1: parentheses group data across lines, so each ')' closes a '('.
    for zone in [
        b"e 0 NSEC = A x)\n".as_slice(),
        b"e 0 CSYNC 1 0 )\n",
        b"a IN TXT x)\n",
    ] {
        assert!(parse(zone).is_err(), "{zone:?}");
    }
}

#[test]
fn type_bitmaps_require_type_mnemonics() {
    // RFC 3597 §5: an unknown type mnemonic is TYPE followed by its decimal code.
    assert!(parse(b"n IN NXT 0 I2000\n").is_err());
    assert_eq!(
        parse(b"n IN NXT 0 TYPE0\n"),
        Ok(vec![(
            30,
            vec![
                1, b'0', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 128
            ]
        )])
    );
}

#[test]
fn generate_template_escapes_keep_their_meaning() {
    // RFC 1035 §5.1: \X is X and \DDD is the octet DDD.
    assert_eq!(
        parse(b"$GENERATE 1-1 n TXT \\t \\065 \\$\n"),
        Ok(vec![(16, b"\x01t\x01A\x01$".to_vec())])
    );
}

#[test]
fn comment_may_touch_the_type() {
    // RFC 1035 §5.1: a semicolon starts a comment.
    assert_eq!(parse(b"N 1 ( TXT;c\nx )\n"), parse(b"N 1 ( TXT ;c\nx )\n"));
    assert_eq!(
        parse(b"N 1 ( TXT;c\nx )\n"),
        Ok(vec![(16, b"\x01x".to_vec())])
    );
    // RFC 1035 §3.3.14: a TXT character-string may contain a class mnemonic.
    assert_eq!(
        parse(b"a ( IN TXT ;c\nIN )\n"),
        Ok(vec![(16, b"\x02IN".to_vec())])
    );
}

#[test]
fn escape_survives_a_stray_carriage_return() {
    // RFC 1035 §5.1: \X is X; the CR between is dropped as miekg/dns does.
    assert_eq!(
        parse(b"1 IN TXT \\\rx\n"),
        Ok(vec![(16, b"\x01x".to_vec())])
    );
    assert_eq!(
        parse(b"1 IN TXT \\\r\x8d\n"),
        Ok(vec![(16, b"\x01\x8d".to_vec())])
    );
    assert_eq!(
        parse(b"1 IN TXT \\\r(x)\n"),
        Ok(vec![(16, b"\x01x".to_vec())])
    );
    assert!(parse(b"1 IN TXT \\\r \n").is_err());
    assert!(parse(b"1 IN TXT \\\r\"x\"\n").is_err());
}

#[test]
fn dangling_name_escapes_are_rejected() {
    // RFC 1035 §5.1: a backslash escape requires a following character.
    for body in [
        b"(x\\\\\\\n IN A 192.0.2.1)".as_slice(),
        br"$ORIGIN \\\",
        b"a IN NS x\\\\\\",
        b"u IN TYPE19\t\\",
    ] {
        for end in [b"".as_slice(), b"\n"] {
            let zone = [body, end].concat();
            assert!(parse(&zone).is_err(), "{zone:?}");
        }
    }
}

#[test]
fn quoted_strings_are_not_domain_names() {
    // RFC 1035 §3.3.7: MINFO RDATA contains two domain names, not character-strings.
    assert!(parse(b"k IN MINFO \"\" \n").is_err());
}
