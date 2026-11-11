use std::io::Cursor;

use pharos_proto::{
    Name, Type,
    zone::{ZoneParser, parse_rdata},
};

fn parse(rtype: Type, fields: &[&str]) -> Result<Vec<u8>, String> {
    parse_rdata(rtype, fields, &"example.".parse::<Name>().unwrap())
}

// RFC 1035 §5.1: diagnostics identify the field that failed presentation parsing.
#[test]
fn zone_errors_point_to_the_offending_advanced_rdata_token() {
    for (input, token) in [
        ("a 1 LOC 91 N 0 E 0\n", "91"),
        ("a 1 LOC 0 60 0 N 0 E 0\n", "60"),
        ("a 1 LOC 0 0 0 bad 0 E 0\n", "bad"),
        ("a 1 LOC ( 0 N\n  181 E 0 )\n", "181"),
        ("a 1 LOC 0 N 0 E bad\n", "bad"),
        ("a 1 LOC 0 N 0 E 0 nope\n", "nope"),
        ("a 1 LOC 0 N 0 E 0 1 nope\n", "nope"),
        ("a 1 LOC ( 0 N 0 E 0\n  1 2 nope )\n", "nope"),
        ("a 1 LOC 0 0 61 N 0 E 0\n", "61"),
        ("a 1 LOC 0 N 180 1 0 E 0\n", "1 0 E"),
        ("a 1 LOC 0 N 0 0 0 bad 0\n", "bad"),
        ("a 1 CSYNC ( 42\n  65536 A )\n", "65536"),
        ("a 1 CSYNC bad\n", "bad"),
        ("a 1 CSYNC 42 0 A BADTYPE AAAA\n", "BADTYPE"),
        ("a 1 IPSECKEY ( 10 1 2\n  ::1 AQID )\n", "::1"),
        ("a 1 IPSECKEY bad\n", "bad"),
        ("a 1 IPSECKEY bad 0\n", "bad"),
        ("a 1 IPSECKEY 10 bad 2 .\n", "bad"),
        ("a 1 IPSECKEY 10 0 bad .\n", "bad"),
        ("a 1 IPSECKEY 10 0 2 . AQID !!!! AA==\n", "!!!!"),
        ("a 1 IPSECKEY 10 0 2 . AQID AA== AAAA\n", "AA=="),
        ("a 1 AMTRELAY 10 bad 0 .\n", "bad"),
        ("a 1 AMTRELAY 10 0 bad .\n", "bad"),
        ("a 1 AMTRELAY 10 0 0 . extra\n", "extra"),
        ("a 1 APL ( 1:192.0.2.0/24\n  !1:192.0.2.1/24 )\n", "!1:"),
        ("a 1 HIP bad AB AQID\n", "bad"),
        ("a 1 HIP bad\n", "bad"),
        ("a 1 HIP bad AB\n", "bad"),
        ("a 1 HIP 2 zz AQID\n", "zz"),
        ("a 1 HIP 2 AB !!!!\n", "!!!!"),
        ("a 1 HIP 2 AB AQID good bad..\n", "bad.."),
        ("a 1 CERT PKIX bad 8 AQID\n", "bad"),
        ("a 1 CERT bad\n", "bad"),
        ("a 1 CERT bad 1\n", "bad"),
        ("a 1 CERT PKIX 1 BADALG AQID\n", "BADALG"),
        ("a 1 CERT PKIX 1 8 AQID !!!! AA==\n", "!!!!"),
        ("a 1 TKEY gss-tsig. 2 abcd 1 zz\n", "zz"),
        ("a 1 TKEY relative 2 abcd 1 ff\n", "relative"),
        ("a 1 TKEY . bad\n", "bad"),
        ("a 1 TKEY . bad abcd\n", "bad"),
    ] {
        let offset = input.find(token).unwrap();
        let before = &input[..offset];
        let line = before.bytes().filter(|b| *b == b'\n').count() + 1;
        let column = before.rsplit('\n').next().unwrap().len() + 1;
        let error = ZoneParser::new(Cursor::new(input), ".".parse().unwrap(), "zone")
            .next()
            .unwrap()
            .unwrap_err();
        assert_eq!(
            (error.line, error.column),
            (line, column),
            "{input:?}: {error}"
        );
    }
}

// RFC 1876 §2: coordinates, altitude and precision have fixed-width wire fields.
#[test]
fn loc_defaults_precision_and_bounds() {
    assert_eq!(
        parse(
            Type::LOC,
            &[
                "51", "30", "12.748", "N", "00", "07", "39.611", "W", "0.00m"
            ]
        )
        .unwrap(),
        [
            0, 0x12, 0x16, 0x13, 0x8b, 0x0d, 0x2c, 0x8c, 0x7f, 0xf8, 0xfc, 0xa5, 0, 0x98, 0x96,
            0x80
        ]
    );
    assert_eq!(
        parse(Type::LOC, &["0", "N", "0", "E", "0m"]).unwrap(),
        [
            0, 0x12, 0x16, 0x13, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 0x98, 0x96, 0x80
        ]
    );
    assert_eq!(
        parse(
            Type::LOC,
            &["0", "S", "0", "W", "-100000", ".01m", "0.1m", "90000000m"]
        )
        .unwrap(),
        [
            0, 0x10, 0x11, 0x99, 0x80, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0
        ]
    );
    assert_eq!(
        &parse(Type::LOC, &["0", "N", "0", "E", "-100000.02"]).unwrap()[12..],
        &[255; 4]
    );
    for fields in [
        vec!["91", "N", "0", "E", "0"],
        vec!["90", "1", "0", "N", "0", "E", "0"],
        vec!["0", "N", "0", "E"],
        vec!["0", "N", "0", "E", "0", "1.001"],
    ] {
        assert!(parse(Type::LOC, &fields).is_err(), "{fields:?}");
    }
}

// RFC 1876 §3: exercise miekg's floating-point parsing and centimeter conversion.
#[test]
fn loc_float_values_match_miekg() {
    let positive_overflow = if cfg!(target_arch = "x86_64") {
        0
    } else {
        u32::MAX
    };
    for (alt, expected) in [
        ("NaN", 0),
        ("nan", 0),
        ("+Inf", positive_overflow),
        ("-Inf", 0),
        ("1e308", positive_overflow),
        ("-1e308", 0),
        ("1e20", positive_overflow),
        ("-1e20", 0),
        ("-100000.02", u32::MAX),
        ("1e-999", 10_000_000),
        ("0x1p+2", 10_000_400),
        ("0x1.8p2", 10_000_600),
        ("0x_1p2", 10_000_400),
        ("1_0", 10_001_000),
        ("0x1p1023", positive_overflow),
        ("0x1.fffffffffffff7p1023", positive_overflow),
        ("0x1p-1075", 10_000_000),
        ("0x1.8p-1075", 10_000_000),
    ] {
        let wire = parse(Type::LOC, &["0", "N", "0", "E", alt]).unwrap();
        assert_eq!(&wire[12..], &expected.to_be_bytes(), "altitude {alt}");
    }
    let rounded = if cfg!(target_arch = "aarch64") {
        0xca80_5500u32
    } else {
        0xca80_5400u32
    };
    let wire = parse(Type::LOC, &["0", "N", "0", "E", "-0x887d53625c.a52656p15"]).unwrap();
    assert_eq!(&wire[12..], &rounded.to_be_bytes());
    for alt in [
        "+NaN",
        "-NaN",
        "1e309",
        "-1e309",
        "0x1p1024",
        "0x1.fffffffffffff8p1023",
        "1__0",
        "1_e2",
        "0x1._8p2",
    ] {
        assert!(
            parse(Type::LOC, &["0", "N", "0", "E", alt]).is_err(),
            "altitude {alt}"
        );
    }
    for (seconds, expected) in [
        ("NaN", 0),
        ("nan", 0),
        ("1e-999", 0),
        ("-0", 0),
        ("0x1p+2", 4_000),
        ("0x1.8p2", 6_000),
        ("1_0", 10_000),
        ("59.9999", 59_999),
    ] {
        let wire = parse(Type::LOC, &["0", "0", seconds, "N", "0", "E", "0"]).unwrap();
        assert_eq!(
            &wire[4..8],
            &(0x8000_0000u32 + expected).to_be_bytes(),
            "seconds {seconds}"
        );
    }
    for seconds in [
        "+NaN", "-NaN", "+Inf", "-Inf", "1e309", "1e308", "60", "-0.001",
    ] {
        assert!(
            parse(Type::LOC, &["0", "0", seconds, "N", "0", "E", "0"]).is_err(),
            "seconds {seconds}"
        );
    }
}

// RFC 8005 §5 and RFC 4398 §2: HIP and CERT encode their keys in binary.
#[test]
fn hip_and_cert() {
    assert_eq!(
        parse(Type::HIP, &["2", "20010010", "AQID", "rvs"]).unwrap(),
        b"\x04\x02\x00\x03\x20\x01\x00\x10\x01\x02\x03\x03rvs\x07example\0"
    );
    assert_eq!(
        parse(Type::CERT, &["PKIX", "42", "RSASHA256", "AQID"]).unwrap(),
        [0, 1, 0, 42, 8, 1, 2, 3]
    );
    assert_eq!(
        parse(Type::CERT, &["1", "0", "0"]).unwrap(),
        [0, 1, 0, 0, 0]
    );
    assert!(parse(Type::HIP, &["2", "ABC", "AQID"]).is_err());
    assert!(parse(Type::HIP, &["2", "AB", "bad"]).is_err());
    assert!(parse(Type::CERT, &["PKIX", "1"]).is_err());
}

// RFC 7477 §2.1: CSYNC uses an NSEC type bitmap.
#[test]
fn csync_bitmap_and_empty_bitmap() {
    assert_eq!(
        parse(Type::CSYNC, &["66", "3", "A", "NS", "AAAA"]).unwrap(),
        [0, 0, 0, 66, 0, 3, 0, 4, 0x60, 0, 0, 8]
    );
    assert_eq!(parse(Type::CSYNC, &["0", "0"]).unwrap(), [0; 6]);
    assert!(parse(Type::CSYNC, &["0", "0", "NOTATYPE"]).is_err());
}

// RFC 4025 §2 and RFC 8777 §4: gateways are selected by their type.
#[test]
fn gateway_variants() {
    assert_eq!(
        parse(Type::IPSECKEY, &["10", "0", "2", ".", "AQID"]).unwrap(),
        [10, 0, 2, 1, 2, 3]
    );
    assert_eq!(
        parse(Type::IPSECKEY, &["10", "1", "2", "1.2.3.4"]).unwrap(),
        [10, 1, 2, 1, 2, 3, 4]
    );
    assert_eq!(
        parse(Type::IPSECKEY, &["10", "2", "2", "2001:db8::1"]).unwrap(),
        [
            10, 2, 2, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]
    );
    assert_eq!(
        parse(Type::IPSECKEY, &["10", "3", "2", "gw"]).unwrap(),
        b"\x0a\x03\x02\x02gw\x07example\0"
    );
    assert_eq!(
        parse(Type::AMTRELAY, &["10", "0", "1", "1.2.3.4"]).unwrap(),
        [10, 1, 1, 2, 3, 4]
    );
    assert_eq!(
        parse(Type::AMTRELAY, &["10", "1", "3", "gw"]).unwrap(),
        [10, 0x83]
    );
    assert_eq!(
        parse(Type::IPSECKEY, &["10", "99", "2"]).unwrap(),
        [10, 99, 2]
    );
    assert_eq!(parse(Type::AMTRELAY, &["10", "0", "99"]).unwrap(), [10, 99]);
    assert!(parse(Type::AMTRELAY, &["10", "2", "0", "."]).is_err());
    assert!(parse(Type::IPSECKEY, &["10", "1", "2", "::1"]).is_err());
    assert!(parse(Type::IPSECKEY, &["10", "0", "2", "gw"]).is_err());
}

// RFC 1035 §5.1: an RR entry carries RDATA; miekg/dns packs zero values instead.
#[test]
fn empty_records_are_rejected() {
    for rtype in [
        Type::LOC,
        Type::HIP,
        Type::CERT,
        Type::CSYNC,
        Type::IPSECKEY,
        Type::AMTRELAY,
        Type::TKEY,
    ] {
        assert!(parse(rtype, &[]).is_err(), "{rtype:?}");
    }
}

// RFC 3123 §4: APL omits trailing zero address octets.
#[test]
fn apl_prefixes_and_validation() {
    assert_eq!(parse(Type::APL, &[]).unwrap(), []);
    assert_eq!(
        parse(
            Type::APL,
            &["1:192.0.2.0/24", "!1:192.0.2.1/32", "2:2001:db8::/32"]
        )
        .unwrap(),
        [
            0, 1, 24, 3, 192, 0, 2, 0, 1, 32, 0x84, 192, 0, 2, 1, 0, 2, 32, 4, 0x20, 1, 0x0d, 0xb8
        ]
    );
    assert_eq!(parse(Type::APL, &["2:::/0"]).unwrap(), [0, 2, 0, 0]);
    for field in [
        "3:0.0.0.0/0",
        "1:192.0.2.1/24",
        "1:2001:db8::/32",
        "2:192.0.2.1/32",
        "1:0.0.0.0/33",
    ] {
        assert!(parse(Type::APL, &[field]).is_err(), "{field}");
    }
}

// RFC 2930 §2: TKEY has an algorithm name and two length-prefixed byte fields.
#[test]
fn tkey_miekg_presentation() {
    assert_eq!(
        parse(Type::TKEY, &["gss-tsig.", "2", "abcd", "1", "ff"]).unwrap(),
        b"\x08gss-tsig\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02\xab\xcd\0\x01\xff"
    );
    assert_eq!(
        parse(Type::TKEY, &[".", "0", "ab", "0", "cd", "ignored"]).unwrap(),
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xab\0\0\xcd"
    );
    assert!(parse(Type::TKEY, &["gss-tsig.", "256", "abcd", "1", "ff"]).is_err());
    assert!(parse(Type::TKEY, &["gss-tsig.", "2", "abcd"]).is_err());
}
