#![forbid(unsafe_code)]

use std::io::Cursor;

use pharos_proto::{
    Name,
    zone::{RecordTextError, ZoneParser, parse_record_text},
};
use proptest::prelude::*;

type Parsed = (Vec<u8>, u32, u16, u16, Vec<u8>);

// RFC 1035 §5.1: the reference is the first entry the streaming parser reads.
fn reference(text: &str, origin: &Name) -> Option<Result<Parsed, ()>> {
    let mut parser = ZoneParser::new(Cursor::new(text.to_owned()), origin.clone(), "t");
    parser.set_default_ttl(3600);
    parser.next().map(|record| {
        record
            .map(|r| {
                (
                    r.owner.as_wire().to_vec(),
                    r.ttl,
                    r.class.0,
                    r.rtype.0,
                    r.rdata,
                )
            })
            .map_err(|_| ())
    })
}

type Fast = Result<Parsed, RecordTextError>;

fn fast(text: &str, origin: &Name) -> Fast {
    let mut buffer = [0; 1024];
    parse_record_text(text, origin, Some(3600), &mut buffer).map(|r| {
        (
            r.owner.to_vec(),
            r.ttl,
            r.class.0,
            r.rtype.0,
            r.rdata.to_vec(),
        )
    })
}

// Fast Ok must equal the reference; fast Invalid must be a reference error.
fn assert_agrees(text: &str, origin: &Name) {
    let expected = reference(text, origin);
    match fast(text, origin) {
        Ok(got) => assert_eq!(expected, Some(Ok(got)), "{text:?}"),
        Err(RecordTextError::Invalid) => {
            assert!(matches!(expected, Some(Err(()))), "{text:?}: {expected:?}")
        }
        Err(_) => {}
    }
}

fn root() -> Name {
    ".".parse().unwrap()
}

#[test]
fn supported_types_match_zone_parser() {
    let origin: Name = "example.".parse().unwrap();
    for text in [
        "www.example. 60 IN A 192.0.2.1",
        "www 60 IN A 192.0.2.1",
        "@ 60 IN A 192.0.2.1",
        "www.example. IN 60 A 192.0.2.1",
        "www.example. A 192.0.2.1",
        "www.example. 1h30m ch A 192.0.2.1",
        "www.example. IN AAAA 2001:db8::1",
        "www.example. 5 IN NS ns1",
        "www.example. 5 IN CNAME target.example.com.",
        "1.2.0.192.in-addr.arpa. 5 IN PTR host",
        "www.example. 5 IN DNAME other.",
        "www.example. 5 IN MX 10 mail",
        "example. 5 IN SOA ns hostmaster 2024010101 1h 15m 1w 5m",
        "_sip._tcp 5 IN SRV 1 2 5060 sip.example.",
        "t 5 IN TXT v=spf1",
        "t 5 IN TXT \"v=spf1 include:example.net ~all\"",
        "t 5 IN TXT \"a b\" c \"\"",
        "t 5 IN SPF \"v=spf1 -all\"",
        "t 5 IN TXT \"a;b(c)d\"",
        "WWW 5 in a 192.0.2.1\n",
        "www 5 IN A 192.0.2.1 \t\r\n",
        "www\t5\tIN\tA\t192.0.2.1",
    ] {
        let got = fast(text, &origin);
        assert!(got.is_ok(), "{text:?}: {got:?}");
        assert_agrees(text, &origin);
    }
}

#[test]
fn long_txt_splits_into_255_octet_strings() {
    let text = format!("t 5 IN TXT \"{}\"", "x".repeat(300));
    let got = fast(&text, &root()).unwrap();
    assert_eq!(got.4.len(), 300 + 2);
    assert_agrees(&text, &root());
}

#[test]
fn invalid_input_is_rejected_like_zone_parser() {
    for text in [
        "www 60 IN A 999.1.1.1",
        "www 60 IN A 1.1.1.1 1.1.1.2",
        "www 60 IN A",
        "www 60 IN AAAA 1.1.1.1",
        "www 60 IN MX mail",
        "www 60 IN MX 70000 mail",
        "www 60 IN MX +1 mail",
        "www 60 IN SOA a b 1 2 3 4",
        "www 60 IN SOA a b 1 2 3 4 x",
        "www 60 IN SRV 1 2 3",
        "www 60 IN TXT",
        "www 60 IN ANY A 1.1.1.1",
        "www 60 IN NONE A 1.1.1.1",
        "www 60 CLASS0 A 1.1.1.1",
        "www IN IN A 1.1.1.1",
        "www 60 60 A 1.1.1.1",
        "www 60 IN",
        "www 60",
        "a..b 60 IN A 1.1.1.1",
        "a. 60 IN CNAME b..",
        "www 60 IN CNAME .a",
        "www 60 IN A 1.1.1.1 ; ok",
        "www 60 IN A 01.1.1.1",
        "www 60 IN TXT \"abc",
    ] {
        assert_agrees(text, &root());
        assert_agrees(text, &"example.".parse().unwrap());
    }
    let label = "l".repeat(64);
    assert_eq!(
        fast(&format!("{label}. 60 IN A 1.1.1.1"), &root()),
        Err(RecordTextError::Invalid)
    );
    assert_agrees(&format!("{label}. 60 IN A 1.1.1.1"), &root());
    let long = format!("{0}.{0}.{0}.{0}.", "n".repeat(63));
    assert_agrees(&format!("{long} 60 IN A 1.1.1.1"), &root());
}

#[test]
fn missing_ttl_follows_default_and_class_rule() {
    let origin = root();
    let mut buffer = [0; 512];
    // RFC 1035 §5.1: without an inherited TTL a record needs one.
    let missing = parse_record_text("www A 1.1.1.1", &origin, None, &mut buffer);
    assert_eq!(missing.err(), Some(RecordTextError::Invalid));
    assert!(matches!(reference("www A 1.1.1.1", &origin), Some(Ok(_))));
    let record = parse_record_text("www A 1.1.1.1", &origin, Some(7), &mut buffer).unwrap();
    assert_eq!(record.ttl, 7);
}

#[test]
fn unsupported_shapes_defer_to_zone_parser() {
    for text in [
        "www 60 IN A 1.1.1.1\nwww 60 IN A 1.1.1.2",
        " 60 IN A 1.1.1.1",
        "$TTL 5",
        "www 60 IN A ( 1.1.1.1 )",
        "www 60 IN TXT \"a\\\"b\"",
        "w\\046w 60 IN A 1.1.1.1",
        "www 60 IN TYPE65280 \\# 1 00",
        "www 60 IN CAA 0 issue \"x\"",
        "",
        "www 60 IN TXT a\"b\"",
        "www 60 IN TXT \"a\"\"b\"",
        "www 60 IN A 1.1.1.1 ; c",
        "tést 60 IN A 1.1.1.1",
    ] {
        let got = fast(text, &root());
        assert!(
            matches!(
                got,
                Err(RecordTextError::Unsupported | RecordTextError::Invalid)
            ),
            "{text:?}: {got:?}"
        );
        assert_agrees(text, &root());
    }
    assert_eq!(
        fast("www 60 IN CAA 0 issue \"x\"", &root()),
        Err(RecordTextError::Unsupported)
    );
}

#[test]
fn small_buffer_reports_overflow() {
    let mut buffer = [0; 8];
    let result = parse_record_text(
        "www.example. 60 IN A 1.1.1.1",
        &root(),
        Some(1),
        &mut buffer,
    );
    assert_eq!(result.err(), Some(RecordTextError::BufferTooSmall));
}

fn token() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "www",
        "www.example.",
        "@",
        ".",
        "a..b",
        "ns.",
        "IN",
        "in",
        "CH",
        "ANY",
        "NONE",
        "CLASS1",
        "TYPE1",
        "60",
        "1h",
        "5m",
        "0",
        "2147483648",
        "A",
        "a",
        "AAAA",
        "NS",
        "CNAME",
        "PTR",
        "DNAME",
        "MX",
        "SOA",
        "SRV",
        "TXT",
        "SPF",
        "CAA",
        "1.2.3.4",
        "01.2.3.4",
        "::1",
        "2001:db8::1",
        "10",
        "65536",
        "-1",
        "+1",
        "\"x y\"",
        "\"\"",
        "\"a",
        "b\"",
        "x",
        ";",
        "(",
        ")",
        "\\046",
        "\\",
        "é",
        "\t",
    ])
}

proptest! {
    #[test]
    fn random_records_agree_with_zone_parser(
        tokens in prop::collection::vec(token(), 0..10),
        tab in any::<bool>(),
        origin_is_root in any::<bool>(),
    ) {
        let origin: Name = if origin_is_root { root() } else { "example.".parse().unwrap() };
        let text = tokens.join(if tab { "\t" } else { " " });
        assert_agrees(&text, &origin);
    }
}

fn record() -> impl Strategy<Value = String> {
    let owner = prop::sample::select(vec![
        "www",
        "www.example.",
        "@",
        ".",
        "a.b.c",
        "A.B",
        "x-y_z",
    ]);
    let header = prop::sample::select(vec![
        "",
        "60 ",
        "IN ",
        "60 IN ",
        "IN 60 ",
        "ch 1h ",
        "1m30s HS ",
        "TYPE1 ",
        "CLASS1 ",
        "99999999999 ",
    ]);
    let rdata = prop_oneof![
        prop::sample::select(vec![
            "A 192.0.2.1",
            "A 1.2.3",
            "A 1.2.3.4 5",
            "AAAA ::1",
            "AAAA 1::2::3"
        ])
        .prop_map(str::to_owned),
        (
            prop::sample::select(vec!["NS", "CNAME", "PTR", "DNAME"]),
            prop::sample::select(vec!["t", "t.example.", "@", ".", "a..b", "t extra", ""]),
        )
            .prop_map(|(t, n)| format!("{t} {n}")),
        (
            prop::sample::select(vec!["0", "10", "65535", "65536", "x"]),
            prop::sample::select(vec!["mail", "mail.example.", "."]),
        )
            .prop_map(|(p, n)| format!("MX {p} {n}")),
        (
            prop::sample::select(vec!["1", "4294967295", "4294967296"]),
            prop::sample::select(vec!["1h", "7d", "1w2d", "x", "2147483648", "5"]),
        )
            .prop_map(|(serial, t)| format!("SOA ns host {serial} {t} 15m 1w 5m")),
        (0u32..70_000, 0u32..3).prop_map(|(port, i)| format!("SRV {i} 1 {port} sip")),
        prop::collection::vec(
            prop::sample::select(vec!["a", "\"b c\"", "\"\"", "v=spf1", "\"x;y\"", "z"]),
            0..4
        )
        .prop_map(|v| format!("TXT {}", v.join(" "))),
    ];
    (owner, header, rdata).prop_map(|(o, h, r)| format!("{o} {h}{r}"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]
    #[test]
    fn structured_records_agree_with_zone_parser(text in record(), root_origin in any::<bool>()) {
        let origin: Name = if root_origin { root() } else { "example.".parse().unwrap() };
        assert_agrees(&text, &origin);
    }
}
