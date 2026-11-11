#![forbid(unsafe_code)]

use std::io::{self, BufReader, Cursor, Read};

use pharos_proto::{Name, zone::ZoneParser};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn check_corpus(zone: &str, expected: &str, origin: &str) {
    let origin: Name = origin.parse().unwrap();
    let records = ZoneParser::new(Cursor::new(zone), origin, "reference.zone")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    // RFC 1035 §4.1.3: compare the owner and RDATA in uncompressed wire form.
    let actual: Vec<_> = records
        .iter()
        .map(|r| {
            format!(
                "{}\t{}\t{}\t{}\t{}",
                hex(r.owner.as_wire()),
                r.ttl,
                r.class.0,
                r.rtype.0,
                hex(&r.rdata)
            )
        })
        .collect();
    assert_eq!(actual, expected.lines().collect::<Vec<_>>());
}

#[test]
fn miekg_scanner_and_parser_cases() {
    check_corpus(
        include_str!("corpus/zone-reference/miekg.zone"),
        include_str!("corpus/zone-reference/miekg.expected"),
        ".",
    );
}

#[test]
fn coredns_file_signed_zone() {
    check_corpus(
        include_str!("corpus/zone-reference/coredns.zone"),
        include_str!("corpus/zone-reference/coredns.expected"),
        "example.org.",
    );
}

#[test]
fn coredns_file_decimal_escaped_owner() {
    check_corpus(
        include_str!("corpus/zone-reference/coredns-escape.zone"),
        include_str!("corpus/zone-reference/coredns-escape.expected"),
        "campus.edu.",
    );
}

#[test]
fn miekg_escaped_octet_differential_corpus() {
    check_corpus(
        include_str!("corpus/zone-reference/octets.zone"),
        include_str!("corpus/zone-reference/octets.expected"),
        "example.",
    );
}

#[test]
fn miekg_seeded_differential_corpus() {
    check_corpus(
        include_str!("corpus/zone-reference/seeded.zone"),
        include_str!("corpus/zone-reference/seeded.expected"),
        "example.",
    );
}

#[test]
fn malformed_records_return_errors() {
    // RFC 1035 §5.1: malformed entries must not silently produce records.
    for zone in [
        "bad.example. IN A ::1",
        "bad.example. IN AAAA 127.0.0.1",
        "bad.example. CNAME ; missing target",
        "bad.example. MX 10 ; missing target",
        "bad.example. SRV 1 0 80 ; missing target",
        "bad.example. TXT \"unterminated",
        "bad.example. SOA ns.example. host.example. ( 1 2 3 4",
        "bad..example. IN A 127.0.0.1",
        "$INCLUDE unavailable.zone",
    ] {
        let mut parser = ZoneParser::new(Cursor::new(zone), ".".parse().unwrap(), "bad.zone");
        assert!(matches!(parser.next(), Some(Err(_))), "accepted {zone:?}");
    }
}

#[test]
fn reader_errors_are_reported() {
    struct FailedReader;

    impl Read for FailedReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read failed"))
        }
    }

    let mut parser = ZoneParser::new(
        BufReader::new(FailedReader),
        ".".parse().unwrap(),
        "io.zone",
    );
    assert!(matches!(parser.next(), Some(Err(_))));
}
