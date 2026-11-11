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
