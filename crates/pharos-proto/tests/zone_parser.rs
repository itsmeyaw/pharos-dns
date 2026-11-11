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
