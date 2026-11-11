use std::io::Cursor;

use pharos_proto::zone::ZoneParser;

// Ported from miekg/dns generate_test.go TestGenerateRangeGuard.
#[test]
fn generate_range_and_modifier_guards_match_miekg() {
    let cases = [
        ("0-1 dhcp-${0,4,d} A 10.0.0.$", true),
        ("0-1 dhcp-${0,0,x} A 10.0.0.$", true),
        ("128-129 dhcp-${-128,4,d} A 10.0.0.$", true),
        ("128-129 dhcp-${-129,4,d} A 10.0.0.$", false),
        ("0-2 dhcp-${2147483647,4,d} A 10.0.0.$", false),
        ("0-1 dhcp-${2147483646,4,d} A 10.0.0.$", true),
        ("0-1/step dhcp-${0,4,d} A 10.0.0.$", false),
        ("0-1/ dhcp-${0,4,d} A 10.0.0.$", false),
        ("0-10/2 dhcp-${0,4,d} A 10.0.0.$", true),
        ("0-1/0 dhcp-${0,4,d} A 10.0.0.$", false),
    ];
    for (directive, accepted) in cases {
        let zone = format!("$TTL 60\n$GENERATE {directive}\n");
        let result = ZoneParser::new(Cursor::new(zone), "test.".parse().unwrap(), "generate")
            .collect::<Result<Vec<_>, _>>();
        assert_eq!(result.is_ok(), accepted, "{directive}: {result:?}");
    }
}
