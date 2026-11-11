use std::io::Cursor;

use pharos_proto::zone::ZoneParser;

// Ported from miekg/dns parse_test.go TestOmittedTTL.
#[test]
fn omitted_ttl_and_owner_follow_prior_records_and_directives() {
    let zone = r#"
$ORIGIN example.com.
example.com. 42 IN SOA ns1.example.com. hostmaster.example.com. 1 86400 60 86400 3600
example.com. NS 2
@ MD 3
 MF 4
 43 TYPE65280 \# 1 05
 MB 6
$TTL 1337
example.com. 88 MG 7
example.com. MR 8
$TTL 314
 1 TXT 9
example.com. DNAME 10
"#;
    let records = ZoneParser::new(Cursor::new(zone), ".".parse().unwrap(), "inheritance")
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        records.iter().map(|r| r.ttl).collect::<Vec<_>>(),
        [42, 42, 42, 42, 43, 43, 88, 1337, 1, 314]
    );
    assert!(
        records
            .iter()
            .all(|r| r.owner.to_string() == "example.com.")
    );
}
