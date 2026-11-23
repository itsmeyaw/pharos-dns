use pharos_proto::{Name, Type};
use serde_json::{Value, json};

use super::records::{build_zone, parse_page};

fn page(value: &Value, private: bool) -> Result<super::records::Page, String> {
    parse_page(value.to_string().as_bytes(), private)
}

fn set(properties: Value) -> Value {
    json!({"name": "x", "properties": properties})
}

fn rdata(page: &super::records::Page, rtype: Type) -> Vec<Vec<u8>> {
    page.records
        .iter()
        .filter(|record| record.rtype == rtype)
        .map(|record| record.rdata.clone())
        .collect()
}

#[test]
fn public_shape_converts_every_supported_type() {
    let page = page(
        &json!({"value": [
            set(json!({"fqdn": "example.org.", "TTL": 300,
                "ARecords": [{"ipv4Address": "192.0.2.1"}],
                "AAAARecords": [{"ipv6Address": "2001:db8::1"}],
                "MXRecords": [{"preference": 10, "exchange": "mail.example.org"}],
                "NSRecords": [{"nsdname": "ns1.example.net."}],
                "PTRRecords": [{"ptrdname": "ptr.example.org."}],
                "SRVRecords": [{"priority": 1, "weight": 2, "port": 5269, "target": "srv.example.org."}],
                "TXTRecords": [{"value": ["one", "two"]}],
                "SOARecord": {"host": "ns1.example.net.", "email": "hostmaster.example.net", "serialNumber": 1,
                    "refreshTime": 3600, "retryTime": 300, "expireTime": 86400, "minimumTTL": 60}})),
            set(json!({"fqdn": "www.example.org.", "TTL": 60, "CNAMERecord": {"cname": "example.org"}})),
        ], "nextLink": "https://management.azure.com/next"}),
        false,
    )
    .unwrap();
    assert_eq!(
        page.next_link.as_deref(),
        Some("https://management.azure.com/next")
    );
    assert_eq!(page.records.len(), 9);
    assert_eq!(rdata(&page, Type::A), [vec![192, 0, 2, 1]]);
    assert_eq!(rdata(&page, Type::AAAA)[0][..4], [0x20, 0x01, 0x0d, 0xb8]);
    assert_eq!(
        rdata(&page, Type::MX),
        [[&[0, 10][..], b"\x04mail\x07example\x03org\x00"].concat()]
    );
    assert_eq!(
        rdata(&page, Type::NS),
        [b"\x03ns1\x07example\x03net\x00".to_vec()]
    );
    assert_eq!(rdata(&page, Type::TXT), [b"\x03one\x03two".to_vec()]);
    assert_eq!(
        rdata(&page, Type::CNAME),
        [b"\x07example\x03org\x00".to_vec()]
    );
    let soa = &rdata(&page, Type::SOA)[0];
    assert_eq!(soa[soa.len() - 4..], 60u32.to_be_bytes());
    assert_eq!(page.records[0].ttl, 300);
}

#[test]
fn private_shape_uses_lowercase_keys_and_skips_ns() {
    let page = page(
        &json!({"value": [set(json!({"fqdn": "example.org.", "ttl": 10,
            "aRecords": [{"ipv4Address": "192.0.2.1"}],
            "nsRecords": [{"nsdname": "ignored.example."}],
            "soaRecord": {"host": "azureprivatedns.net", "email": "azureprivatedns-host.microsoft.com", "serialNumber": 1,
                "refreshTime": 3600, "retryTime": 300, "expireTime": 2419200, "minimumTtl": 10}}))]}),
        true,
    )
    .unwrap();
    assert_eq!(page.next_link, None);
    assert_eq!(
        page.records
            .iter()
            .map(|record| record.rtype)
            .collect::<Vec<_>>(),
        [Type::A, Type::SOA]
    );
}

#[test]
fn keys_match_without_case_and_null_means_absent() {
    let page = page(
        &json!({"VALUE": [set(json!({"FQDN": "example.org.", "tTl": 5, "arecords": [{"IPV4ADDRESS": "192.0.2.9"}], "AAAARecords": null}))],
            "nextLink": null}),
        false,
    )
    .unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.next_link, None);
    let empty = super::records::parse_page(b"{}", false).unwrap();
    assert!(empty.records.is_empty());
    let blank = parse_page(br#"{"value": [], "nextLink": ""}"#, false).unwrap();
    assert_eq!(blank.next_link, None);
}

#[test]
fn malformed_values_fail_the_page_instead_of_panicking() {
    let a = |address: Value| json!({"value": [set(json!({"fqdn": "example.org.", "TTL": 1, "ARecords": [{"ipv4Address": address}]}))]});
    let bad = [
        a(json!("999.0.0.1")),
        a(json!(null)),
        a(json!(7)),
        json!({"value": [set(json!({"fqdn": "example.org.", "ARecords": []}))]}),
        json!({"value": [set(json!({"fqdn": "example.org.", "TTL": 4294967296u64}))]}),
        json!({"value": [set(json!({"fqdn": "example.org.", "TTL": -1}))]}),
        json!({"value": [set(json!({"fqdn": "example.org.", "TTL": 1.5}))]}),
        json!({"value": [set(json!({"TTL": 1}))]}),
        json!({"value": [{"name": "no-properties"}]}),
        json!({"value": [set(json!({"fqdn": "example.org.", "TTL": 1,
            "SRVRecords": [{"priority": 1, "weight": 1, "port": 70000, "target": "t."}]}))]}),
        json!({"value": [set(json!({"fqdn": "example.org.", "TTL": 1,
            "MXRecords": [{"preference": -1, "exchange": "m."}]}))]}),
        json!({"value": [set(json!({"fqdn": "example.org.", "TTL": 1,
            "TXTRecords": [{"value": ["x".repeat(256)]}]}))]}),
        json!({"value": [set(json!({"fqdn": "example.org.", "TTL": 1, "TXTRecords": [{"value": []}]}))]}),
        json!({"value": [set(json!({"fqdn": "example.org.", "TTL": 1, "CNAMERecord": {"cname": "a..b"}}))]}),
        json!({"value": "nope"}),
        json!({"value": [], "nextLink": 3}),
        json!([]),
    ];
    for value in bad {
        assert!(page(&value, false).is_err(), "{value}");
    }
    assert!(parse_page(b"not json", false).is_err());
}

fn soa_and(extra: Value, private: bool) -> Vec<pharos_proto::zone::ZoneRecord> {
    let soa = set(json!({"fqdn": "example.org.", "TTL": 30,
        "SOARecord": {"host": "ns.example.net.", "email": "h.example.net.", "serialNumber": 1,
            "refreshTime": 1, "retryTime": 1, "expireTime": 1, "minimumTTL": 1}}));
    parse_page(
        json!({"value": [soa, extra]}).to_string().as_bytes(),
        private,
    )
    .unwrap()
    .records
}

#[test]
fn a_zone_needs_an_soa_and_gets_an_apex_ns_when_azure_has_none() {
    let apex: Name = "example.org.".parse().unwrap();
    let www = set(
        json!({"fqdn": "www.example.org.", "TTL": 60, "ARecords": [{"ipv4Address": "192.0.2.1"}]}),
    );
    let error = parse_page(json!({"value": [www.clone()]}).to_string().as_bytes(), true)
        .unwrap()
        .records;
    assert_eq!(
        build_zone(&apex, error).unwrap_err(),
        "zone has no SOA record"
    );
    assert_eq!(
        build_zone(&apex, Vec::new()).unwrap_err(),
        "zone has no SOA record"
    );

    // Private zones have no NS records: the SOA host stands in at the apex.
    let zone = build_zone(&apex, soa_and(www.clone(), true)).unwrap();
    let ns: Vec<_> = zone.rrset(apex.as_name_ref(), Type::NS).collect();
    assert_eq!(ns.len(), 1);
    assert_eq!(ns[0].rdata, b"\x02ns\x07example\x03net\x00");
    assert_eq!(ns[0].ttl, 30);

    // A public zone keeps its own NS RRset.
    let own = set(
        json!({"fqdn": "example.org.", "TTL": 100, "NSRecords": [{"nsdname": "real.example.net."}]}),
    );
    let zone = build_zone(&apex, soa_and(own, false)).unwrap();
    let ns: Vec<_> = zone.rrset(apex.as_name_ref(), Type::NS).collect();
    assert_eq!(ns.len(), 1);
    assert_eq!(ns[0].rdata, b"\x04real\x07example\x03net\x00");
}

#[test]
fn records_outside_the_zone_fail_the_build() {
    let apex: Name = "example.org.".parse().unwrap();
    let stray = set(
        json!({"fqdn": "www.other.example.", "TTL": 60, "ARecords": [{"ipv4Address": "192.0.2.1"}]}),
    );
    assert!(build_zone(&apex, soa_and(stray, true)).is_err());
}
