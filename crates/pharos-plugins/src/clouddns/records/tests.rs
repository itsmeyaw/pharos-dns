use pharos_proto::{Name, Type};

use super::*;

fn apex() -> Name {
    "example.org.".parse().unwrap()
}

fn rrset(name: &str, rtype: &str, ttl: u32, data: &[&str]) -> Rrset {
    Rrset {
        name: name.to_owned(),
        rtype: rtype.to_owned(),
        ttl,
        rrdatas: data.iter().map(|value| (*value).to_owned()).collect(),
    }
}

// Cloud DNS managed zones always carry an apex SOA and NS.
fn with_apex(mut rrsets: Vec<Rrset>) -> Vec<Rrset> {
    rrsets.push(rrset(
        "example.org.",
        "SOA",
        21600,
        &["ns-cloud-e1.googledomains.com. cloud-dns-hostmaster.google.com. 1 21600 3600 259200 300"],
    ));
    rrsets.push(rrset(
        "example.org.",
        "NS",
        21600,
        &["ns-cloud-e1.googledomains.com."],
    ));
    rrsets
}

fn zone(rrsets: Vec<Rrset>) -> Zone {
    build(&apex(), "p:z", &with_apex(rrsets)).unwrap()
}

fn texts(zone: &Zone, rtype: Type) -> Vec<String> {
    zone.records()
        .iter()
        .filter(|record| record.rtype == rtype)
        .map(|record| {
            let data = pharos_proto::Rdata::parse(record.rtype, &record.rdata).unwrap();
            format!("{} {} {data}", record.owner, record.ttl)
        })
        .collect()
}

// CoreDNS v1.15.0 plugin/clouddns/clouddns.go updateZoneFromRRS: one record per value, owners made absolute.
#[test]
fn each_value_becomes_a_record_with_an_absolute_owner() {
    let zone = zone(vec![
        rrset("www.example.org", "A", 300, &["192.0.2.1", "192.0.2.2"]),
        rrset(
            "example.org.",
            "AAAA",
            60,
            &["2001:db8:85a3::8a2e:370:7334"],
        ),
    ]);
    assert_eq!(
        texts(&zone, Type::A),
        [
            "www.example.org. 300 192.0.2.1",
            "www.example.org. 300 192.0.2.2"
        ]
    );
    assert_eq!(
        texts(&zone, Type::AAAA),
        ["example.org. 60 2001:db8:85a3::8a2e:370:7334"]
    );
}

// CoreDNS v1.15.0 plugin/clouddns/clouddns.go updateZoneFromRRS: CNAME and PTR values are made absolute.
#[test]
fn cname_and_ptr_values_are_made_absolute() {
    let zone = zone(vec![
        rrset("a.example.org.", "CNAME", 300, &["www.example.org"]),
        rrset("b.example.org.", "PTR", 300, &["ptr.example.org"]),
    ]);
    assert_eq!(
        texts(&zone, Type::CNAME),
        ["a.example.org. 300 www.example.org."]
    );
    assert_eq!(
        texts(&zone, Type::PTR),
        ["b.example.org. 300 ptr.example.org."]
    );
}

// miekg/dns NewRR resolves relative names in rdata against the root: the CoreDNS fixture's SRV targets stay as written.
#[test]
fn relative_names_in_rdata_are_not_put_under_the_apex() {
    let zone = zone(vec![rrset(
        "_dummy._tcp.example.org.",
        "SRV",
        300,
        &["0 0 5269 split-example.org", "0 0 5269 other-example.org"],
    )]);
    assert_eq!(
        texts(&zone, Type::SRV),
        [
            "_dummy._tcp.example.org. 300 0 0 5269 split-example.org.",
            "_dummy._tcp.example.org. 300 0 0 5269 other-example.org."
        ]
    );
}

#[test]
fn wildcard_owners_and_txt_strings_survive() {
    let zone = zone(vec![
        rrset("*.www.example.org.", "CNAME", 300, &["www.example.org."]),
        rrset(
            "example.org.",
            "TXT",
            300,
            &["\"v=spf1 a ; b\"", "\"two words\""],
        ),
    ]);
    assert_eq!(
        texts(&zone, Type::CNAME),
        ["*.www.example.org. 300 www.example.org."]
    );
    assert_eq!(texts(&zone, Type::TXT).len(), 2);
}

// ADR-0002: CoreDNS stops at the first unparsable value and ignores the error; Pharos skips that record set only.
#[test]
fn an_unparsable_record_set_is_skipped_and_the_rest_kept() {
    let zone = zone(vec![
        rrset("before.example.org.", "A", 300, &["192.0.2.1"]),
        rrset("swag.example.org.", "YOLO", 300, &["foobar"]),
        rrset(
            "bad.example.org.",
            "A",
            300,
            &["192.0.2.2", "not-an-address"],
        ),
        rrset("after.example.org.", "A", 300, &["192.0.2.3"]),
    ]);
    assert_eq!(
        texts(&zone, Type::A),
        [
            "before.example.org. 300 192.0.2.1",
            "after.example.org. 300 192.0.2.3"
        ]
    );
}

// RFC 2181 §6.1: Pharos zones hold in-zone owners only; the CoreDNS fixture's out-of-zone records are skipped.
#[test]
fn out_of_zone_record_sets_are_skipped() {
    let zone = zone(vec![
        rrset("split-example.gov.", "A", 300, &["1.2.3.4"]),
        rrset("example.org.org.", "A", 300, &["1.2.3.5"]),
        rrset("in.example.org.", "A", 300, &["1.2.3.6"]),
        rrset("com.", "NS", 300, &["ns-cloud-c4.googledomains.com."]),
    ]);
    assert_eq!(texts(&zone, Type::A), ["in.example.org. 300 1.2.3.6"]);
    assert_eq!(texts(&zone, Type::NS).len(), 1);
}

#[test]
fn control_characters_cannot_start_another_entry() {
    let zone = zone(vec![
        rrset(
            "evil.example.org.",
            "TXT",
            300,
            &["\"x\"\nsmuggled.example.org. 300 IN A 192.0.2.99"],
        ),
        rrset("evil.example.org\n$ORIGIN x.", "A", 300, &["192.0.2.98"]),
        rrset("$GENERATE.", "A", 300, &["192.0.2.97"]),
        rrset("ok.example.org.", "A\nB", 300, &["192.0.2.96"]),
        rrset("fine.example.org.", "A", 300, &["192.0.2.1"]),
    ]);
    assert_eq!(texts(&zone, Type::A), ["fine.example.org. 300 192.0.2.1"]);
    assert!(texts(&zone, Type::TXT).is_empty());
}

#[test]
fn record_sets_without_values_add_nothing() {
    let zone = zone(vec![rrset("empty.example.org.", "A", 300, &[])]);
    assert!(texts(&zone, Type::A).is_empty());
}

// RFC 1035 §5.2: a Zone needs its SOA; a listing without one is an error, so the last good Zone stays.
#[test]
fn a_listing_without_an_apex_soa_is_an_error() {
    let rrsets = vec![rrset("www.example.org.", "A", 300, &["192.0.2.1"])];
    assert!(build(&apex(), "p:z", &rrsets).is_err());
    assert!(build(&apex(), "p:z", &[]).is_err());
}

#[test]
fn absolute_names_are_recognised_like_miekg_dns() {
    assert_eq!(fqdn("a.b"), "a.b.");
    assert_eq!(fqdn("a.b."), "a.b.");
    assert_eq!(fqdn("a\\."), "a\\..");
    assert_eq!(fqdn("a\\\\."), "a\\\\.");
}
