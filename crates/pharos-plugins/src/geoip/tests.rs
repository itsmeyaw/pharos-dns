use std::net::{IpAddr, SocketAddr};

use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Protocol, Transport};

use super::GeoIp;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/geoip");

fn fixture(name: &str) -> String {
    format!("{FIXTURES}/{name}")
}

fn city() -> String {
    fixture("GeoLite2-City.mmdb")
}

fn asn() -> String {
    fixture("GeoLite2-ASN.mmdb")
}

/// A Query with an optional EDNS Client Subnet option naming the full address.
fn query(subnet: Option<IpAddr>) -> Vec<u8> {
    let mut wire = vec![0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    if let Some(address) = subnet {
        let (family, bytes) = match address {
            IpAddr::V4(address) => (1_u16, address.octets().to_vec()),
            IpAddr::V6(address) => (2, address.octets().to_vec()),
        };
        wire[10..12].copy_from_slice(&1_u16.to_be_bytes());
        let length = u16::try_from(4 + bytes.len()).unwrap();
        // RFC 6891 §6.1.2 and RFC 7871 §6: an OPT record carrying one Client Subnet option.
        wire.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0, 0]);
        wire.extend_from_slice(&(length + 4).to_be_bytes());
        wire.extend_from_slice(&8_u16.to_be_bytes());
        wire.extend_from_slice(&length.to_be_bytes());
        wire.extend_from_slice(&family.to_be_bytes());
        wire.push(u8::try_from(bytes.len() * 8).unwrap());
        wire.push(0);
        wire.extend_from_slice(&bytes);
    }
    wire
}

/// Collect Metadata for one Query and return the value of `labels` in order.
fn collect(
    plugin: &GeoIp,
    client: &str,
    subnet: Option<&str>,
    labels: &[&str],
) -> Vec<Option<String>> {
    let wire = query(subnet.map(|address| address.parse().unwrap()));
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::new();
    let mut slots = [];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: SocketAddr::new(client.parse().unwrap(), 53),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    plugin.collect_metadata(&mut cx);
    labels
        .iter()
        .map(|label| cx.metadata.get(label).map(str::to_owned))
        .collect()
}

fn label(plugin: &GeoIp, client: &str, subnet: Option<&str>, label: &str) -> Option<String> {
    collect(plugin, client, subnet, &[label]).remove(0)
}

// Derived from CoreDNS v1.15.0 plugin/geoip/geoip_test.go TestMetadata.
#[test]
fn coredns_metadata_labels() {
    let cases = [
        ("geoip/city/name", "Cambridge", city(), "81.2.69.142"),
        ("geoip/country/code", "GB", city(), "81.2.69.142"),
        (
            "geoip/country/name",
            "United Kingdom",
            city(),
            "81.2.69.142",
        ),
        (
            "geoip/country/is_in_european_union",
            "true",
            city(),
            "81.2.69.142",
        ),
        ("geoip/continent/code", "EU", city(), "81.2.69.142"),
        ("geoip/continent/name", "Europe", city(), "81.2.69.142"),
        ("geoip/latitude", "52.2242", city(), "81.2.69.142"),
        ("geoip/longitude", "0.1315", city(), "81.2.69.142"),
        ("geoip/timezone", "Europe/London", city(), "81.2.69.142"),
        ("geoip/postalcode", "CB4", city(), "81.2.69.142"),
        ("geoip/subdivisions/code", "ENG,CAM", city(), "81.2.69.142"),
        ("geoip/asn/number", "12345", asn(), "81.2.69.142"),
        (
            "geoip/asn/org",
            "Test ASN Organization",
            asn(),
            "81.2.69.142",
        ),
        // Test data from iptoasn.com: ranges without an assigned ASN.
        ("geoip/asn/number", "0", asn(), "10.0.0.1"),
        ("geoip/asn/org", "Not routed", asn(), "10.0.0.1"),
    ];
    for (name, expected, path, address) in cases {
        let direct = GeoIp::open(&path, false).unwrap();
        assert_eq!(
            label(&direct, address, None, name).as_deref(),
            Some(expected),
            "{name} direct"
        );
        let subnet = GeoIp::open(&path, true).unwrap();
        assert_eq!(
            label(&subnet, "127.0.0.1", Some(address), name).as_deref(),
            Some(expected),
            "{name} subnet"
        );
    }
}

#[test]
fn subnet_is_ignored_without_edns_subnet() {
    let plugin = GeoIp::open(&city(), false).unwrap();
    assert_eq!(
        label(&plugin, "127.0.0.1", Some("81.2.69.142"), "geoip/city/name").as_deref(),
        Some("")
    );
}

#[test]
fn source_address_is_used_when_the_query_has_no_subnet() {
    let plugin = GeoIp::open(&city(), true).unwrap();
    assert_eq!(
        label(&plugin, "81.2.69.142", None, "geoip/city/name").as_deref(),
        Some("Cambridge")
    );
}

// Derived from CoreDNS v1.15.0 plugin/geoip/geoip_test.go TestMetadataUnknownIP.
#[test]
fn unknown_address_in_the_asn_database_publishes_zero_values() {
    let plugin = GeoIp::open(&asn(), false).unwrap();
    // TEST-NET-3 is not in the fixture.
    let values = collect(
        &plugin,
        "203.0.113.1",
        None,
        &["geoip/asn/number", "geoip/asn/org"],
    );
    assert_eq!(values, [Some("0".to_owned()), Some(String::new())]);
}

#[test]
fn unknown_address_in_the_city_database_publishes_empty_labels() {
    let plugin = GeoIp::open(&city(), false).unwrap();
    let labels = [
        "geoip/city/name",
        "geoip/country/name",
        "geoip/continent/name",
        "geoip/country/code",
        "geoip/subdivisions/code",
        "geoip/country/is_in_european_union",
        "geoip/continent/code",
        "geoip/latitude",
        "geoip/longitude",
        "geoip/timezone",
        "geoip/postalcode",
    ];
    let values = collect(&plugin, "203.0.113.1", None, &labels);
    for (name, value) in labels.iter().zip(values) {
        let expected = if *name == "geoip/country/is_in_european_union" {
            "false"
        } else {
            ""
        };
        assert_eq!(value.as_deref(), Some(expected), "{name}");
    }
}

#[test]
fn databases_publish_only_their_own_schema() {
    let city_plugin = GeoIp::open(&city(), false).unwrap();
    assert_eq!(
        label(&city_plugin, "81.2.69.142", None, "geoip/asn/number"),
        None
    );
    let asn_plugin = GeoIp::open(&asn(), false).unwrap();
    assert_eq!(
        label(&asn_plugin, "81.2.69.142", None, "geoip/city/name"),
        None
    );
}

#[test]
fn ipv4_mapped_addresses_find_the_ipv4_record() {
    let plugin = GeoIp::open(&city(), true).unwrap();
    // Go prints an IPv4-mapped source address as IPv4, so the source address is canonicalized.
    assert_eq!(
        label(&plugin, "::ffff:81.2.69.142", None, "geoip/city/name").as_deref(),
        Some("Cambridge")
    );
}

#[test]
fn ipv6_address_publishes_float32_coordinates_and_utf8_names() {
    let plugin = GeoIp::open(&fixture("Pharos-City-IPv6.mmdb"), false).unwrap();
    let labels = [
        "geoip/city/name",
        "geoip/latitude",
        "geoip/longitude",
        "geoip/timezone",
        "geoip/postalcode",
        "geoip/country/is_in_european_union",
        // A subdivision without an ISO code keeps its comma separator.
        "geoip/subdivisions/code",
    ];
    let values = collect(&plugin, "2001:db8:1::1", None, &labels);
    let expected = [
        "Zürich",
        "47.5",
        "8.25",
        "Europe/Zurich",
        "8001",
        "false",
        "ZH,,X",
    ];
    for ((name, value), expected) in labels.iter().zip(values).zip(expected) {
        assert_eq!(value.as_deref(), Some(expected), "{name}");
    }
}

#[test]
fn ipv6_subnet_is_looked_up() {
    let plugin = GeoIp::open(&fixture("Pharos-City-IPv6.mmdb"), true).unwrap();
    assert_eq!(
        label(
            &plugin,
            "127.0.0.1",
            Some("2001:db8:1::"),
            "geoip/country/code"
        )
        .as_deref(),
        Some("CH")
    );
    assert_eq!(
        label(
            &plugin,
            "127.0.0.1",
            Some("2001:db8:9::"),
            "geoip/country/code"
        )
        .as_deref(),
        Some("")
    );
}

#[test]
fn oversized_subdivision_codes_are_omitted() {
    let plugin = GeoIp::open(&fixture("Pharos-City-IPv6.mmdb"), false).unwrap();
    let values = collect(
        &plugin,
        "2001:db8:3::1",
        None,
        &["geoip/country/code", "geoip/subdivisions/code"],
    );
    assert_eq!(values, [Some("CH".to_owned()), None]);
}

#[test]
fn isp_database_publishes_the_asn_schema() {
    let plugin = GeoIp::open(&fixture("Pharos-ISP-IPv6.mmdb"), false).unwrap();
    assert!(!plugin.city && plugin.asn);
    let values = collect(
        &plugin,
        "2001:db8:2::1",
        None,
        &["geoip/asn/number", "geoip/asn/org"],
    );
    assert_eq!(
        values,
        [Some("64500".to_owned()), Some("Example ISP".to_owned())]
    );
}

#[test]
fn ipv6_in_an_ipv4_only_database_publishes_nothing() {
    let plugin = GeoIp::open(&fixture("Pharos-City-IPv4.mmdb"), true).unwrap();
    assert_eq!(
        label(&plugin, "81.2.69.142", None, "geoip/city/name").as_deref(),
        Some("Cambridge")
    );
    assert_eq!(label(&plugin, "2001:db8::1", None, "geoip/city/name"), None);
    // An IPv4-mapped source is looked up as IPv4, never as IPv6.
    assert_eq!(
        label(&plugin, "::ffff:81.2.69.142", None, "geoip/city/name").as_deref(),
        Some("Cambridge")
    );
    assert_eq!(
        label(&plugin, "127.0.0.1", Some("2001:db8::1"), "geoip/city/name"),
        None
    );
}

// Derived from CoreDNS v1.15.0 plugin/geoip/setup_test.go TestGeoIPParse.
#[test]
fn database_type_selects_schemas() {
    let plugin = GeoIp::open(&city(), false).unwrap();
    assert!(plugin.city && !plugin.asn);
    let plugin = GeoIp::open(&asn(), true).unwrap();
    assert!(!plugin.city && plugin.asn && plugin.edns_subnet);
}

#[test]
fn unsupported_database_is_rejected() {
    let error = GeoIp::open(&fixture("GeoLite2-UnknownDbType.mmdb"), false).unwrap_err();
    assert!(
        error.contains("reader does not support the \"UnknownDbType\" database type"),
        "{error}"
    );
}

#[test]
fn missing_database_is_rejected() {
    let error = GeoIp::open("/invalidPath", false).unwrap_err();
    assert!(
        error.contains("failed to open database file: open /invalidPath:"),
        "{error}"
    );
}

#[test]
fn corrupt_database_is_rejected() {
    let path =
        std::env::temp_dir().join(format!("pharos-geoip-corrupt-{}.mmdb", std::process::id()));
    std::fs::write(&path, b"not a database").unwrap();
    let error = GeoIp::open(path.to_str().unwrap(), false).unwrap_err();
    std::fs::remove_file(&path).unwrap();
    assert!(
        error.starts_with("failed to open database file:"),
        "{error}"
    );
}

#[test]
fn schema_classification_follows_geoip2_golang() {
    use super::schemas;
    assert_eq!(schemas("GeoLite2-City"), Some((true, false)));
    assert_eq!(schemas("GeoIP2-Enterprise"), Some((true, false)));
    assert_eq!(schemas("GeoLite2-Country"), Some((true, false)));
    assert_eq!(schemas("GeoLite2-ASN"), Some((false, true)));
    assert_eq!(schemas("GeoIP2-ISP"), Some((false, true)));
    assert_eq!(schemas("GeoIP2-Domain"), Some((false, false)));
    assert_eq!(schemas("GeoIP2-Anonymous-IP"), Some((false, false)));
    assert_eq!(schemas("nope"), None);
}
