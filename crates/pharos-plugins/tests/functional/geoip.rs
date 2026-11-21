#![cfg(feature = "plugin-geoip")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/geoip");

fn fixture(name: &str) -> String {
    format!("{FIXTURES}/{name}")
}

fn setup(text: &str) -> Result<Vec<pharos_corefile::BlockContext<Chain>>, String> {
    let blocks = parse("Corefile", text).map_err(|error| error.to_string())?;
    configure::<Chain>(&blocks, directives()).map_err(|error| error.to_string())
}

// Derived from CoreDNS v1.15.0 plugin/geoip/setup_test.go TestSetup and TestGeoIPParse.
#[test]
fn coredns_valid_setup_cases() {
    for database in ["GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb"] {
        let path = fixture(database);
        for directive in [
            format!("geoip {path}"),
            format!("geoip {path} {{ edns-subnet }}"),
            format!("geoip {path} {{\n edns-subnet\n}}"),
        ] {
            let configured = setup(&format!(".:53 {{\n{directive}\n}}")).unwrap();
            assert!(configured[0].config.geoip.is_some(), "{directive}");
        }
    }
}

// Derived from CoreDNS v1.15.0 plugin/geoip/setup_test.go TestGeoIPParse.
#[test]
fn coredns_invalid_setup_cases() {
    let city = fixture("GeoLite2-City.mmdb");
    let unknown = fixture("GeoLite2-UnknownDbType.mmdb");
    for (directive, expected) in [
        ("geoip".to_owned(), "Wrong argument count"),
        (
            format!("geoip {city} {{\n languages en fr es zh-CN\n}}"),
            "unknown property \"languages\"",
        ),
        (
            format!("geoip {city}\ngeoip {city}"),
            "configuring multiple databases is not supported",
        ),
        ("geoip 1 2 3".to_owned(), "Wrong argument count"),
        ("geoip { }".to_owned(), "Wrong argument count"),
        (
            "geoip /dbpath { city }".to_owned(),
            "unknown property \"city\"",
        ),
        (
            "geoip /invalidPath".to_owned(),
            "failed to open database file: open /invalidPath:",
        ),
        (
            format!("geoip {unknown}"),
            "reader does not support the \"UnknownDbType\" database type",
        ),
    ] {
        let error = setup(&format!(".:53 {{\n{directive}\n}}"))
            .err()
            .unwrap_or_default();
        assert!(
            error.contains(expected),
            "{directive}: expected {expected:?}, got {error:?}"
        );
    }
}

#[cfg(all(
    feature = "plugin-metadata",
    feature = "plugin-view",
    feature = "plugin-hosts"
))]
mod labels {
    use pharos_corefile::{configure, parse};
    use pharos_plugins::{Chain, directives, servers};
    use pharos_proto::Message;
    use pharos_server::{Handler, Protocol};

    use super::fixture;

    const QUERY: &[u8] =
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

    /// A Query with one EDNS Client Subnet option naming `address` in full.
    fn query(subnet: Option<&str>) -> Vec<u8> {
        let mut wire = QUERY.to_vec();
        let Some(subnet) = subnet else { return wire };
        let address: std::net::IpAddr = subnet.parse().unwrap();
        let (family, octets) = match address {
            std::net::IpAddr::V4(address) => (1_u16, address.octets().to_vec()),
            std::net::IpAddr::V6(address) => (2, address.octets().to_vec()),
        };
        wire[10..12].copy_from_slice(&1_u16.to_be_bytes());
        let length = u16::try_from(4 + octets.len()).unwrap();
        // RFC 6891 §6.1.2 and RFC 7871 §6: an OPT record carrying one Client Subnet option.
        wire.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0, 0]);
        wire.extend_from_slice(&(length + 4).to_be_bytes());
        wire.extend_from_slice(&8_u16.to_be_bytes());
        wire.extend_from_slice(&length.to_be_bytes());
        wire.extend_from_slice(&family.to_be_bytes());
        wire.push(u8::try_from(octets.len() * 8).unwrap());
        wire.push(0);
        wire.extend_from_slice(&octets);
        wire
    }

    /// Which Server Block answered: the view selected by a geoip label returns 192.0.2.1.
    async fn answered_by_view(
        text: &str,
        peer: &str,
        subnet: Option<&str>,
        protocol: Protocol,
    ) -> bool {
        let blocks = parse("Corefile", text).unwrap();
        let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
        let server = servers.values().next().unwrap();
        let mut response = Vec::with_capacity(65_535);
        server
            .handle(
                &query(subnet),
                peer.parse().unwrap(),
                protocol,
                &mut response,
            )
            .await;
        let rdata = Message::parse(&response)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata
            .to_vec();
        match rdata.as_slice() {
            [192, 0, 2, 1] => true,
            [192, 0, 2, 2] => false,
            other => panic!("unexpected answer {other:?}"),
        }
    }

    fn corefile(directives: &str, expression: &str) -> String {
        format!(
            ".:53 {{\n {directives}\n view selected {{\n  expr {expression}\n }}\n hosts {{\n  192.0.2.1 example.com\n }}\n}}\n.:53 {{\n hosts {{\n  192.0.2.2 example.com\n }}\n}}"
        )
    }

    #[tokio::test]
    async fn later_plugins_read_ipv4_ipv6_and_subnet_labels() {
        let city = fixture("GeoLite2-City.mmdb");
        let ipv6 = fixture("Pharos-City-IPv6.mmdb");
        let cambridge = corefile(
            &format!("metadata\n geoip {city} {{\n  edns-subnet\n }}"),
            "metadata('geoip/city/name') == 'Cambridge'",
        );
        let zurich = corefile(
            &format!("metadata\n geoip {ipv6}"),
            "metadata('geoip/city/name') == 'Zürich' && metadata('geoip/latitude') == '47.5'",
        );
        for protocol in [Protocol::Udp, Protocol::Tcp] {
            // IPv4 source address.
            assert!(answered_by_view(&cambridge, "81.2.69.142:1234", None, protocol).await);
            // IPv4-mapped IPv6 source address is looked up as IPv4.
            assert!(
                answered_by_view(&cambridge, "[::ffff:81.2.69.142]:1234", None, protocol).await
            );
            // RFC 7871 §6: the subnet replaces the source address when `edns-subnet` is set.
            assert!(
                answered_by_view(&cambridge, "127.0.0.1:1234", Some("81.2.69.142"), protocol).await
            );
            // An address that is not in the database publishes only zero values.
            assert!(!answered_by_view(&cambridge, "203.0.113.1:1234", None, protocol).await);
            assert!(!answered_by_view(&cambridge, "127.0.0.1:1234", None, protocol).await);
            // IPv6 source address.
            assert!(answered_by_view(&zurich, "[2001:db8:1::7]:1234", None, protocol).await);
            assert!(!answered_by_view(&zurich, "[2001:db8:9::7]:1234", None, protocol).await);
        }
    }

    #[tokio::test]
    async fn subnet_is_ignored_without_edns_subnet() {
        let city = fixture("GeoLite2-City.mmdb");
        let text = corefile(
            &format!("metadata\n geoip {city}"),
            "metadata('geoip/city/name') == 'Cambridge'",
        );
        assert!(
            !answered_by_view(&text, "127.0.0.1:1234", Some("81.2.69.142"), Protocol::Udp).await
        );
        assert!(
            answered_by_view(
                &text,
                "81.2.69.142:1234",
                Some("203.0.113.1"),
                Protocol::Udp
            )
            .await
        );
    }

    #[tokio::test]
    async fn asn_labels_are_published() {
        let asn = fixture("GeoLite2-ASN.mmdb");
        let text = corefile(
            &format!("metadata\n geoip {asn}"),
            "metadata('geoip/asn/number') == '12345' && metadata('geoip/asn/org') == 'Test ASN Organization'",
        );
        assert!(answered_by_view(&text, "81.2.69.142:1234", None, Protocol::Udp).await);
        assert!(!answered_by_view(&text, "203.0.113.1:1234", None, Protocol::Udp).await);
    }

    #[tokio::test]
    async fn labels_need_the_metadata_plugin_and_its_domains() {
        let city = fixture("GeoLite2-City.mmdb");
        let expression = "metadata('geoip/city/name') == 'Cambridge'";
        // CoreDNS v1.15.0 plugin/metadata: Providers run only where the metadata Plugin is configured.
        let without = corefile(&format!("geoip {city}"), expression);
        assert!(!answered_by_view(&without, "81.2.69.142:1234", None, Protocol::Udp).await);
        // CoreDNS v1.15.0 plugin/metadata: collection is limited to the configured Zones.
        let other_zone = corefile(&format!("metadata example.org\n geoip {city}"), expression);
        assert!(!answered_by_view(&other_zone, "81.2.69.142:1234", None, Protocol::Udp).await);
        let zone = corefile(&format!("metadata example.com\n geoip {city}"), expression);
        assert!(answered_by_view(&zone, "81.2.69.142:1234", None, Protocol::Udp).await);
    }
}
