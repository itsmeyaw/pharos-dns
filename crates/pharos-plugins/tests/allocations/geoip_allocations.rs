#![forbid(unsafe_code)]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::{
    alloc::System,
    future::Future,
    task::{Context as TaskContext, Poll, Waker},
};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const DATABASES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/geoip");

// RFC 1035 §4.1: a header and the Question `example.com. A IN`.
const PLAIN_QUERY: &[u8] =
    b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

/// RFC 6891 §6.1.2 and RFC 7871 §6: the Query with an OPT record carrying a Client Subnet option for 81.2.69.142/32.
fn subnet_query() -> Vec<u8> {
    let mut wire = PLAIN_QUERY.to_vec();
    wire[10..12].copy_from_slice(&1_u16.to_be_bytes());
    wire.extend_from_slice(&[
        0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 12, 0, 8, 0, 8, 0, 1, 32, 0, 81, 2, 69, 142,
    ]);
    wire
}

/// Serve one warmed Query and return whether the lookup published labels.
fn measure(client: &str, subnet: bool, database: &str, edns_subnet: bool) -> bool {
    let directive = if edns_subnet {
        format!("geoip {DATABASES}/{database} {{\n edns-subnet\n}}")
    } else {
        format!("geoip {DATABASES}/{database}")
    };
    let blocks = parse(
        "Corefile",
        &format!(". {{\n metadata\n {directive}\n whoami\n}}"),
    )
    .unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let wire = if subnet {
        subnet_query()
    } else {
        PLAIN_QUERY.to_vec()
    };
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    // Warm any process-wide state with one Query before measuring.
    for measured in [false, true] {
        response.clear();
        let mut slots = [];
        let mut context = Context {
            query: Message::parse(&wire).unwrap(),
            client: format!("{client}:53").parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let region = Region::new(GLOBAL);
        let result = {
            let future = configured[0].config.serve(&mut context);
            let mut future = std::pin::pin!(future);
            future
                .as_mut()
                .poll(&mut TaskContext::from_waker(Waker::noop()))
        };
        let stats = region.change();
        assert_eq!(result, Poll::Ready(Outcome::Response));
        if measured {
            assert_eq!(
                (stats.allocations, stats.reallocations),
                (0, 0),
                "{client} {database}"
            );
            return ["geoip/country/code", "geoip/asn/number"]
                .iter()
                .any(|label| context.metadata.get(label).is_some());
        }
    }
    unreachable!()
}

#[test]
fn city_lookup_does_not_allocate_per_query() {
    if crate::run_isolated("geoip::cases::city_lookup_does_not_allocate_per_query") {
        return;
    }
    assert!(measure("81.2.69.142", false, "GeoLite2-City.mmdb", false));
    assert!(measure("203.0.113.1", false, "GeoLite2-City.mmdb", false));
    assert!(measure(
        "[2001:db8:1::1]",
        false,
        "Pharos-City-IPv6.mmdb",
        false
    ));
    // An IPv6 address in an IPv4-only database publishes nothing.
    assert!(!measure(
        "[2001:db8:1::1]",
        false,
        "Pharos-City-IPv4.mmdb",
        false
    ));
}

#[test]
fn subnet_lookup_does_not_allocate_per_query() {
    if crate::run_isolated("geoip::cases::subnet_lookup_does_not_allocate_per_query") {
        return;
    }
    assert!(measure("127.0.0.1", true, "GeoLite2-City.mmdb", true));
}

#[test]
fn asn_lookup_does_not_allocate_per_query() {
    if crate::run_isolated("geoip::cases::asn_lookup_does_not_allocate_per_query") {
        return;
    }
    assert!(measure("81.2.69.142", false, "GeoLite2-ASN.mmdb", false));
    assert!(measure(
        "[2001:db8:2::1]",
        false,
        "Pharos-ISP-IPv6.mmdb",
        false
    ));
}
