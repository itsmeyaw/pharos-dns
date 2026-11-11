#![forbid(unsafe_code)]
#![cfg(feature = "plugin-siit")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/siit/setup_test.go.
#[test]
fn coredns_siit_setup_cases() {
    for (directive, valid) in [
        ("siit", true),
        ("siit {\n ipv6_prefix 64:dead::/96\n}", true),
        ("siit {\n ipv6_prefix 10.0.0.0/8\n}", false),
        ("siit {\n ipv6_prefix foobar\n}", false),
        ("siit {\n eam 10.0.0.1 64:dead::1\n}", true),
        (
            "siit {\n eam 10.0.0.1 64:dead::1\n eam 10.0.0.2 64:dead::2\n}",
            true,
        ),
        ("siit {\n eam 64:dead::1 10.0.0.1\n}", false),
        ("siit {\n eam foobar 64:dead::1\n}", false),
        ("siit {\n eam 10.0.0.1 foobar\n}", false),
        ("siit {\n ipv6_prefix 64:ff9b::/72\n}", false),
        ("siit {\n ipv6_prefix 64:ff9b::/32\n}", true),
        ("siit {\n ipv6_prefix 64:ff9b::/40\n}", true),
        ("siit {\n ipv6_prefix 64:ff9b::/48\n}", true),
        ("siit {\n ipv6_prefix 64:ff9b::/56\n}", true),
        ("siit {\n ipv6_prefix 64:ff9b::/64\n}", true),
        ("siit {\n ipv6_prefix 2001:db8:122:344:ff00::/96\n}", false),
        ("siit {\n ipv6_prefix 2001:db8::/96\n}", true),
        ("siit {\n eam 10.0.0.1\n}", false),
        ("siit {\n eam 10.0.0.1 64:dead::1 extra\n}", false),
    ] {
        let text = format!(".:53 {{\n{directive}\n}}");
        let blocks = parse("Corefile", &text).unwrap();
        assert_eq!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            valid,
            "{directive}"
        );
    }
}
