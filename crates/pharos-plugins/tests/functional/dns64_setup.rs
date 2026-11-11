#![forbid(unsafe_code)]
#![cfg(feature = "plugin-dns64")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/dns64/setup_test.go.
#[test]
fn coredns_dns64_setup_cases() {
    for length in [32, 40, 48, 56, 64, 72, 80, 88, 96] {
        for directive in [
            format!("dns64 2001:db8::/{length}"),
            format!("dns64 {{\n prefix 2001:db8::/{length}\n}}"),
        ] {
            let text = format!(".:53 {{\n{directive}\n}}");
            let blocks = parse("Corefile", &text).unwrap();
            assert_eq!(
                configure::<Chain>(&blocks, directives()).is_ok(),
                !matches!(length, 72 | 80 | 88),
                "{directive}"
            );
        }
    }
    for (directive, valid) in [
        ("dns64", true),
        ("dns64 64:dead::/96", true),
        ("dns64 {\n translate_all\n}", true),
        ("dns64 {\n prefix 64:ff9b::/96\n}", true),
        ("dns64 {\n prefix 64:ff9b::/32\n}", true),
        ("dns64 {\n prefix 64:ff9b::/52\n}", false),
        ("dns64 {\n prefix 64:ff9b::/104\n}", false),
        ("dns64 {\n prefix 8.8.8.8/24\n}", false),
        ("dns64 {\n prefix 2002:ac12:b083::/96\n}", true),
        ("dns64 {\n prefix 2002:c0a8:a88a::/48\n}", true),
        ("dns64 foobar {\n prefix 64:ff9b::/96\n}", false),
        ("dns64 foobar", false),
        ("dns64 {\n foobar\n}", false),
        ("dns64 {\n allow_ipv4\n}", true),
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
