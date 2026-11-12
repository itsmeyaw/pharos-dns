#![forbid(unsafe_code)]
#![cfg(feature = "plugin-transfer")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/transfer/setup_test.go, TestParse.
#[test]
fn coredns_transfer_setup_cases() {
    for (directive, valid) in [
        (
            "transfer example.net example.org {\n to 1.2.3.4 5.6.7.8:1053 [1::2]:34\n source 2001:db8::53\n}",
            true,
        ),
        ("transfer {\n to * 1.2.3.4\n}", true),
        ("transfer example.net example.org {\n}", false),
        ("transfer {\n invalid option\n}", false),
        ("transfer {\n to 1.2.3.4\n source example.org\n}", false),
        (
            "transfer {\n to 1.2.3.4\n source 192.0.2.53\n source 2001:db8::53\n}",
            false,
        ),
        ("transfer {\n to example.com 1.2.3.4\n}", false),
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
