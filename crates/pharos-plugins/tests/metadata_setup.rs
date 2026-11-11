#![recursion_limit = "512"]
#![cfg(all(feature = "plugin-metadata", feature = "plugin-whoami"))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/metadata/setup_test.go.
#[test]
fn coredns_metadata_setup_cases() {
    for directive in [
        "metadata",
        "metadata example.com.",
        "metadata example.com. net.",
        "metadata {}",
    ] {
        let text = format!(".:53 {{\n{directive}\n whoami\n}}");
        let blocks = parse("Corefile", &text).unwrap();
        assert!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            "{directive}"
        );
    }
    for directive in ["metadata example.com. { some_param }", "metadata\nmetadata"] {
        let text = format!(".:53 {{\n{directive}\n whoami\n}}");
        let blocks = parse("Corefile", &text).unwrap();
        assert!(
            configure::<Chain>(&blocks, directives()).is_err(),
            "{directive}"
        );
    }
}
