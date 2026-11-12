#![cfg(feature = "plugin-dnssec")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

fn accepts(directive: &str) -> bool {
    let text = format!("example.org:53 {{\n{directive}\n}}");
    parse("Corefile", &text)
        .and_then(|blocks| configure::<Chain>(&blocks, directives()))
        .is_ok()
}

// Derived from CoreDNS v1.15.0 plugin/dnssec/setup_test.go.
#[test]
fn coredns_setup_without_keys() {
    for directive in [
        "dnssec",
        "dnssec example.org",
        "dnssec 10.0.0.0/8",
        "dnssec {\n cache_capacity 500\n}",
        "dnssec {\n cache_capacity -1\n}",
        "dnssec {\n cache_capacity 0\n}",
    ] {
        assert!(accepts(directive), "rejected {directive}");
    }
    for directive in [
        "dnssec\n dnssec",
        "dnssec {\n cache_capacity\n}",
        "dnssec {\n cache_capacity nope\n}",
        "dnssec {\n invalid\n}",
        "dnssec {\n key file\n}",
        "dnssec {\n key aws_secretsmanager\n}",
    ] {
        assert!(!accepts(directive), "accepted {directive}");
    }
}

#[test]
fn key_file_extensions_and_owner_scope() {
    let base = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dnssec/Kmiek.nl.+013+59725"
    );
    for suffix in ["", ".key", ".private"] {
        let text = format!("miek.nl {{\n dnssec {{\n key file {base}{suffix}\n }}\n}}");
        assert!(
            parse("Corefile", &text)
                .and_then(|blocks| configure::<Chain>(&blocks, directives()))
                .is_ok(),
            "{suffix}"
        );
    }
    let text = format!("example.org {{\n dnssec {{\n key file {base}\n }}\n}}");
    assert!(
        parse("Corefile", &text)
            .and_then(|blocks| configure::<Chain>(&blocks, directives()))
            .is_err()
    );
    assert!(!accepts("dnssec {\n key file /does/not/exist\n}"));
}

#[cfg(not(feature = "dnssec-aws"))]
#[test]
fn aws_key_requires_feature() {
    let text = "example.org {\n dnssec {\n key aws_secretsmanager example\n }\n}";
    let blocks = parse("Corefile", text).unwrap();
    let error = configure::<Chain>(&blocks, directives())
        .unwrap_err()
        .to_string();
    assert!(error.contains("dnssec-aws"), "{error}");
}
