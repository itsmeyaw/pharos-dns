#![cfg(feature = "plugin-bind")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/bind/setup_test.go.
#[test]
fn setup_accepts_addresses_and_rejects_invalid_arguments() {
    for (directive, expected) in [
        ("bind 1.2.3.4", vec!["1.2.3.4"]),
        ("bind 1.2.3.4 ::5", vec!["1.2.3.4", "::5"]),
        (
            "bind ::1 1.2.3.4 ::5 127.9.9.0",
            vec!["::1", "1.2.3.4", "::5", "127.9.9.0"],
        ),
    ] {
        let blocks = parse("Corefile", &format!(".:53 {{\n{directive}\n}}")).unwrap();
        let configured = configure::<Chain>(&blocks, directives()).unwrap();
        assert_eq!(configured[0].listen_addresses, expected);
    }
    for directive in [
        "bind",
        "bind 1.2.3.invalid",
        "bind ::1 noone",
        "bind 1.2.3.4 {\nexcept\n}",
        "bind ::1 {\nunknown ::1\n}",
    ] {
        let blocks = parse("Corefile", &format!(".:53 {{\n{directive}\n}}")).unwrap();
        assert!(
            configure::<Chain>(&blocks, directives()).is_err(),
            "{directive}"
        );
    }
}

#[test]
fn directives_accumulate_with_per_directive_exclusions() {
    let input = ".:53 {\n bind 127.0.0.1 ::1 {\n except ::1\n }\n bind ::1\n}";
    let blocks = parse("Corefile", input).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    assert_eq!(configured[0].listen_addresses, ["127.0.0.1", "::1"]);
}
