#![forbid(unsafe_code)]
#![cfg(feature = "plugin-acl")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/acl/setup_test.go.
#[test]
fn coredns_acl_setup_cases() {
    for (directive, valid) in [
        ("acl {\n block type A net 192.168.0.0/16\n}", true),
        ("acl {\n allow net 192.168.1.0/24\n block\n}", true),
        ("acl a.example.org {\n drop net 2001:db8::/32\n}", true),
        ("acl {\n filter type TXT ANY CNAME net *\n}", true),
        ("acl {\n block A net 192.168.0.0/16\n}", false),
        ("acl {\n block type net 192.168.0.0/16\n}", false),
        ("acl {\n block type ABC\n}", false),
        ("acl {\n blck\n}", false),
        ("acl {\n block net 192.168.0/16\n}", false),
        ("acl {\n block net 192.168.0.0/33\n}", false),
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
