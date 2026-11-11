#![forbid(unsafe_code)]
#![cfg(feature = "plugin-acl")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/acl/setup_test.go.
#[test]
fn coredns_acl_setup_cases() {
    for (directive, valid) in [
        ("acl {\n block type A net 192.168.0.0/16\n}", true),
        ("acl {\n block type * net 192.168.0.0/16\n}", true),
        ("acl {\n block type A net *\n}", true),
        (
            "acl {\n allow type * net 192.168.1.0/24\n block type * net 192.168.0.0/16\n}",
            true,
        ),
        ("acl {\n filter type A net 192.168.0.0/16\n}", true),
        (
            "acl {\n allow type * net 192.168.0.0/16\n block type * net *\n}",
            true,
        ),
        ("acl {\n drop type * net 192.168.0.0/16\n}", true),
        (
            "acl a.example.org {\n block type * net 192.168.1.0/24\n}",
            true,
        ),
        (
            "acl a.example.org {\n block type * net 192.168.1.0/24\n}\nacl b.example.org {\n block type * net 192.168.2.0/24\n}",
            true,
        ),
        (
            "acl example.org {\n block type * net 192.168.1.0/24 192.168.3.0/24\n}",
            true,
        ),
        (
            "acl example.org {\n block type TXT ANY CNAME net 192.168.3.0/24\n}",
            true,
        ),
        ("acl {\n allow net 192.168.1.0/24\n block\n}", true),
        ("acl a.example.org {\n drop net 2001:db8::/32\n}", true),
        ("acl {\n filter type TXT ANY CNAME net *\n}", true),
        ("acl {\n block A net 192.168.0.0/16\n}", false),
        ("acl {\n block type net 192.168.0.0/16\n}", false),
        ("acl {\n block type ABC\n}", false),
        ("acl {\n blck\n}", false),
        ("acl {\n block net 192.168.0/16\n}", false),
        ("acl {\n block net 192.168.0.0/33\n}", false),
        (
            "acl {\n block type A net 2001:0db8:85a3:0000:0000:8a2e:0370:7334\n}",
            true,
        ),
        (
            "acl {\n block type * net 2001:db8:85a3::8a2e:370:7334\n}",
            true,
        ),
        ("acl {\n block type A\n}", true),
        (
            "acl {\n allow net 2001:db8:abcd:0012::0/64\n block net 2001:db8:abcd:0012::0/48\n}",
            true,
        ),
        (
            "acl {\n filter type A net 2001:0db8:85a3:0000:0000:8a2e:0370:7334\n}",
            true,
        ),
        (
            "acl {\n allow net 2001:db8:abcd:0012::0/64\n block\n}",
            true,
        ),
        ("acl {\n drop net 2001:db8:abcd:0012::0/64\n}", true),
        (
            "acl a.example.org {\n block net 2001:db8:abcd:0012::0/64\n}",
            true,
        ),
        (
            "acl a.example.org {\n block net 2001:db8:abcd:0012::0/64\n}\nacl b.example.org {\n block net 2001:db8:abcd:0013::0/64\n}",
            true,
        ),
        (
            "acl example.org {\n block net 2001:db8:abcd:0012::0/64 2001:db8:85a3::8a2e:370:7334/64\n}",
            true,
        ),
        (
            "acl {\n block type A net 2001::85a3::8a2e:370:7334\n}",
            false,
        ),
        (
            "acl {\n block type A net 2001:db8:85a3:::8a2e:370:7334\n}",
            false,
        ),
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
