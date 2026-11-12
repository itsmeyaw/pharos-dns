#![cfg(feature = "plugin-view")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/view/setup_test.go.
#[test]
fn coredns_view_setup_cases() {
    for (directive, valid) in [
        ("view example {\n expr name() == 'example.com.'\n}", true),
        (
            "view example {\n expr incidr(client_ip(), '10.0.0.0/24')\n}",
            true,
        ),
        (
            "view example {\n expr name() == 'example.com.'\n expr name() == 'example2.com.'\n}",
            true,
        ),
        ("view", false),
        ("view example {\n expr invalid expression\n}", false),
        ("view x {\n foo bar\n}", false),
        ("view a { }\nview b { }", false),
    ] {
        let input = format!(".:53 {{\n{directive}\n}}");
        let blocks = parse("Corefile", &input).unwrap();
        assert_eq!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            valid,
            "{directive}"
        );
    }
}
