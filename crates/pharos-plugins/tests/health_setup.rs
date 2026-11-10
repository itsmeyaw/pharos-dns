#![cfg(feature = "plugin-health")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/health/setup_test.go.
#[test]
fn health_corefile_syntax() {
    for (directive, valid) in [
        ("health", true),
        ("health localhost:1234", true),
        ("health localhost:1234 {\n lameduck 4s\n}", true),
        ("health {\n lameduck 1h2m3.5s\n}", true),
        ("health {\n lameduck -1µs\n}", true),
        ("health {\n lameduck 0\n}", true),
        ("health bla:a", true),
        ("health bla", false),
        ("health bla bla", false),
        ("health localhost:1234 {\n lameduck a\n}", false),
        ("health {\n lameduck 1\n}", false),
        ("health {\n lameduck 9223372036854775808ns\n}", false),
        ("health localhost:1234 {\n lamedudk 4\n}", false),
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
