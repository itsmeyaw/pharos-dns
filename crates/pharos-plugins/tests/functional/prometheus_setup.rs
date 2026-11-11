#![cfg(feature = "plugin-prometheus")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/metrics/setup_test.go.
#[test]
fn prometheus_corefile_syntax() {
    for directive in [
        "prometheus",
        "prometheus localhost:53",
        "prometheus :9153",
        "prometheus localhost:",
        "prometheus [::1]:9153",
        "prometheus {\n runtime_metrics\n}",
        "prometheus localhost:53 {\n runtime_metrics\n}",
        "prometheus {\n tls config.yml\n}",
    ] {
        let input = format!(".:53 {{\n{directive}\n}}");
        let blocks = parse("Corefile", &input).unwrap();
        assert!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            "{directive}"
        );
    }
    for directive in [
        "prometheus {}",
        "prometheus {\n runtime_metrics extra_arg\n}",
        "prometheus /foo",
        "prometheus localhost",
        "prometheus localhost:9[5",
        "prometheus 2001:db8::1:9153",
        "prometheus a b c",
        "prometheus {\n unknown\n}",
        "prometheus {\n tls\n}",
        "prometheus {\n tls a b\n}",
        "prometheus {\n tls a\n tls b\n}",
        "prometheus\nprometheus",
    ] {
        let input = format!(".:53 {{\n{directive}\n}}");
        let blocks = parse("Corefile", &input).unwrap();
        assert!(
            configure::<Chain>(&blocks, directives()).is_err(),
            "{directive}"
        );
    }
}
