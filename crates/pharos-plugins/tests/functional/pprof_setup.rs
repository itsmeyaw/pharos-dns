#![cfg(feature = "plugin-pprof")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

fn configured(directive: &str) -> Result<Vec<pharos_corefile::BlockContext<Chain>>, String> {
    let input = format!(".:53 {{\n{directive}\n}}");
    let blocks = parse("Corefile", &input).unwrap();
    configure::<Chain>(&blocks, directives()).map_err(|error| error.to_string())
}

// Derived from CoreDNS v1.15.0 plugin/pprof/setup_test.go.
#[test]
fn pprof_corefile_syntax() {
    for (directive, valid) in [
        ("pprof", true),
        ("pprof 1.2.3.4:1234", true),
        ("pprof :1234", true),
        ("pprof :1234 -1", false),
        ("pprof {\n}", true),
        ("pprof /foo", false),
        ("pprof {\n a b\n}", false),
        ("pprof { block\n}", true),
        ("pprof :1234 {\n block 20\n}", true),
        ("pprof {\n block 20 30\n}", false),
        ("pprof {\n block invalid\n}", false),
        ("pprof {\n unknown_property\n}", false),
        ("pprof\npprof", false),
    ] {
        assert_eq!(configured(directive).is_ok(), valid, "{directive}");
    }
}

#[test]
fn pprof_defaults_to_localhost_6053_without_block_profiling() {
    let configured = configured("pprof").unwrap();
    let pprof = configured[0].config.pprof.as_ref().unwrap();
    assert_eq!(pprof.address, "localhost:6053");
    assert_eq!(pprof.block_rate, None);
}

#[test]
fn pprof_block_rate_defaults_to_one_and_accepts_any_integer() {
    // CoreDNS v1.15.0 plugin/pprof/setup.go: strconv.Atoi accepts negative values and a bare block means 1.
    for (directive, rate) in [
        ("pprof :1234 {\n block\n}", 1),
        ("pprof :1234 {\n block 20\n}", 20),
        ("pprof :1234 {\n block -5\n}", -5),
        ("pprof :1234 {\n block +7\n}", 7),
        ("pprof :1234 {\n block 0\n}", 0),
        ("pprof :1234 {\n block 20\n block 3\n}", 3),
    ] {
        let configured = configured(directive).unwrap();
        let pprof = configured[0].config.pprof.as_ref().unwrap();
        assert_eq!(pprof.address, ":1234", "{directive}");
        assert_eq!(pprof.block_rate, Some(rate), "{directive}");
    }
}

#[test]
fn pprof_rejects_invalid_addresses_and_properties_with_coredns_messages() {
    for address in ["bla", "1.2.3.4", "[::1", "a:b:c", "::1:80"] {
        let error = configured(&format!("pprof {address}")).unwrap_err();
        assert!(
            error.contains("invalid pprof address"),
            "{address}: {error}"
        );
    }
    let error = configured("pprof {\n block x\n}").unwrap_err();
    assert!(
        error.contains("property 'block' invalid integer value 'x'"),
        "{error}"
    );
    // CoreDNS v1.15.0 has no mutex property.
    let error = configured("pprof {\n mutex 5\n}").unwrap_err();
    assert!(error.contains("unknown property 'mutex'"), "{error}");
    let error = configured("pprof\npprof").unwrap_err();
    assert!(error.contains("only be used once"), "{error}");
}
