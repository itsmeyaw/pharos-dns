#![forbid(unsafe_code)]
#![cfg(feature = "plugin-loop")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/loop/setup_test.go.
#[test]
fn setup_accepts_no_arguments_and_only_one_directive() {
    for (directive, valid) in [
        ("loop", true),
        ("loop argument", false),
        ("loop\nloop", false),
    ] {
        let blocks = parse("Corefile", &format!(".:53 {{\n{directive}\n}}")).unwrap();
        assert_eq!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            valid,
            "{directive}"
        );
    }
}

#[test]
fn setup_uses_first_normalized_server_block_key() {
    for (keys, domain) in [
        ("example.org", "example.org."),
        ("dns://ExAmPlE.org:53 example.net:53", "example.org."),
        (".", "."),
    ] {
        let blocks = parse("Corefile", &format!("{keys} {{\nloop\n}}")).unwrap();
        let configured = configure::<Chain>(&blocks, directives()).unwrap();
        assert_eq!(configured[0].config.r#loop.as_ref().unwrap().domain, domain);
    }
}
