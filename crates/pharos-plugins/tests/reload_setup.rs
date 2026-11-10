#![cfg(feature = "plugin-reload")]

use pharos_corefile::{BlockContext, Error, configure, parse};
use pharos_plugins::{Chain, directives};
use std::time::Duration;

fn configure_reload(input: &str) -> Result<Vec<BlockContext<Chain>>, Error> {
    let blocks = parse("Corefile", input)?;
    configure(&blocks, directives())
}

// Derived from CoreDNS v1.15.0 plugin/reload/setup_test.go.
#[test]
fn setup_accepts_and_rejects_coredns_examples() {
    for directive in ["reload", "reload 10s", "reload 10s 2s", "reload 2s 0s"] {
        assert!(
            configure_reload(&format!(".:53 {{\n{directive}\n}}")).is_ok(),
            "{directive}"
        );
    }
    for directive in [
        "reload foo",
        "reload 10s foo",
        "reload 10s 5s foo",
        "reload 1s",
        "reload 0s",
        "reload 3s 0.5s",
        "reload 3s -1s",
        "reload 3s -+0",
        "reload\nreload",
    ] {
        assert!(
            configure_reload(&format!(".:53 {{\n{directive}\n}}")).is_err(),
            "{directive}"
        );
    }
}

#[test]
fn setup_applies_defaults_and_caps_jitter() {
    for (directive, interval, jitter) in [
        ("reload", 30, 15),
        ("reload 10s", 10, 5),
        ("reload 2s 0", 2, 0),
        ("reload 10s 8s", 10, 5),
    ] {
        let blocks = configure_reload(&format!(".:53 {{\n{directive}\n}}")).unwrap();
        let reload = blocks[0].config.reload.as_ref().unwrap();
        assert_eq!(reload.interval, Duration::from_secs(interval));
        assert_eq!(reload.jitter, Duration::from_secs(jitter));
    }
}
