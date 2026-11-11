#![forbid(unsafe_code)]
#![cfg(feature = "plugin-cache")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

fn configure_cache(directive: &str) -> bool {
    let text = format!(".:53 {{\n{directive}\n}}");
    parse("Corefile", &text)
        .and_then(|blocks| configure::<Chain>(&blocks, directives()))
        .is_ok()
}

#[test]
fn accepts_coredns_cache_setup_cases() {
    for text in [
        "cache",
        "cache {}",
        "cache example.nl {\n success 10\n}",
        "cache example.nl {\n success 10 1800 30\n denial 10 15 2\n}",
        "cache 25 example.nl {\n success 10\n denial 10 15 5\n}",
        "cache aaa example.nl",
        "cache {\n prefetch 10 1m 90%\n}",
        "cache {\n serve_stale 1h VERIFY 100ms 30s 30s\n serve_stale_policy prefer_positive\n}",
        "cache {\n serve_stale 1h immediate 30s 30s\n}",
        "cache {\n servfail 5m\n disable denial example.com example.org\n disable success\n keepttl\n}",
    ] {
        assert!(configure_cache(text), "rejected {text}");
    }
}

#[test]
fn rejects_coredns_invalid_cache_setup_cases() {
    for text in [
        "cache 0 example.nl",
        "cache -1 example.nl",
        "cache\n cache",
        "cache {\n success\n}",
        "cache {\n denial aaa\n}",
        "cache {\n positive 15\n}",
        "cache {\n prefetch -1\n}",
        "cache {\n prefetch 0 blurp\n}",
        "cache {\n prefetch 1 1m 9%\n}",
        "cache {\n prefetch 1 1m 91%\n}",
        "cache {\n serve_stale -20m\n}",
        "cache {\n serve_stale 1m nono\n}",
        "cache {\n serve_stale 1h immediate 100ms\n}",
        "cache {\n serve_stale 1h verify -1ms\n}",
        "cache {\n serve_stale_policy prefer_positive\n}",
        "cache {\n servfail 6m\n}",
        "cache {\n disable invalid example.com\n}",
        "cache {\n keepttl arg1\n}",
    ] {
        assert!(!configure_cache(text), "accepted {text}");
    }
}
