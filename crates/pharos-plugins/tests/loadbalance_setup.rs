#![forbid(unsafe_code)]
#![cfg(feature = "plugin-loadbalance")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

fn accepts(directive: &str) -> bool {
    let text = format!(".:53 {{\n{directive}\n}}");
    parse("Corefile", &text)
        .and_then(|blocks| configure::<Chain>(&blocks, directives()))
        .is_ok()
}

#[test]
fn accepts_coredns_loadbalance_setup_cases() {
    for text in [
        "loadbalance",
        "loadbalance round_robin",
        "loadbalance weighted wfile",
        "loadbalance weighted wf {\n reload 10s\n}",
        "loadbalance weighted wf {\n reload 0s\n}",
        "loadbalance round_robin\n loadbalance weighted wf",
    ] {
        assert!(accepts(text), "rejected {text}");
    }
}

#[test]
fn rejects_coredns_invalid_loadbalance_setup_cases() {
    for text in [
        "loadbalance fleeb",
        "loadbalance round_robin a",
        "loadbalance weighted",
        "loadbalance weighted a b",
        "loadbalance weighted wfile {\n susu\n}",
        "loadbalance weighted wfile {\n reload a\n}",
        "loadbalance weighted wfile {\n reload 30s a\n}",
        "loadbalance\n loadbalance fleeb",
    ] {
        assert!(!accepts(text), "accepted {text}");
    }
}
