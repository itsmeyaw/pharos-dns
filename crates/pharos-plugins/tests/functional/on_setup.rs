#![forbid(unsafe_code)]
#![cfg(feature = "plugin-on")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from coredns/caddy v1.1.4 onevent/on_test.go `TestSetup`.
#[test]
fn setup_validates_events() {
    for (directive, valid) in [
        ("on", false),
        ("on xyz cmd arg", false),
        ("on startup cmd arg", true),
        ("on shutdown cmd arg &", true),
        ("on certrenew cmd arg", true),
        ("on startup cmd\non shutdown cmd", true),
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
fn each_server_block_registers_its_own_hooks() {
    let blocks = parse(
        "Corefile",
        ".:53 {\non startup cmd\non shutdown cmd\non certrenew cmd\n}\nexample.org:53 {\non startup cmd\n}",
    )
    .unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    // certrenew registers nothing: startup and shutdown (Restart, RestartFailed, Shutdown) only.
    assert_eq!(
        format!("{:?}", configured[0].config.lifecycle),
        "Lifecycle { hooks: 4 }"
    );
    assert_eq!(
        format!("{:?}", configured[1].config.lifecycle),
        "Lifecycle { hooks: 1 }"
    );
}
