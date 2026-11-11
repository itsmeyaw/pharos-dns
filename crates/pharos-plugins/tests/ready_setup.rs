#![recursion_limit = "512"]
#![cfg(feature = "plugin-ready")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/ready/setup_test.go.
#[test]
fn ready_corefile_syntax() {
    for directive in [
        "ready",
        "ready localhost:1234",
        "ready {\n monitor until-ready\n}",
        "ready {\n monitor continuously\n}",
        "ready localhost:1234 {\n monitor continuously\n}",
    ] {
        let input = format!(".:53 {{\n{directive}\n}}");
        let blocks = parse("Corefile", &input).unwrap();
        assert!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            "{directive}"
        );
    }
    for directive in [
        "ready localhost:1234 {\n monitor 404\n}",
        "ready {\n monitro continuously\n}",
        "ready localhost:1234 b",
        "ready bla",
        "ready bla bla",
        "ready {\n monitor\n}",
        "ready {\n monitor continuously extra\n}",
        "ready\nready",
    ] {
        let input = format!(".:53 {{\n{directive}\n}}");
        let blocks = parse("Corefile", &input).unwrap();
        assert!(
            configure::<Chain>(&blocks, directives()).is_err(),
            "{directive}"
        );
    }
}

#[test]
fn ready_defaults_and_last_monitor_value() {
    let input = ".:53 {\n ready {\n monitor continuously\n monitor until-ready\n }\n}";
    let blocks = parse("Corefile", input).unwrap();
    let configured = configure::<Chain>(&blocks, directives()).unwrap();
    let ready = configured[0].config.ready.as_ref().unwrap();
    assert_eq!(ready.address, ":8181");
    assert!(!ready.continuous);
}
