#![forbid(unsafe_code)]
#![cfg(feature = "plugin-timeouts")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

#[test]
fn coredns_timeouts_setup_cases() {
    for directive in [
        "timeouts {\n read 30s\n}",
        "timeouts {\n read 1m\n write 2m\n}",
        "timeouts {\n idle 1h\n}",
        "timeouts {\n read 10\n write 20\n idle 60\n}",
        "timeouts {\n maxtcpqueries 128\n}",
        "timeouts {\n maxtcpqueries -1\n}",
    ] {
        let text = format!(".:53 {{\n{directive}\n}}");
        assert!(
            configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).is_ok(),
            "{directive}"
        );
    }
    for directive in [
        "timeouts",
        "timeouts {}",
        "timeouts {\n read 10s\n giraffe 30s\n}",
        "timeouts {\n read 10s 20s\n}",
        "timeouts {\n write snake\n}",
        "timeouts {\n idle 0s\n}",
        "timeouts {\n read 48h\n}",
        "timeouts {\n maxtcpqueries 0\n}",
        "timeouts {\n maxtcpqueries -2\n}",
        "timeouts {\n maxtcpqueries snake\n}",
    ] {
        let text = format!(".:53 {{\n{directive}\n}}");
        assert!(
            configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).is_err(),
            "{directive}"
        );
    }
}

#[test]
fn shared_listener_combines_last_explicit_values() {
    let text = "one.example:53 {\n timeouts {\n read 7s\n write 8s\n maxtcpqueries 4\n }\n}\ntwo.example:53 {\n timeouts {\n idle 9s\n maxtcpqueries -1\n }\n}";
    let blocks = configure::<Chain>(&parse("Corefile", text).unwrap(), directives()).unwrap();
    let (servers, _) = pharos_plugins::servers(blocks).unwrap();
    let options = servers.values().next().unwrap().tcp_options;
    assert_eq!(options.read, std::time::Duration::from_secs(7));
    assert_eq!(options.write, std::time::Duration::from_secs(8));
    assert_eq!(options.idle, std::time::Duration::from_secs(9));
    assert_eq!(options.max_queries, None);
}

#[test]
fn repeated_timeouts_preserve_earlier_options() {
    let text = ".:53 {\n timeouts {\n read 7s\n }\n timeouts {\n idle 9s\n }\n}";
    let blocks = configure::<Chain>(&parse("Corefile", text).unwrap(), directives()).unwrap();
    let (servers, _) = pharos_plugins::servers(blocks).unwrap();
    let options = servers.values().next().unwrap().tcp_options;
    assert_eq!(options.read, std::time::Duration::from_secs(7));
    assert_eq!(options.idle, std::time::Duration::from_secs(9));
}
