#![cfg(feature = "plugin-log")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/log/setup_test.go.
#[test]
fn corefile_log_rules() {
    for rule in [
        "log",
        "log example.org",
        "log example.org. {common}",
        "log example.org {combined}",
        "log example.org.\nlog example.net {combined}",
        "log example.org {host}\nlog example.org {when}",
        "log example.org example.net",
        "log example.org example.net {host}",
        "log example.org example.net {when} {\n class denial\n}",
        "log example.org {\n class all\n}",
        "log {\n class denial error\n}",
        "log {\n class denial\n class error\n}",
        "log example.org \"{when} {common} {/forward/upstream}\"",
    ] {
        let corefile = format!(".:53 {{\n{rule}\n}}");
        let blocks = parse("Corefile", &corefile).unwrap();
        assert!(configure::<Chain>(&blocks, directives()).is_ok(), "{rule}");
    }
    for rule in [
        "log {\n class abracadabra\n}",
        "log {\n class\n}",
        "log {\n unknown\n}",
    ] {
        let corefile = format!(".:53 {{\n{rule}\n}}");
        let blocks = parse("Corefile", &corefile).unwrap();
        assert!(configure::<Chain>(&blocks, directives()).is_err(), "{rule}");
    }
}
