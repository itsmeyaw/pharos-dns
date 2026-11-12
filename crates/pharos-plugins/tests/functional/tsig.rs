#![cfg(feature = "plugin-tsig")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

#[test]
fn setup_accepts_coredns_requirement_options() {
    for directive in [
        "tsig {\n secret name.key. test-key\n require all\n}",
        "tsig example.com {\n require A AAAA\n require_opcode UPDATE NOTIFY\n}",
        "tsig {\n require none\n require_opcode none\n}",
    ] {
        let source = format!(". {{\n {directive}\n}}");
        let blocks = parse("Corefile", &source).unwrap();
        assert!(
            configure::<Chain>(&blocks, directives()).is_ok(),
            "{directive}"
        );
    }
}
