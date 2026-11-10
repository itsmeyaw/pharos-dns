#![recursion_limit = "512"]
#![cfg(feature = "plugin-errors")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_server::Chain as _;

// Derived from CoreDNS v1.15.0 plugin/errors/setup_test.go.
#[test]
fn corefile_errors_rules() {
    for rule in [
        "errors",
        "errors stdout",
        "errors {\n stacktrace\n}",
        "errors {\n consolidate 1m ^exact$\n}",
        "errors {\n consolidate 1m \"format error\"\n}",
        "errors {\n consolidate 1m error1\n consolidate 5s error2\n}",
        "errors {\n consolidate 1m error show_first\n}",
        "errors {\n consolidate 1m error warning show_first\n}",
        "errors {\n consolidate 1m error error\n}",
        "errors {\n consolidate 1m error info\n}",
        "errors {\n consolidate 1m error debug\n}",
        "errors {\n consolidate 1m error show_first show_first\n}",
    ] {
        let corefile = format!(".:53 {{\n{rule}\n}}");
        let blocks = parse("Corefile", &corefile).unwrap();
        assert!(configure::<Chain>(&blocks, directives()).is_ok(), "{rule}");
    }
    for rule in [
        "errors errors.txt",
        "errors visible",
        "errors {\n log visible\n}",
        "errors\n errors",
        "errors a b",
        "errors {\n consolidate\n}",
        "errors {\n consolidate 1m\n}",
        "errors {\n consolidate 1m .* extra\n}",
        "errors {\n consolidate abc .*\n}",
        "errors {\n consolidate 1 .*\n}",
        "errors {\n consolidate 1m ())\n}",
        "errors {\n consolidate 1m error warning error\n}",
        "errors {\n consolidate 1m error info debug\n}",
        "errors {\n consolidate 1m error show_first warning\n}",
    ] {
        let corefile = format!(".:53 {{\n{rule}\n}}");
        let blocks = parse("Corefile", &corefile).unwrap();
        assert!(configure::<Chain>(&blocks, directives()).is_err(), "{rule}");
    }
    let corefile = format!(
        ".:53 {{\n errors {{\n consolidate 1m {}\n }}\n}}",
        "a".repeat(10_001)
    );
    let blocks = parse("Corefile", &corefile).unwrap();
    assert!(configure::<Chain>(&blocks, directives()).is_err());
}

#[test]
fn stacktrace_option_reaches_chain() {
    for (option, expected) in [("", false), (" {\n stacktrace\n}", true)] {
        let corefile = format!(".:53 {{\n errors{option}\n}}");
        let blocks = parse("Corefile", &corefile).unwrap();
        let configured = configure::<Chain>(&blocks, directives()).unwrap();
        assert_eq!(configured[0].config.stacktrace(), expected);
    }
}
