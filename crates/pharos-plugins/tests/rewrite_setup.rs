#![forbid(unsafe_code)]
#![cfg(feature = "plugin-rewrite")]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/rewrite/setup_test.go.
#[test]
fn coredns_rewrite_setup_cases() {
    for (rule, valid) in [
        ("rewrite", false),
        ("rewrite name", false),
        ("rewrite name a.com b.com", true),
        (
            "rewrite stop {\n name regex foo bar\n answer name bar foo\n}",
            true,
        ),
        ("rewrite stop name regex foo bar answer name bar foo", true),
        (
            "rewrite stop {\n name regex foo bar\n answer name bar foo\n name baz\n}",
            false,
        ),
        (
            "rewrite stop {\n answer name bar foo\n name regex foo bar\n}",
            false,
        ),
        ("rewrite stop", false),
        ("rewrite continue", false),
        (
            "rewrite stop name regex [bad[ bar answer name bar foo",
            false,
        ),
    ] {
        let text = format!(".:53 {{\n{rule}\n}}");
        let result =
            parse("Corefile", &text).and_then(|blocks| configure::<Chain>(&blocks, directives()));
        assert_eq!(result.is_ok(), valid, "{rule}: {result:?}");
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/ttl_test.go TestNewTTLRule.
#[test]
fn coredns_ttl_setup_cases() {
    for (args, valid) in [
        ("srv1.coredns.rocks 10", true),
        ("exact srv1.coredns.rocks 15", true),
        ("prefix coredns.rocks 20", true),
        ("suffix srv1 25", true),
        ("substring coredns 30", true),
        (r"regex (srv1)\.(coredns)\.(rocks) 35", true),
        ("srv1.coredns.rocks 12345678901234567890", false),
        ("srv1.coredns.rocks coredns.rocks", false),
        ("srv1.coredns.rocks #1", false),
        ("range.coredns.rocks 1-2", true),
        ("ceil.coredns.rocks -2", true),
        ("floor.coredns.rocks 1-", true),
        ("range.coredns.rocks 2-2", true),
        ("invalid.coredns.rocks -", false),
        ("invalid.coredns.rocks 2-1", false),
        ("invalid.coredns.rocks 5-10-20", false),
    ] {
        for mode in ["stop", "continue"] {
            let text = format!(".:53 {{\n rewrite {mode} ttl {args}\n}}");
            let result = parse("Corefile", &text)
                .and_then(|blocks| configure::<Chain>(&blocks, directives()));
            assert_eq!(result.is_ok(), valid, "{mode} {args}: {result:?}");
        }
    }
}

#[test]
fn edns_hex_data_rejects_non_ascii_without_panicking() {
    let text = ".:53 {\n rewrite edns0 local set 0xffee 0xaé0\n}";
    let result =
        parse("Corefile", text).and_then(|blocks| configure::<Chain>(&blocks, directives()));
    assert!(result.is_err());
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestNewRule.
#[test]
fn coredns_edns_local_setup_cases() {
    for (args, valid) in [
        ("local set 65518 abcdefg", true),
        ("local set 0xffee 0x61626364", true),
        ("local append 0xffee abcdefg", true),
        ("local replace 0xffee abcdefg", true),
        ("local unset 0xffee", true),
        ("local set invalid-uint abcdefg", false),
        ("local unset 0xffee extra", false),
        ("local unset 0xffee revert", false),
        ("local foo 0xffee abcdefg", false),
        ("local set 0xffee 0xabcdefg", false),
    ] {
        let text = format!(".:53 {{\n rewrite edns0 {args}\n}}");
        let result =
            parse("Corefile", &text).and_then(|blocks| configure::<Chain>(&blocks, directives()));
        assert_eq!(result.is_ok(), valid, "{args}: {result:?}");
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/name_test.go TestNewNameRule.
#[test]
fn coredns_name_setup_cases() {
    for (args, valid) in [
        ("exact srv3.coredns.rocks srv4.coredns.rocks", true),
        ("srv1.coredns.rocks srv2.coredns.rocks", true),
        ("suffix coredns.rocks coredns.rocks.", true),
        ("suffix coredns.rocks. coredns.rocks", true),
        ("suffix coredns.rocks. coredns.rocks.", true),
        ("regex srv1.coredns.rocks 10", true),
        ("regex (.*).coredns.rocks 10", true),
        ("regex (.*).coredns.rocks {1}.coredns.rocks", true),
        ("regex (.*).coredns.rocks {1}.{2}.coredns.rocks", false),
        (
            "regex staging.mydomain.com aws-loadbalancer-id.us-east-1.elb.amazonaws.com",
            true,
        ),
        ("suffix staging.mydomain.com coredns.rock answer", false),
        (
            "suffix staging.mydomain.com coredns.rock answer name",
            false,
        ),
        (
            "suffix staging.mydomain.com coredns.rock answer other",
            false,
        ),
        ("suffix staging.mydomain.com coredns.rock answer auto", true),
        ("regex staging.mydomain.com coredns.rock answer auto", true),
        ("regex staging.mydomain.com coredns.rock answer name", false),
        (
            "regex staging.mydomain.com coredns.rock answer name coredns.rock staging.mydomain.com",
            true,
        ),
        (
            "regex staging.mydomain.com coredns.rock answer name (.*).coredns.rock {1}.{2}.staging.mydomain.com",
            false,
        ),
        (
            "regex staging.mydomain.com coredns.rock answer name (.*).coredns.rock {1}.staging.mydomain.com name (.*).coredns.rock {1}.staging.mydomain.com",
            true,
        ),
        (
            "regex staging.mydomain.com coredns.rock answer name (.*).coredns.rock {1}.staging.mydomain.com answer name (.*).coredns.rock {1}.staging.mydomain.com",
            true,
        ),
        (
            "regex staging.mydomain.com coredns.rock answer name (.*).coredns.rock {1}.staging.mydomain.com name (.*).coredns.rock",
            false,
        ),
        (
            "regex staging.mydomain.com coredns.rock answer name (.*).coredns.rock {1}.staging.mydomain.com value (.*).coredns.rock {1}.staging.mydomain.com",
            true,
        ),
        (
            "regex staging.mydomain.com coredns.rock answer name (.*).coredns.rock {1}.staging.mydomain.com answer value (.*).coredns.rock {1}.staging.mydomain.com",
            true,
        ),
        (
            "regex staging.mydomain.com coredns.rock answer name (.*).coredns.rock {1}.staging.mydomain.com value (.*).coredns.rock",
            false,
        ),
        (
            "suffix staging.mydomain.com. coredns.rock. answer value (.*).coredns.rock {1}.staging.mydomain.com value (.*).coredns.rock {1}.staging.mydomain.com",
            true,
        ),
        (
            "suffix staging.mydomain.com. coredns.rock. answer value (.*).coredns.rock {1}.staging.mydomain.com answer value (.*).coredns.rock {1}.staging.mydomain.com",
            true,
        ),
        (
            "suffix staging.mydomain.com. coredns.rock. answer value (.*).coredns.rock {1}.staging.mydomain.com name (.*).coredns.rock {1}.staging.mydomain.com",
            true,
        ),
        (
            "suffix staging.mydomain.com. coredns.rock. answer value (.*).coredns.rock {1}.staging.mydomain.com value (.*).coredns.rock",
            false,
        ),
    ] {
        for mode in ["stop", "continue"] {
            let text = format!(".:53 {{\n rewrite {mode} name {args}\n}}");
            let result = parse("Corefile", &text)
                .and_then(|blocks| configure::<Chain>(&blocks, directives()));
            assert_eq!(result.is_ok(), valid, "{mode} {args}: {result:?}");
        }
    }
}
