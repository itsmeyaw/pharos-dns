#![forbid(unsafe_code)]
#![cfg(feature = "plugin-rewrite")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

// Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestNewRule.
#[test]
fn coredns_new_rule_setup_rows() {
    for (args, valid) in [
        ("", false),
        ("foo", false),
        ("name", false),
        ("name a.com", false),
        ("name a.com b.com c.com", false),
        ("name a.com b.com", true),
        ("name exact a.com b.com", true),
        ("name prefix a.com b.com", true),
        ("name suffix a.com b.com", true),
        ("name substring a.com b.com", true),
        (r"name regex ([a])\.com new-{1}.com", true),
        (r"name regex ([a]\.com new-{1}.com", false),
        (
            r"name regex (dns)\.(core)\.(rocks) {2}.{1}.{3} answer name (core)\.(dns)\.(rocks) {2}.{1}.{3}",
            true,
        ),
        (
            r"name regex (adns)\.(core)\.(rocks) {2}.{1}.{3} answer name (core)\.(adns)\.(rocks) {2}.{1}.{3} too.long way.too.long",
            false,
        ),
        (
            r"name regex (bdns)\.(core)\.(rocks) {2}.{1}.{3} NoAnswer name (core)\.(bdns)\.(rocks) {2}.{1}.{3}",
            false,
        ),
        (
            r"name regex (cdns)\.(core)\.(rocks) {2}.{1}.{3} answer ttl (core)\.(cdns)\.(rocks) {2}.{1}.{3}",
            false,
        ),
        (
            r"name substring fcore.dns.rocks dns.fcore.rocks answer name (fcore)\.(dns)\.(rocks) {2}.{1}.{3}",
            true,
        ),
        ("name substring a.com b.com c.com", false),
        ("type", false),
        ("type a", false),
        ("type any a a", false),
        ("type any a", true),
        ("type XY WV", false),
        ("type ANY WV", false),
        ("class", false),
        ("class IN", false),
        ("class ch in in", false),
        ("class ch in", true),
        ("class XY WV", false),
        ("class IN WV", false),
        ("edns0", false),
        ("edns0 unknown-rule-type set", false),
        ("edns0 unknown-rule-type unset", false),
        ("edns0 local", false),
        ("edns0 local set", false),
        ("edns0 local set 0xffee", false),
        ("unknown-action name a.com b.com", false),
        ("stop name a.com b.com", true),
        ("continue name a.com b.com", true),
        ("unknown-action type any a", false),
        ("stop type any a", true),
        ("continue type any a", true),
        ("unknown-action class ch in", false),
        ("stop class ch in", true),
        ("continue class ch in", true),
        ("unknown-action edns0 nsid set", false),
        ("unknown-action edns0 local set 0xffee abcedef", false),
        ("unknown-action edns0 local set 0xffee {qname}", false),
        ("unknown-action edns0 subnet set 24 64", false),
    ] {
        let text = format!(".:53 {{\n rewrite {args}\n}}");
        let result =
            parse("Corefile", &text).and_then(|blocks| configure::<Chain>(&blocks, directives()));
        assert_eq!(result.is_ok(), valid, "{args}: {result:?}");
    }
    for mode in ["", "stop ", "continue "] {
        for action in ["set", "append", "replace"] {
            for variable in [
                "qname",
                "qtype",
                "client_ip",
                "client_port",
                "protocol",
                "server_ip",
                "server_port",
                "dummy",
            ] {
                let text = format!(
                    ".:53 {{\n rewrite {mode}edns0 local {action} 0xffee {{{variable}}}\n}}"
                );
                let result = parse("Corefile", &text)
                    .and_then(|blocks| configure::<Chain>(&blocks, directives()));
                assert_eq!(result.is_ok(), variable != "dummy", "{text}: {result:?}");
            }
            let text = format!(
                ".:53 {{\n rewrite {mode}edns0 local {action} 0xffee {{server_port}} revert\n}}"
            );
            assert!(
                parse("Corefile", &text)
                    .and_then(|blocks| configure::<Chain>(&blocks, directives()))
                    .is_ok(),
                "{text}"
            );
        }
        for (rule, valid) in [
            ("edns0 local set invalid-uint {qname}", false),
            ("edns0 local set 65518 abcdefg", true),
            ("edns0 local set 0xffee abcdefg", true),
            ("edns0 local set 0xffee abcdefg revert", true),
            ("edns0 local append 0xffee abcdefg revert", true),
            ("edns0 local replace 0xffee abcdefg revert", true),
            ("edns0 nsid foo", false),
            ("edns0 subnet append 24 56 revert", true),
            ("edns0 subnet replace 24 56 revert", true),
        ] {
            let text = format!(".:53 {{\n rewrite {mode}{rule}\n}}");
            let result = parse("Corefile", &text)
                .and_then(|blocks| configure::<Chain>(&blocks, directives()));
            assert_eq!(result.is_ok(), valid, "{text}: {result:?}");
        }
    }
}

// CoreDNS TestNewRule passes invalid UTF-8 directly to its private constructor; the Rust setup seam accepts &str.
#[test]
fn coredns_invalid_utf8_rule_arguments_cannot_enter_str_setup() {
    for bytes in [
        &b"\xecore\\.(ddns)\\.(rocks)"[..],
        &b"\xedns\\.(core)\\.(rocks)"[..],
    ] {
        assert!(std::str::from_utf8(bytes).is_err());
    }
}

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

#[test]
fn coredns_edns_variable_setup_cases() {
    for (variable, valid) in [
        ("qname", true),
        ("qtype", true),
        ("client_ip", true),
        ("client_port", true),
        ("server_ip", true),
        ("server_port", true),
        ("protocol", true),
        ("test/label", true),
        ("dummy", false),
        ("/label", false),
        ("provider/", false),
    ] {
        let text = format!(".:53 {{\n rewrite edns0 local set 0xffee {{{variable}}}\n}}");
        let result =
            parse("Corefile", &text).and_then(|blocks| configure::<Chain>(&blocks, directives()));
        assert_eq!(result.is_ok(), valid, "{variable}: {result:?}");
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestNewRule.
#[test]
fn coredns_edns_nsid_and_subnet_setup_cases() {
    for (args, valid) in [
        ("nsid set", true),
        ("nsid set revert", true),
        ("nsid append", true),
        ("nsid append revert", true),
        ("nsid replace", true),
        ("nsid replace revert", true),
        ("nsid unset", true),
        ("nsid unset revert", false),
        ("nsid set junk", false),
        ("subnet set 24 56", true),
        ("subnet set 24 56 revert", true),
        ("subnet append 24 56", true),
        ("subnet replace 24 56", true),
        ("subnet unset", true),
        ("subnet unset revert", false),
        ("subnet set -1 56", false),
        ("subnet set 24 -56", false),
        ("subnet set 33 56", false),
        ("subnet set 24 129", false),
        ("subnet append 24 56 72", false),
        ("subnet unset 24 56", false),
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

#[test]
fn coredns_exact_name_validates_destination_regex_at_setup() {
    let text = ".:53 {\n rewrite name example. [invalid.\n}";
    assert!(
        parse("Corefile", text)
            .and_then(|blocks| configure::<Chain>(&blocks, directives()))
            .is_err()
    );
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/name_metadata_test.go.
#[test]
fn coredns_name_metadata_validation() {
    for replacement in [
        "{missing}",
        "{test/}",
        "{/value}",
        "{test/value",
        "test/value}",
        "{{test/value}}",
        "{2}.{test/value}",
        "{-1}.{test/value}",
    ] {
        let text = format!(".:53 {{\n rewrite name regex (.*) {replacement} metadata\n}}");
        let result =
            parse("Corefile", &text).and_then(|blocks| configure::<Chain>(&blocks, directives()));
        assert!(result.is_err(), "{replacement}");
    }
    for mode in ["exact", "prefix", "suffix", "substring"] {
        let text = format!(".:53 {{\n rewrite name {mode} example. {{test/value}}. metadata\n}}");
        let result =
            parse("Corefile", &text).and_then(|blocks| configure::<Chain>(&blocks, directives()));
        assert!(result.is_err(), "{mode}");
    }
}

// Derived from CoreDNS v1.15.0 plugin/rewrite/rcode_test.go.
#[test]
fn coredns_rcode_setup_cases() {
    for (args, valid) in [
        ("numeric.rcode.coredns.rocks 2 0", true),
        ("too.few.rcode.coredns.rocks 2", false),
        ("exact too.many.rcode.coredns.rocks 2 1 0", false),
        (
            "exact match.string.rcode.coredns.rocks SERVFAIL NOERROR",
            true,
        ),
        (
            r"regex (regex)\.rcode\.(coredns)\.(rocks) FORMERR NOERROR",
            true,
        ),
        ("invalid.rcode.coredns.rocks random nothing", false),
    ] {
        for mode in ["stop", "continue"] {
            let text = format!(".:53 {{\n rewrite {mode} rcode {args}\n}}");
            let result = parse("Corefile", &text)
                .and_then(|blocks| configure::<Chain>(&blocks, directives()));
            assert_eq!(result.is_ok(), valid, "{mode} {args}: {result:?}");
        }
    }
    let too_long = "a".repeat(10_001);
    let text = format!(".:53 {{\n rewrite rcode regex {too_long} SERVFAIL NXDOMAIN\n}}");
    assert!(
        parse("Corefile", &text)
            .and_then(|blocks| configure::<Chain>(&blocks, directives()))
            .is_err()
    );
}

#[test]
fn coredns_numeric_rule_syntax() {
    for (rule, valid) in [
        ("edns0 local set 0xff_ee data", true),
        ("edns0 local set +65518 data", false),
        ("edns0 local set 0x_ff__ee data", false),
        ("ttl example. +15", false),
        ("rcode example. +2 0", false),
    ] {
        let text = format!(".:53 {{\n rewrite {rule}\n}}");
        let result =
            parse("Corefile", &text).and_then(|blocks| configure::<Chain>(&blocks, directives()));
        assert_eq!(result.is_ok(), valid, "{rule}");
    }
}

#[test]
fn coredns_rewrite_rejects_oversized_patterns() {
    let too_long = "a".repeat(10_001);
    for rule in [
        format!("name regex {too_long} destination."),
        format!("ttl regex {too_long} 300"),
        format!("rcode regex {too_long} SERVFAIL NXDOMAIN"),
        format!("cname regex {too_long} destination."),
    ] {
        let text = format!(".:53 {{\n rewrite {rule}\n}}");
        assert!(
            parse("Corefile", &text)
                .and_then(|blocks| configure::<Chain>(&blocks, directives()))
                .is_err(),
            "{rule}"
        );
    }
}
