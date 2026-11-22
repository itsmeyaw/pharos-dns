use super::*;

// CoreDNS v1.15.0 plugin/etcd/setup_test.go TestParseTTL.
#[test]
fn parse_ttl_accepts_what_coredns_accepts() {
    for (input, expected) in [
        ("30", 30),
        ("300", 300),
        ("30s", 30),
        ("90s", 90),
        ("5m", 300),
        ("1m", 60),
        ("1h", 3600),
        ("2h", 7200),
        ("2h30m", 9000),
        ("1h30m45s", 5445),
        ("0", 0),
        ("0s", 0),
        ("", 0),
    ] {
        assert_eq!(parse_ttl(input), Ok(expected), "{input:?}");
    }
}

// CoreDNS v1.15.0 plugin/etcd/setup_test.go TestParseTTL.
#[test]
fn parse_ttl_rejects_what_coredns_rejects() {
    for input in ["-30s", "abc", "1y"] {
        assert!(parse_ttl(input).is_err(), "{input:?}");
    }
}

// CoreDNS v1.15.0 plugin/etcd/setup.go parseTTL: the value is trimmed, a fraction is truncated, and negative or too large is an error.
#[test]
fn parse_ttl_trims_truncates_and_bounds() {
    assert_eq!(parse_ttl("  45 "), Ok(45));
    assert_eq!(parse_ttl("1.5h"), Ok(5400));
    assert_eq!(parse_ttl("0.9s"), Ok(0));
    assert_eq!(parse_ttl("4294967295"), Ok(u32::MAX));
    assert_eq!(parse_ttl("-0"), Ok(0));
    assert_eq!(parse_ttl("-1s").unwrap_err(), "TTL must be non-negative");
    assert_eq!(
        parse_ttl("4294967296").unwrap_err(),
        "TTL too large, maximum is 4294967295 seconds"
    );
    assert_eq!(
        parse_ttl("4294967295.5s").unwrap_err(),
        "TTL too large, maximum is 4294967295 seconds"
    );
    // A bare number beyond u64 is not "plain": it gets no unit and fails like Go's ParseDuration.
    assert!(
        parse_ttl("99999999999999999999")
            .unwrap_err()
            .starts_with("invalid TTL format")
    );
}

// Go time.ParseDuration grammar `[-+]?([0-9]*(\.[0-9]*)?[a-z]+)+`, units and limits (time/format_test.go parseDurationTests).
#[test]
fn parse_duration_follows_go() {
    for (input, expected) in [
        ("0", 0),
        ("5s", 5_000_000_000),
        ("30s", 30_000_000_000),
        ("1478s", 1_478_000_000_000),
        ("-5s", -5_000_000_000),
        ("+5s", 5_000_000_000),
        ("-0", 0),
        ("+0", 0),
        ("5.0s", 5_000_000_000),
        ("5.6s", 5_600_000_000),
        ("5.s", 5_000_000_000),
        (".5s", 500_000_000),
        ("1.0s", 1_000_000_000),
        ("1.00s", 1_000_000_000),
        ("1.004s", 1_004_000_000),
        ("1.0040s", 1_004_000_000),
        ("100.00100s", 100_001_000_000),
        ("10ns", 10),
        ("11us", 11_000),
        ("12\u{b5}s", 12_000),
        ("12\u{3bc}s", 12_000),
        ("13ms", 13_000_000),
        ("14s", 14_000_000_000),
        ("15m", 900_000_000_000),
        ("16h", 57_600_000_000_000),
        ("3h30m", 12_600_000_000_000),
        ("10.5s4m", 250_500_000_000),
        ("-2m3.4s", -123_400_000_000),
        ("1h2m3s4ms5us6ns", 3_723_004_005_006),
        ("39h9m14.425s", 140_954_425_000_000),
        ("52763797000ns", 52_763_797_000),
        ("9007199254740993ns", 9_007_199_254_740_993),
        ("9223372036854775807ns", i64::MAX),
        ("9223372036854775.807us", i64::MAX),
        ("9223372036s854ms775us807ns", i64::MAX),
        ("-9223372036854775.808us", i64::MIN),
        ("-9223372036s854ms775us808ns", i64::MIN),
        ("-9223372036854775808ns", i64::MIN),
    ] {
        assert_eq!(parse_duration(input), Ok(expected), "{input:?}");
    }
    for input in [
        "",
        "3",
        "-",
        "s",
        ".",
        "-.",
        ".s",
        "+.s",
        "1d",
        "1y",
        "\u{3bc}s",
        "1\u{3bc}",
        "3000000h",
        "9223372036854775808ns",
        "9223372036854775.808us",
        "9223372036854ms775us808ns",
        "1.5",
        "1 s",
        "5s ",
    ] {
        assert!(parse_duration(input).is_err(), "{input:?}");
    }
}
