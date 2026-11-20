use super::*;
use pharos_corefile::{Cursor, lex};
use std::time::Duration;

fn parse_text(text: &str) -> Result<Config, pharos_corefile::Error> {
    let tokens = lex("Corefile", text);
    parse(&mut Cursor::new("Corefile", &tokens), &["example.org"])
}

#[test]
fn defaults_and_server_block_domains() {
    let config = parse_text("cache").unwrap();
    assert_eq!(config.zones[0].to_string(), "example.org.");
    assert_eq!(config.success_capacity, 10_000);
    assert_eq!(config.denial_capacity, 10_000);
    assert_eq!(config.success_max_ttl, Duration::from_secs(3600));
    assert_eq!(config.denial_max_ttl, Duration::from_secs(1800));
    assert_eq!(config.success_min_ttl, Duration::from_secs(5));
    assert_eq!(config.denial_min_ttl, Duration::from_secs(5));
    assert_eq!(config.prefetch_duration, 60_000_000_000);
    assert_eq!(config.prefetch_percentage, 10);
    assert_eq!(config.fail_ttl, Duration::from_secs(5));
}

#[test]
fn capacities_ttls_and_domains() {
    let inherited = parse_text("cache 25 example.nl {\nsuccess 10\ndenial 10 15\n}").unwrap();
    assert_eq!(inherited.success_max_ttl, Duration::from_secs(25));
    assert_eq!(inherited.denial_max_ttl, Duration::from_secs(15));
    let config =
        parse_text("cache 25 Example.NL {\nsuccess 10 1800 30 ignored\ndenial 20 15 0\n}").unwrap();
    assert_eq!(config.zones[0].to_string(), "example.nl.");
    assert_eq!((config.success_capacity, config.denial_capacity), (10, 20));
    assert_eq!(config.success_max_ttl, Duration::from_secs(1800));
    assert_eq!(config.success_min_ttl, Duration::from_secs(30));
    assert_eq!(config.denial_max_ttl, Duration::from_secs(15));
    assert_eq!(config.denial_min_ttl, Duration::ZERO);
    for text in [
        "cache 0 example.nl",
        "cache -1",
        "cache {\nsuccess\n}",
        "cache {\ndenial aaa\n}",
        "cache {\nsuccess 10 0\n}",
        "cache {\ndenial 10 5 -1\n}",
        "cache {\npositive 5\n}",
    ] {
        assert!(parse_text(text).is_err(), "accepted {text}");
    }
    let capped = parse_text("cache {\nsuccess 10 7 0\ndenial 10 20 0\n}").unwrap();
    assert_eq!(capped.denial_max_ttl, Duration::from_secs(7));
}

#[test]
fn prefetch_signed_durations_and_percentage() {
    let config = parse_text("cache {\nprefetch 3 -1m2.5s 90%\n}").unwrap();
    assert_eq!(
        (
            config.prefetch_amount,
            config.prefetch_duration,
            config.prefetch_percentage
        ),
        (3, -62_500_000_000, 90)
    );
    assert!(parse_text("cache {\nprefetch 0 0 10%\n}").is_ok());
    assert!(parse_text("cache {\nprefetch 1 -9223372036854775808ns\n}").is_ok());
    for value in [
        "prefetch",
        "prefetch -1",
        "prefetch 1 nonsense",
        "prefetch 1 1s 9%",
        "prefetch 1 1s 91%",
        "prefetch 1 1s 10",
        "prefetch 1 1s 10% extra",
        "prefetch 1 9223372036854775808ns",
    ] {
        assert!(
            parse_text(&format!("cache {{\n{value}\n}}")).is_err(),
            "accepted {value}"
        );
    }
}

#[test]
fn serve_stale_modes_ttl_recheck_and_policy() {
    let config = parse_text(
        "cache {\nserve_stale_policy PREFER_POSITIVE\nserve_stale 1h VERIFY 100ms 30s 250ms\n}",
    )
    .unwrap();
    assert_eq!(config.stale, Duration::from_secs(3600));
    assert!(config.verify && config.prefer_positive);
    assert_eq!(config.verify_timeout, Duration::from_millis(100));
    assert_eq!(config.stale_ttl, Duration::from_secs(30));
    assert_eq!(config.stale_recheck, Duration::from_millis(250));
    let immediate = parse_text("cache {\nserve_stale 1h immediate 4294967295s 5m\n}").unwrap();
    assert!(!immediate.verify);
    assert_eq!(immediate.stale_ttl, Duration::from_secs(u32::MAX.into()));
    assert_eq!(immediate.stale_recheck, Duration::from_secs(300));
    assert_eq!(
        parse_text("cache {\nserve_stale\n}").unwrap().stale,
        Duration::from_secs(3600)
    );
    for value in [
        "serve_stale 20",
        "serve_stale -20m",
        "serve_stale 1h invalid",
        "serve_stale 1h immediate 100ms",
        "serve_stale 1h immediate 4294967296s",
        "serve_stale 1h immediate -1s",
        "serve_stale 1h immediate 30s 5m1s",
        "serve_stale 1h immediate 30s 30s extra",
        "serve_stale 1h verify -1ms",
        "serve_stale 1h verify 100ms 500ms",
        "serve_stale 1h verify 100ms 30s -1s",
        "serve_stale_policy prefer_positive",
        "serve_stale\nserve_stale_policy",
        "serve_stale\nserve_stale_policy invalid",
        "serve_stale\nserve_stale_policy prefer_positive\nserve_stale_policy prefer_positive",
    ] {
        assert!(
            parse_text(&format!("cache {{\n{value}\n}}")).is_err(),
            "accepted {value}"
        );
    }
}

#[test]
fn servfail_disable_and_keepttl() {
    let config = parse_text(
        "cache {\nservfail 5m\ndisable denial Example.com example.org\ndisable success\nkeepttl\n}",
    )
    .unwrap();
    assert_eq!(config.fail_ttl, Duration::from_secs(300));
    assert_eq!(
        config
            .disable_denial
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["example.com.", "example.org."]
    );
    assert_eq!(config.disable_success[0].to_string(), ".");
    assert!(config.keepttl);
    for value in [
        "servfail",
        "servfail 6m",
        "servfail 20",
        "servfail -1s",
        "servfail invalid",
        "servfail 1s extra",
        "disable",
        "disable invalid example.com",
        "disable denial a..b",
        "keepttl extra",
    ] {
        assert!(
            parse_text(&format!("cache {{\n{value}\n}}")).is_err(),
            "accepted {value}"
        );
    }
}

#[test]
fn servfail_ttl_obeys_one_second_minimum() {
    for option in ["servfail 0", "servfail 0ms", "servfail 500ms"] {
        let config = parse_text(&format!("cache {{\n{option}\n}}")).unwrap();
        assert_eq!(config.fail_ttl, Duration::from_secs(1), "{option}");
    }
}

#[test]
fn coredns_stale_and_servfail_cases() {
    for (option, stale, verify, timeout, ttl, recheck) in [
        ("serve_stale", 3600, false, 0, 30, 0),
        ("serve_stale 20m", 1200, false, 0, 30, 0),
        ("serve_stale 1h20m", 4800, false, 0, 30, 0),
        ("serve_stale 0m", 0, false, 0, 30, 0),
        ("serve_stale 0", 0, false, 0, 30, 0),
        ("serve_stale 0 verify", 0, true, 0, 30, 0),
        ("serve_stale 0 immediate", 0, false, 0, 30, 0),
        ("serve_stale 0 VERIFY", 0, true, 0, 30, 0),
        ("serve_stale 1h immediate 30s", 3600, false, 0, 30, 0),
        (
            "serve_stale 1h immediate 30s 30s",
            3600,
            false,
            0,
            30,
            30000,
        ),
        ("serve_stale 1h immediate 0", 3600, false, 0, 0, 0),
        ("serve_stale 1h verify 100ms", 3600, true, 100, 30, 0),
        ("serve_stale 1h verify 100ms 30s", 3600, true, 100, 30, 0),
        (
            "serve_stale 1h verify 100ms 30s 30s",
            3600,
            true,
            100,
            30,
            30000,
        ),
        ("serve_stale 1h verify 0", 3600, true, 0, 30, 0),
        ("serve_stale 1h verify 0 1m", 3600, true, 0, 60, 0),
        ("serve_stale 1h VERIFY 250ms", 3600, true, 250, 30, 0),
        ("serve_stale 1h verify 0 0 5m", 3600, true, 0, 0, 300000),
    ] {
        let config = parse_text(&format!("cache {{\n{option}\n}}")).unwrap();
        assert_eq!(
            (
                config.stale,
                config.verify,
                config.verify_timeout,
                config.stale_ttl,
                config.stale_recheck
            ),
            (
                Duration::from_secs(stale),
                verify,
                Duration::from_millis(timeout),
                Duration::from_secs(ttl),
                Duration::from_millis(recheck)
            ),
            "{option}"
        );
    }
    for option in [
        "servfail 0",
        "servfail 0s",
        "servfail 1s",
        "servfail 5m",
        "serve_stale 1h immediate 0 0",
    ] {
        assert!(
            parse_text(&format!("cache {{\n{option}\n}}")).is_ok(),
            "{option}"
        );
    }
    for option in [
        "serve_stale aa",
        "serve_stale 0 after nono",
        "serve_stale 1h immediate garbage",
        "serve_stale 1h immediate 30s extra",
        "serve_stale 1h verify garbage",
        "serve_stale 1h verify 100ms -1s",
        "serve_stale 1h verify 100ms garbage",
        "serve_stale 1h verify 100ms 30s extra",
        "serve_stale 1h verify 100ms 30s 30s extra",
        "serve_stale\nserve_stale_policy prefer_positive extra",
    ] {
        assert!(
            parse_text(&format!("cache {{\n{option}\n}}")).is_err(),
            "{option}"
        );
    }
    let config = parse_text("cache {\nserve_stale 1h verify 1s 30s 5m\nserve_stale\n}").unwrap();
    assert!(!config.verify);
    assert_eq!(
        (
            config.verify_timeout,
            config.stale_ttl,
            config.stale_recheck
        ),
        (Duration::ZERO, Duration::from_secs(30), Duration::ZERO)
    );
}

#[test]
fn successive_directives_leave_cursor_for_caller() {
    let tokens = lex("Corefile", "cache example.org\ncache example.net");
    let mut cursor = Cursor::new("Corefile", &tokens);
    assert_eq!(
        parse(&mut cursor, &["."]).unwrap().zones[0].to_string(),
        "example.org."
    );
    assert_eq!(
        parse(&mut cursor, &["."]).unwrap().zones[0].to_string(),
        "example.net."
    );
}
