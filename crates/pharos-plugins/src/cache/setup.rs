use std::time::Duration;

use pharos_corefile::{Cursor, Error, normalize_domain, origins_from_args_or_server_block};
use pharos_proto::Name;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Config {
    pub(super) zones: Vec<Name>,
    pub(super) success_capacity: i64,
    pub(super) denial_capacity: i64,
    pub(super) success_max_ttl: Duration,
    pub(super) success_min_ttl: Duration,
    pub(super) denial_max_ttl: Duration,
    pub(super) denial_min_ttl: Duration,
    pub(super) prefetch_amount: i64,
    pub(super) prefetch_duration: i64,
    pub(super) prefetch_percentage: i64,
    pub(super) stale: Duration,
    pub(super) verify: bool,
    pub(super) verify_timeout: Duration,
    pub(super) stale_ttl: Duration,
    pub(super) stale_recheck: Duration,
    pub(super) prefer_positive: bool,
    pub(super) fail_ttl: Duration,
    pub(super) disable_success: Vec<Name>,
    pub(super) disable_denial: Vec<Name>,
    pub(super) keepttl: bool,
}

pub(super) fn parse(cursor: &mut Cursor<'_>, server_keys: &[&str]) -> Result<Config, Error> {
    if !cursor.next() || cursor.val() != "cache" {
        return Err(cursor.error("expected cache Directive"));
    }
    let args = cursor.remaining_args();
    let mut zone_args = args.as_slice();
    let mut ttl = None;
    if let Some(value) = args.first().and_then(|arg| arg.parse::<i64>().ok()) {
        ttl = Some(ttl_seconds(cursor, value, false)?);
        zone_args = &args[1..];
    }
    let zone_args: Vec<&str> = zone_args.iter().map(String::as_str).collect();
    let zones = origins_from_args_or_server_block(&zone_args, server_keys)
        .iter()
        .map(|name| {
            name.parse()
                .map_err(|_| cursor.error(format!("invalid zone {name}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut config = Config {
        zones,
        success_capacity: 10_000,
        denial_capacity: 10_000,
        success_max_ttl: Duration::from_secs(3600),
        success_min_ttl: Duration::from_secs(5),
        denial_max_ttl: Duration::from_secs(1800),
        denial_min_ttl: Duration::from_secs(5),
        prefetch_amount: 0,
        prefetch_duration: 60_000_000_000,
        prefetch_percentage: 10,
        stale: Duration::ZERO,
        verify: false,
        verify_timeout: Duration::ZERO,
        stale_ttl: Duration::ZERO,
        stale_recheck: Duration::ZERO,
        prefer_positive: false,
        fail_ttl: Duration::from_secs(5),
        disable_success: Vec::new(),
        disable_denial: Vec::new(),
        keepttl: false,
    };
    if let Some(ttl) = ttl {
        config.success_max_ttl = ttl;
        config.denial_max_ttl = ttl;
    }
    let mut stale_configured = false;
    let mut policy_configured = false;
    while cursor.next_block() {
        let option = cursor.val().to_owned();
        let args = cursor.remaining_args();
        match option.as_str() {
            "success" | "denial" => {
                if args.is_empty() {
                    return Err(cursor.arg_err());
                }
                let capacity = integer(cursor, &args[0])?;
                let max = args
                    .get(1)
                    .map(|s| integer(cursor, s).and_then(|n| ttl_seconds(cursor, n, false)))
                    .transpose()?;
                let min = args
                    .get(2)
                    .map(|s| integer(cursor, s).and_then(|n| ttl_seconds(cursor, n, true)))
                    .transpose()?;
                let (cap, max_ttl, min_ttl) = if option == "success" {
                    (
                        &mut config.success_capacity,
                        &mut config.success_max_ttl,
                        &mut config.success_min_ttl,
                    )
                } else {
                    (
                        &mut config.denial_capacity,
                        &mut config.denial_max_ttl,
                        &mut config.denial_min_ttl,
                    )
                };
                *cap = capacity;
                if let Some(value) = max {
                    *max_ttl = value;
                }
                if let Some(value) = min {
                    *min_ttl = value;
                }
            }
            "prefetch" => {
                if args.is_empty() || args.len() > 3 {
                    return Err(cursor.arg_err());
                }
                let amount = integer(cursor, &args[0])?;
                if amount < 0 {
                    return Err(cursor.error("prefetch amount must not be negative"));
                }
                config.prefetch_amount = amount;
                if let Some(value) = args.get(1) {
                    config.prefetch_duration =
                        duration(value).ok_or_else(|| cursor.error("invalid prefetch duration"))?;
                }
                if let Some(value) = args.get(2) {
                    let percentage = value
                        .strip_suffix('%')
                        .ok_or_else(|| cursor.error("invalid prefetch percentage"))?;
                    let percentage = integer(cursor, percentage)?;
                    if !(10..=90).contains(&percentage) {
                        return Err(cursor.error("prefetch percentage must be between 10 and 90"));
                    }
                    config.prefetch_percentage = percentage;
                }
            }
            "serve_stale" => {
                if args.len() > 5 {
                    return Err(cursor.arg_err());
                }
                stale_configured = true;
                config.stale = Duration::from_secs(3600);
                config.verify = false;
                config.verify_timeout = Duration::ZERO;
                config.stale_ttl = Duration::ZERO;
                config.stale_recheck = Duration::ZERO;
                if let Some(value) = args.first() {
                    config.stale = nonnegative_duration(cursor, value)?;
                }
                if let Some(mode) = args.get(1) {
                    if mode.eq_ignore_ascii_case("verify") {
                        config.verify = true;
                    } else if !mode.eq_ignore_ascii_case("immediate") {
                        return Err(cursor.error("invalid serve_stale refresh mode"));
                    }
                }
                let ttl_index = if config.verify {
                    if let Some(value) = args.get(2) {
                        config.verify_timeout = nonnegative_duration(cursor, value)?;
                    }
                    3
                } else {
                    if args.len() > 4 {
                        return Err(cursor.arg_err());
                    }
                    2
                };
                if let Some(value) = args.get(ttl_index) {
                    config.stale_ttl = nonnegative_duration(cursor, value)?;
                    if config.stale_ttl.subsec_nanos() != 0
                        || config.stale_ttl.as_secs() > u64::from(u32::MAX)
                    {
                        return Err(cursor.error(
                            "serve_stale response TTL must be whole seconds in DNS TTL range",
                        ));
                    }
                }
                if let Some(value) = args.get(ttl_index + 1) {
                    config.stale_recheck = nonnegative_duration(cursor, value)?;
                    // RFC 8767 §6: the stale failure recheck interval should not exceed 5 minutes.
                    if config.stale_recheck > Duration::from_secs(300) {
                        return Err(cursor.error("serve_stale recheck exceeds 5 minutes"));
                    }
                }
            }
            "serve_stale_policy" => {
                if policy_configured {
                    return Err(cursor.error("serve_stale_policy can only be specified once"));
                }
                policy_configured = true;
                if args.len() != 1 {
                    return Err(cursor.arg_err());
                }
                if !args[0].eq_ignore_ascii_case("prefer_positive") {
                    return Err(cursor.error("invalid serve_stale_policy"));
                }
                config.prefer_positive = true;
            }
            "servfail" => {
                if args.len() != 1 {
                    return Err(cursor.arg_err());
                }
                config.fail_ttl = nonnegative_duration(cursor, &args[0])?;
                // RFC 9520 §3.2: resolution failures must not be cached for over 5 minutes.
                if config.fail_ttl > Duration::from_secs(300) {
                    return Err(cursor.error("servfail TTL exceeds 5 minutes"));
                }
            }
            "disable" => {
                if args.is_empty() {
                    return Err(cursor.arg_err());
                }
                let zones = if args.len() == 1 {
                    vec![".".parse().expect("root is a valid name")]
                } else {
                    let mut zones = Vec::new();
                    for value in &args[1..] {
                        let normalized = normalize_domain(value);
                        if normalized.is_empty() {
                            return Err(cursor.error(format!("invalid disabled zone {value}")));
                        }
                        for name in normalized {
                            zones.push(name.parse().map_err(|_| {
                                cursor.error(format!("invalid disabled zone {value}"))
                            })?);
                        }
                    }
                    zones
                };
                match args[0].as_str() {
                    "success" => config.disable_success = zones,
                    "denial" => config.disable_denial = zones,
                    _ => return Err(cursor.error("disable requires success or denial")),
                }
            }
            "keepttl" => {
                if !args.is_empty() {
                    return Err(cursor.arg_err());
                }
                config.keepttl = true;
            }
            _ => return Err(cursor.arg_err()),
        }
    }
    if policy_configured && !stale_configured {
        return Err(cursor.error("serve_stale_policy requires serve_stale"));
    }
    Ok(config)
}

fn integer(cursor: &Cursor<'_>, value: &str) -> Result<i64, Error> {
    value
        .parse()
        .map_err(|_| cursor.error(format!("invalid integer {value}")))
}

fn ttl_seconds(cursor: &Cursor<'_>, value: i64, allow_zero: bool) -> Result<Duration, Error> {
    if value < 0 || (!allow_zero && value == 0) {
        return Err(cursor.error(format!("invalid TTL {value}")));
    }
    Ok(Duration::from_secs(value as u64))
}

fn nonnegative_duration(cursor: &Cursor<'_>, value: &str) -> Result<Duration, Error> {
    let nanos = duration(value).ok_or_else(|| cursor.error(format!("invalid duration {value}")))?;
    let nanos =
        u64::try_from(nanos).map_err(|_| cursor.error(format!("negative duration {value}")))?;
    Ok(Duration::from_nanos(nanos))
}

// Go durations are signed nanoseconds, with each fractional component truncated.
fn duration(value: &str) -> Option<i64> {
    let (negative, mut rest) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    if rest == "0" {
        return Some(0);
    }
    if rest.is_empty() {
        return None;
    }
    let mut total = 0u128;
    while !rest.is_empty() {
        let number_end = rest
            .find(|ch: char| !ch.is_ascii_digit() && ch != '.')
            .unwrap_or(rest.len());
        let number = &rest[..number_end];
        rest = &rest[number_end..];
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if (whole.is_empty() && fraction.is_empty())
            || !whole.bytes().all(|b| b.is_ascii_digit())
            || !fraction.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let unit_end = rest
            .find(|ch: char| ch.is_ascii_digit() || ch == '.')
            .unwrap_or(rest.len());
        let unit = match &rest[..unit_end] {
            "ns" => 1u128,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return None,
        };
        rest = &rest[unit_end..];
        let whole = if whole.is_empty() {
            0
        } else {
            whole.parse::<u128>().ok()?
        };
        let digits = &fraction[..fraction.len().min(18)];
        let fraction = if digits.is_empty() {
            0
        } else {
            digits.parse::<u128>().ok()?.checked_mul(unit)? / 10u128.pow(digits.len() as u32)
        };
        total = total.checked_add(whole.checked_mul(unit)?.checked_add(fraction)?)?;
        if total > (i64::MAX as u128) + u128::from(negative) {
            return None;
        }
    }
    if negative {
        if total == (i64::MAX as u128) + 1 {
            Some(i64::MIN)
        } else {
            Some(-(total as i64))
        }
    } else {
        Some(total as i64)
    }
}

pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::cache;

    let zones = block
        .keys()
        .iter()
        .map(|key| key.domain.clone())
        .collect::<Vec<_>>();
    block.config.cache = Some(cache::Cache::parse(cursor, &zones)?);
    Ok(())
}

#[cfg(test)]
mod tests {
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
            parse_text("cache 25 Example.NL {\nsuccess 10 1800 30 ignored\ndenial 20 15 0\n}")
                .unwrap();
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
        let config = parse_text("cache {\nservfail 5m\ndisable denial Example.com example.org\ndisable success\nkeepttl\n}").unwrap();
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
    fn coredns_stale_and_servfail_cases() {
        for (option, stale, verify, timeout, ttl, recheck) in [
            ("serve_stale", 3600, false, 0, 0, 0),
            ("serve_stale 20m", 1200, false, 0, 0, 0),
            ("serve_stale 1h20m", 4800, false, 0, 0, 0),
            ("serve_stale 0m", 0, false, 0, 0, 0),
            ("serve_stale 0", 0, false, 0, 0, 0),
            ("serve_stale 0 verify", 0, true, 0, 0, 0),
            ("serve_stale 0 immediate", 0, false, 0, 0, 0),
            ("serve_stale 0 VERIFY", 0, true, 0, 0, 0),
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
            ("serve_stale 1h verify 100ms", 3600, true, 100, 0, 0),
            ("serve_stale 1h verify 100ms 30s", 3600, true, 100, 30, 0),
            (
                "serve_stale 1h verify 100ms 30s 30s",
                3600,
                true,
                100,
                30,
                30000,
            ),
            ("serve_stale 1h verify 0", 3600, true, 0, 0, 0),
            ("serve_stale 1h verify 0 1m", 3600, true, 0, 60, 0),
            ("serve_stale 1h VERIFY 250ms", 3600, true, 250, 0, 0),
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
        let config =
            parse_text("cache {\nserve_stale 1h verify 1s 30s 5m\nserve_stale\n}").unwrap();
        assert!(!config.verify);
        assert_eq!(
            (
                config.verify_timeout,
                config.stale_ttl,
                config.stale_recheck
            ),
            (Duration::ZERO, Duration::ZERO, Duration::ZERO)
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
}
