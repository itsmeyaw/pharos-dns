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
        // RFC 9520 §3.2: bound failure-cache memory with a configurable capacity.
        denial_capacity: 10_000,
        success_max_ttl: Duration::from_secs(3600),
        success_min_ttl: Duration::from_secs(5),
        // RFC 2308 §3: Retain denial_min_ttl for syntax compatibility; response lifetime never uses it.
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
                // RFC 8767 §4: The default stale response TTL should be 30 seconds.
                config.stale_ttl = Duration::from_secs(30);
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
            // RFC 9520 §3.2: let operators configure the cache duration for resolution failures.
            "servfail" => {
                if args.len() != 1 {
                    return Err(cursor.arg_err());
                }
                config.fail_ttl = nonnegative_duration(cursor, &args[0])?;
                // RFC 9520 §3.2: Failure entries must live for at least one second.
                config.fail_ttl = config.fail_ttl.max(Duration::from_secs(1));
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
    // RFC 2308 §5: The negative-cache maximum must not exceed the positive maximum.
    config.denial_max_ttl = config.denial_max_ttl.min(config.success_max_ttl);
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
mod tests;
