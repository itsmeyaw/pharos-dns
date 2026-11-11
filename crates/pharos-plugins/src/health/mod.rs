//! Health endpoint configuration.

pub(crate) mod setup;

use std::time::Duration;

#[cfg(feature = "plugin-health")]
use pharos_corefile::{Cursor, Error};

#[cfg(feature = "plugin-health")]
#[derive(Debug)]
pub struct Health {
    pub address: String,
    pub lameduck: Duration,
}

#[cfg(feature = "plugin-health")]
pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Health, Error> {
    let mut address = ":8080".to_owned();
    let mut lameduck = Duration::ZERO;
    while cursor.next() {
        let args = cursor.remaining_args();
        if args.len() > 1 {
            return Err(cursor.arg_err());
        }
        if let Some(value) = args.first() {
            if !crate::valid_http_address(value) {
                return Err(cursor.error("invalid health address"));
            }
            address.clone_from(value);
        }
        while cursor.next_block() {
            if cursor.val() != "lameduck" {
                return Err(cursor.error(format!("unknown property: {}", cursor.val())));
            }
            let args = cursor.remaining_args();
            if args.len() != 1 {
                return Err(cursor.arg_err());
            }
            lameduck = parse_duration(&args[0]).ok_or_else(|| cursor.error("invalid duration"))?;
        }
    }
    Ok(Health { address, lameduck })
}

pub(crate) fn parse_duration(value: &str) -> Option<Duration> {
    let (negative, mut rest) = match value.as_bytes().first() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    if rest == "0" {
        return Some(Duration::ZERO);
    }
    if rest.is_empty() {
        return None;
    }
    let mut total = 0u128;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        let integer = if digits == 0 {
            0
        } else {
            rest[..digits].parse::<u128>().ok()?
        };
        rest = &rest[digits..];
        let mut fraction = 0u128;
        let mut scale = 1u128;
        let mut decimals = 0;
        if let Some(after_dot) = rest.strip_prefix('.') {
            decimals = after_dot.bytes().take_while(u8::is_ascii_digit).count();
            for digit in after_dot.bytes().take(decimals) {
                if scale < 1_000_000_000_000_000_000 {
                    fraction = fraction * 10 + u128::from(digit - b'0');
                    scale *= 10;
                }
            }
            rest = &after_dot[decimals..];
        }
        if digits == 0 && decimals == 0 {
            return None;
        }
        let end = rest
            .find(|ch: char| ch.is_ascii_digit() || ch == '.')
            .unwrap_or(rest.len());
        let unit = match &rest[..end] {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return None,
        };
        total = total.checked_add(integer.checked_mul(unit)?)?;
        total = total.checked_add(fraction * unit / scale)?;
        let limit = if negative {
            1u128 << 63
        } else {
            i64::MAX as u128
        };
        if total > limit {
            return None;
        }
        rest = &rest[end..];
    }
    Some(if negative {
        Duration::ZERO
    } else {
        Duration::from_nanos(total as u64)
    })
}
