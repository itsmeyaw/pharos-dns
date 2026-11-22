//! `min-lease-ttl` and `max-lease-ttl` values, parsed like CoreDNS does with Go's `time.ParseDuration`.

const NS_PER_SECOND: i64 = 1_000_000_000;
const INVALID_FORMAT: &str =
    "invalid TTL format, use format like '30', '30s', '5m', '1h', or '2h30m'";

/// CoreDNS v1.15.0 plugin/etcd/setup.go parseTTL: seconds from a bare number or a Go duration.
pub(super) fn parse_ttl(text: &str) -> Result<u32, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(0);
    }
    // CoreDNS v1.15.0 plugin/etcd/setup.go parseTTL: a plain number is seconds.
    let plain = text.bytes().all(|byte| byte.is_ascii_digit()) && text.parse::<u64>().is_ok();
    let nanoseconds = if plain {
        parse_duration(&format!("{text}s"))
    } else {
        parse_duration(text)
    }
    .map_err(|()| INVALID_FORMAT.to_owned())?;
    // Go time.Duration.Seconds: whole seconds and the fraction are added as float64.
    let seconds = (nanoseconds / NS_PER_SECOND) as f64 + (nanoseconds % NS_PER_SECOND) as f64 / 1e9;
    if seconds < 0.0 {
        return Err("TTL must be non-negative".to_owned());
    }
    if seconds > f64::from(u32::MAX) {
        return Err(format!("TTL too large, maximum is {} seconds", u32::MAX));
    }
    Ok(seconds as u32)
}

/// Go `time.ParseDuration`: nanoseconds of `[-+]?([0-9]*(\.[0-9]*)?[a-z]+)+`; `Err` for what Go rejects.
fn parse_duration(original: &str) -> Result<i64, ()> {
    const LIMIT: u64 = 1 << 63;
    let mut rest = original;
    let negative = rest.starts_with('-');
    if negative || rest.starts_with('+') {
        rest = &rest[1..];
    }
    // Go time.ParseDuration: a bare "0" is zero and needs no unit.
    if rest == "0" {
        return Ok(0);
    }
    if rest.is_empty() {
        return Err(());
    }
    let mut total: u64 = 0;
    while !rest.is_empty() {
        if !(rest.starts_with('.') || rest.starts_with(|c: char| c.is_ascii_digit())) {
            return Err(());
        }
        let (whole, after) = leading_int(rest).ok_or(())?;
        let before_period = after.len() != rest.len();
        rest = after;
        let mut fraction = 0_u64;
        let mut scale = 1.0_f64;
        let mut after_period = false;
        if let Some(digits) = rest.strip_prefix('.') {
            let (value, divisor, after) = leading_fraction(digits);
            after_period = after.len() != digits.len();
            (fraction, scale, rest) = (value, divisor, after);
        }
        if !before_period && !after_period {
            return Err(());
        }
        let unit_end = rest
            .find(|c: char| c == '.' || c.is_ascii_digit())
            .unwrap_or(rest.len());
        // Go time.ParseDuration: a number without a unit, or with an unknown one, is an error.
        let unit = unit_nanoseconds(&rest[..unit_end]).ok_or(())?;
        rest = &rest[unit_end..];
        if whole > LIMIT / unit {
            return Err(());
        }
        let mut value = whole * unit;
        if fraction > 0 {
            // Go time.ParseDuration: float64 keeps fractions of an hour nanosecond accurate.
            value += (fraction as f64 * (unit as f64 / scale)) as u64;
            if value > LIMIT {
                return Err(());
            }
        }
        total += value;
        if total > LIMIT {
            return Err(());
        }
    }
    if negative {
        return Ok((total as i64).wrapping_neg());
    }
    i64::try_from(total).map_err(|_| ())
}

/// Go time.ParseDuration `unitMap`.
fn unit_nanoseconds(unit: &str) -> Option<u64> {
    Some(match unit {
        "ns" => 1,
        "us" | "\u{b5}s" | "\u{3bc}s" => 1_000,
        "ms" => 1_000_000,
        "s" => 1_000_000_000,
        "m" => 60_000_000_000,
        "h" => 3_600_000_000_000,
        _ => return None,
    })
}

/// Go time.leadingInt: the digits at the start of `text` as a value up to 2^63, and the rest.
fn leading_int(text: &str) -> Option<(u64, &str)> {
    let end = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let mut value: u64 = 0;
    for byte in text.as_bytes()[..end].iter() {
        if value > (1 << 63) / 10 {
            return None;
        }
        value = value * 10 + u64::from(byte - b'0');
        if value > 1 << 63 {
            return None;
        }
    }
    Some((value, &text[end..]))
}

/// Go time.leadingFraction: the digits after a period as a value, its power-of-ten scale, and the rest; digits that overflow are ignored.
fn leading_fraction(text: &str) -> (u64, f64, &str) {
    let end = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (mut value, mut scale, mut overflow) = (0_u64, 1.0_f64, false);
    for byte in text.as_bytes()[..end].iter() {
        if overflow {
            continue;
        }
        if value > (u64::MAX >> 1) / 10 {
            overflow = true;
            continue;
        }
        let next = value * 10 + u64::from(byte - b'0');
        if next > 1 << 63 {
            overflow = true;
            continue;
        }
        value = next;
        scale *= 10.0;
    }
    (value, scale, &text[end..])
}

#[cfg(test)]
mod tests;
