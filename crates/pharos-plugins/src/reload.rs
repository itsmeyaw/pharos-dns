//! Reload Directive configuration.

use std::time::Duration;

use pharos_corefile::{Cursor, Error};

#[derive(Clone, Copy, Debug)]
pub struct Reload {
    pub interval: Duration,
    pub jitter: Duration,
}

/// Parse the timing options without starting a watcher.
pub fn parse(cursor: &mut Cursor<'_>) -> Result<Reload, Error> {
    cursor.next();
    let args = cursor.remaining_args();
    if args.len() > 2 {
        return Err(cursor.arg_err());
    }
    let duration = |value: &str| {
        if let Some(magnitude) = value.strip_prefix('-') {
            if magnitude.starts_with(['-', '+']) {
                return None;
            }
            let parsed = crate::health::parse_duration(magnitude)?;
            return parsed.is_zero().then_some(parsed);
        }
        crate::health::parse_duration(value)
    };
    let interval = match args.first() {
        Some(value) => duration(value).ok_or_else(|| cursor.error("invalid interval"))?,
        None => Duration::from_secs(30),
    };
    if interval < Duration::from_secs(2) {
        return Err(cursor.error("interval must be at least 2s"));
    }
    let jitter = match args.get(1) {
        Some(value) => duration(value).ok_or_else(|| cursor.error("invalid jitter"))?,
        None => Duration::from_secs(15),
    };
    if !jitter.is_zero() && jitter < Duration::from_secs(1) {
        return Err(cursor.error("jitter must be zero or at least 1s"));
    }
    Ok(Reload {
        interval,
        jitter: jitter.min(interval / 2),
    })
}
