//! `https3` Directive: connection and stream limits of `https3://` Listeners.

pub(crate) mod setup;

use pharos_corefile::{Cursor, Error};

/// Limits set by the Directive; an absent value keeps the Listener default.
#[derive(Debug, Default)]
pub struct Https3 {
    pub max_streams: Option<usize>,
    pub max_connections: Option<usize>,
}

// CoreDNS v1.15.0 plugin/https3/setup.go parseDOH3: two non-negative limits, each set at most once.
pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Https3, Error> {
    let mut https3 = Https3::default();
    if !cursor.next() {
        return Err(cursor.arg_err());
    }
    if !cursor.remaining_args().is_empty() {
        return Err(cursor.arg_err());
    }
    while cursor.next_block() {
        let name = cursor.val().to_owned();
        let slot = match name.as_str() {
            "max_streams" => &mut https3.max_streams,
            "max_connections" => &mut https3.max_connections,
            other => return Err(cursor.error(format!("unknown property '{other}'"))),
        };
        let args = cursor.remaining_args();
        let [arg] = args.as_slice() else {
            return Err(cursor.arg_err());
        };
        let value: i64 = arg
            .parse()
            .map_err(|error| cursor.error(format!("invalid {name} value '{arg}': {error}")))?;
        if value < 0 {
            return Err(cursor.error(format!("{name} must be a non-negative integer: {value}")));
        }
        if slot.is_some() {
            return Err(cursor.error(format!("{name} already defined for this server block")));
        }
        *slot = Some(usize::try_from(value).unwrap_or(usize::MAX));
    }
    Ok(https3)
}
