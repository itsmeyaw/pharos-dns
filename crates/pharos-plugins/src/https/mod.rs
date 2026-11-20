//! `https` Directive: connection and stream limits of `https://` Listeners.

pub(crate) mod setup;

use pharos_corefile::{Cursor, Error};

/// Limits configured by one Server Block; `None` keeps the Listener default.
#[derive(Debug, Default)]
pub struct Https {
    pub max_connections: Option<usize>,
    pub max_streams: Option<u32>,
}

// CoreDNS v1.15.0 plugin/https/setup.go parseDOH: a non-negative integer, set at most once per block.
fn number(cursor: &Cursor<'_>, name: &str, args: &[String]) -> Result<u64, Error> {
    let [arg] = args else {
        return Err(cursor.arg_err());
    };
    let value: i64 = arg
        .parse()
        .map_err(|error| cursor.error(format!("invalid {name} value '{arg}': {error}")))?;
    u64::try_from(value)
        .map_err(|_| cursor.error(format!("{name} must be a non-negative integer: {value}")))
}

pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Https, Error> {
    let mut config = Https::default();
    while cursor.next() {
        if !cursor.remaining_args().is_empty() {
            return Err(cursor.arg_err());
        }
        while cursor.next_block() {
            let name = cursor.val().to_owned();
            let args = cursor.remaining_args();
            match name.as_str() {
                "max_connections" => {
                    let value = number(cursor, &name, &args)?;
                    if config.max_connections.is_some() {
                        return Err(
                            cursor.error("max_connections already defined for this server block")
                        );
                    }
                    config.max_connections = Some(usize::try_from(value).map_err(|_| {
                        cursor.error(format!("invalid max_connections value '{value}'"))
                    })?);
                }
                "max_streams" => {
                    let value = number(cursor, &name, &args)?;
                    let value = u32::try_from(value).map_err(|_| {
                        cursor.error(format!("max_streams must not exceed {}: {value}", u32::MAX))
                    })?;
                    if config.max_streams.is_some() {
                        return Err(
                            cursor.error("max_streams already defined for this server block")
                        );
                    }
                    config.max_streams = Some(value);
                }
                other => return Err(cursor.error(format!("unknown property '{other}'"))),
            }
        }
    }
    Ok(config)
}
