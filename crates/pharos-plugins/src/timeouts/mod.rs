//! Connection timeout Directive configuration.

pub(crate) mod setup;

use pharos_corefile::{Cursor, Error};
use std::time::Duration;

#[derive(Debug, Default)]
pub struct Timeouts {
    pub read: Option<Duration>,
    pub write: Option<Duration>,
    pub idle: Option<Duration>,
    pub max_tcp_queries: Option<i64>,
}

pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Timeouts, Error> {
    let mut config = Timeouts::default();
    while cursor.next() {
        if !cursor.remaining_args().is_empty() {
            return Err(cursor.arg_err());
        }
        let mut count = 0;
        while cursor.next_block() {
            let name = cursor.val().to_owned();
            let args = cursor.remaining_args();
            if args.len() != 1 {
                return Err(cursor.arg_err());
            }
            if name == "maxtcpqueries" {
                let n = args[0]
                    .parse::<i64>()
                    .map_err(|_| cursor.error("invalid maxtcpqueries"))?;
                if n < -1 || n == 0 {
                    return Err(cursor.error("invalid maxtcpqueries"));
                }
                config.max_tcp_queries = Some(n);
            } else {
                let value = if args[0].parse::<i64>().is_ok() {
                    format!("{}s", args[0])
                } else {
                    args[0].clone()
                };
                let duration = crate::health::parse_duration(&value)
                    .filter(|v| *v >= Duration::from_secs(1) && *v <= Duration::from_secs(86400))
                    .ok_or_else(|| cursor.error("invalid duration"))?;
                match name.as_str() {
                    "read" => config.read = Some(duration),
                    "write" => config.write = Some(duration),
                    "idle" => config.idle = Some(duration),
                    _ => return Err(cursor.error("unknown option")),
                }
            }
            count += 1;
        }
        if count == 0 {
            return Err(cursor.error("timeouts block with no timeouts specified"));
        }
    }
    Ok(config)
}
