//! `pprof` endpoint configuration and profiling HTTP handlers.

pub(crate) mod http;
pub(crate) mod setup;

use pharos_corefile::{Cursor, Error};

/// CoreDNS v1.15.0 plugin/pprof/setup.go: the default listen address.
const DEFAULT_ADDRESS: &str = "localhost:6053";

#[derive(Debug)]
pub struct Pprof {
    pub address: String,
    /// `block [RATE]`; accepted and validated, but Pharos has no block profiler to configure.
    pub block_rate: Option<i64>,
}

pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Pprof, Error> {
    let mut address = DEFAULT_ADDRESS.to_owned();
    let mut block_rate = None;
    // CoreDNS v1.15.0 plugin/pprof/setup.go: one directive line; a second is ErrOnce (Directive.once).
    if cursor.next() {
        let args = cursor.remaining_args();
        if args.len() > 1 {
            return Err(cursor.arg_err());
        }
        if let Some(value) = args.first() {
            // CoreDNS v1.15.0 plugin/pprof/setup.go: the address must pass net.SplitHostPort.
            if !crate::valid_http_address(value) {
                return Err(cursor.error(format!("invalid pprof address '{value}'")));
            }
            address.clone_from(value);
        }
        while cursor.next_block() {
            if cursor.val() != "block" {
                return Err(cursor.error(format!("unknown property '{}'", cursor.val())));
            }
            let args = cursor.remaining_args();
            if args.len() > 1 {
                return Err(cursor.arg_err());
            }
            // CoreDNS v1.15.0 plugin/pprof/setup.go: RATE defaults to 1 and is parsed by strconv.Atoi.
            block_rate = Some(match args.first() {
                None => 1,
                Some(value) => value.parse::<i64>().map_err(|_| {
                    cursor.error(format!("property 'block' invalid integer value '{value}'"))
                })?,
            });
        }
    }
    Ok(Pprof {
        address,
        block_rate,
    })
}
