//! `grpc_server` Directive: connection and stream limits of `grpc://` Listeners.

pub(crate) mod setup;

use pharos_corefile::{Cursor, Error};

/// Limits configured by one Server Block; `None` keeps the Listener default.
#[derive(Debug, Default)]
pub struct GrpcServer {
    pub max_streams: Option<u32>,
    pub max_connections: Option<usize>,
}

impl GrpcServer {
    /// The Listener limits, with defaults for every value left unset.
    pub fn options(&self) -> pharos_server::GrpcOptions {
        let defaults = pharos_server::GrpcOptions::default();
        pharos_server::GrpcOptions {
            max_streams: self.max_streams.unwrap_or(defaults.max_streams),
            max_connections: self.max_connections.unwrap_or(defaults.max_connections),
        }
    }
}

// CoreDNS v1.15.0 plugin/grpc_server/setup.go parseGRPCServer: a non-negative integer, set at most once per block.
fn number(cursor: &mut Cursor<'_>, name: &str) -> Result<u64, Error> {
    let args = cursor.remaining_args();
    let [arg] = args.as_slice() else {
        return Err(cursor.arg_err());
    };
    let value: i64 = arg
        .parse()
        .map_err(|error| cursor.error(format!("invalid {name} value '{arg}': {error}")))?;
    u64::try_from(value)
        .map_err(|_| cursor.error(format!("{name} must be a non-negative integer: {value}")))
}

pub(crate) fn parse(cursor: &mut Cursor<'_>, mut config: GrpcServer) -> Result<GrpcServer, Error> {
    while cursor.next() {
        if !cursor.remaining_args().is_empty() {
            return Err(cursor.arg_err());
        }
        while cursor.next_block() {
            let name = cursor.val().to_owned();
            match name.as_str() {
                "max_streams" => {
                    let value = number(cursor, &name)?;
                    // CoreDNS passes uint32(value) to grpc.MaxConcurrentStreams and wraps; Pharos rejects it.
                    let value = u32::try_from(value).map_err(|_| {
                        cursor.error(format!("max_streams must not exceed {}: {value}", u32::MAX))
                    })?;
                    if config.max_streams.replace(value).is_some() {
                        return Err(
                            cursor.error("max_streams already defined for this server block")
                        );
                    }
                }
                "max_connections" => {
                    let value = number(cursor, &name)?;
                    let value = usize::try_from(value).map_err(|_| {
                        cursor.error(format!("invalid max_connections value '{value}'"))
                    })?;
                    if config.max_connections.replace(value).is_some() {
                        return Err(
                            cursor.error("max_connections already defined for this server block")
                        );
                    }
                }
                other => return Err(cursor.error(format!("unknown property '{other}'"))),
            }
        }
    }
    Ok(config)
}
