//! `quic` Directive: DNS over QUIC resource limits.

pub(crate) mod setup;

use pharos_corefile::{Cursor, Error};

/// Limits set by the Directive; an absent value keeps the Listener default.
#[derive(Debug, Default)]
pub struct Quic {
    pub max_streams: Option<usize>,
    pub max_connections: Option<usize>,
    pub worker_pool_size: Option<usize>,
}

impl Quic {
    /// The Listener limits, with defaults for every value left unset.
    pub fn options(&self) -> pharos_server::QuicOptions {
        let defaults = pharos_server::QuicOptions::default();
        pharos_server::QuicOptions {
            max_streams: self.max_streams.unwrap_or(defaults.max_streams),
            max_connections: self.max_connections.unwrap_or(defaults.max_connections),
            worker_pool_size: self.worker_pool_size.unwrap_or(defaults.worker_pool_size),
        }
    }
}

// CoreDNS v1.15.0 plugin/quic/setup.go parseQuic: three limits, each set at most once.
pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Quic, Error> {
    let mut quic = Quic::default();
    if !cursor.next() {
        return Err(cursor.arg_err());
    }
    if !cursor.remaining_args().is_empty() {
        return Err(cursor.arg_err());
    }
    while cursor.next_block() {
        let name = cursor.val().to_owned();
        let (slot, minimum) = match name.as_str() {
            "max_streams" => (&mut quic.max_streams, 1),
            "max_connections" => (&mut quic.max_connections, 0),
            "worker_pool_size" => (&mut quic.worker_pool_size, 1),
            other => return Err(cursor.error(format!("unknown property '{other}'"))),
        };
        let args = cursor.remaining_args();
        let [arg] = args.as_slice() else {
            return Err(cursor.arg_err());
        };
        let value: i64 = arg
            .parse()
            .map_err(|error| cursor.error(format!("invalid {name} value '{arg}': {error}")))?;
        if value < minimum {
            let kind = if minimum == 0 {
                "non-negative"
            } else {
                "positive"
            };
            return Err(cursor.error(format!("{name} must be a {kind} integer: {value}")));
        }
        if slot.is_some() {
            return Err(cursor.error(format!("{name} already defined for this server block")));
        }
        *slot = Some(usize::try_from(value).unwrap_or(usize::MAX));
    }
    Ok(quic)
}
