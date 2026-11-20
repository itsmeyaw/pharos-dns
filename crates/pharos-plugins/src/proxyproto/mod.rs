//! `proxyproto` Directive: PROXY protocol v1 and v2 on Listener accept paths.

pub(crate) mod setup;

use std::{net::IpAddr, sync::Arc, time::Duration};

use pharos_corefile::{Cursor, Error};
use pharos_server::proxyproto::{Config, Policy, UdpTracking, session::DEFAULT_MAX_SESSIONS};

/// The PROXY protocol settings the Listeners of a Server Block apply.
#[derive(Debug)]
pub struct Proxyproto {
    pub config: Arc<Config>,
}

// CoreDNS v1.15.0 plugin/proxyproto/setup.go setup: `allow`, `default`, `udp_session_tracking` and `tlv_metadata`.
pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Proxyproto, Error> {
    let mut allowed: Vec<(IpAddr, u8)> = Vec::new();
    let mut default = None;
    let mut ttl = Duration::ZERO;
    let mut max_sessions = DEFAULT_MAX_SESSIONS;
    let mut tlv_metadata = false;
    while cursor.next() {
        if !cursor.remaining_args().is_empty() {
            return Err(cursor.arg_err());
        }
        while cursor.next_block() {
            match cursor.val() {
                "allow" => {
                    for value in cursor.remaining_args() {
                        allowed.push(parse_cidr(&value).ok_or_else(|| {
                            cursor.error(format!("{value}: invalid CIDR address: {value}"))
                        })?);
                    }
                }
                "default" => {
                    let args = cursor.remaining_args();
                    let [value] = args.as_slice() else {
                        return Err(cursor.arg_err());
                    };
                    default = Some(match value.to_ascii_lowercase().as_str() {
                        "use" => Policy::Use,
                        "ignore" => Policy::Ignore,
                        "reject" => Policy::Reject,
                        "skip" => Policy::Skip,
                        _ => return Err(cursor.arg_err()),
                    });
                }
                "udp_session_tracking" => {
                    let args = cursor.remaining_args();
                    if args.is_empty() || args.len() > 2 {
                        return Err(cursor.arg_err());
                    }
                    ttl = crate::health::parse_duration(&args[0]).ok_or_else(|| {
                        cursor.error(format!(
                            "udp_session_tracking: invalid duration \"{}\"",
                            args[0]
                        ))
                    })?;
                    if let Some(value) = args.get(1) {
                        max_sessions = value
                            .parse::<usize>()
                            .ok()
                            .filter(|count| *count > 0)
                            .ok_or_else(|| {
                                cursor.error(format!(
                                    "udp_session_tracking: invalid max sessions \"{value}\": must be a positive integer"
                                ))
                            })?;
                    }
                }
                "tlv_metadata" => {
                    if !cursor.remaining_args().is_empty() {
                        return Err(cursor.arg_err());
                    }
                    tlv_metadata = true;
                }
                other => return Err(cursor.error(format!("unknown option '{other}'"))),
            }
        }
    }
    // CoreDNS v1.15.0 plugin/proxyproto/setup.go: without `allow`, `default` applies to every peer, and USE when unset.
    let fallback = default.unwrap_or(Policy::Ignore);
    let mut config = Config::new(move |address| {
        if allowed.is_empty() {
            return default.unwrap_or(Policy::Use);
        }
        if allowed
            .iter()
            .any(|(network, prefix)| crate::ipnet::contains(*network, *prefix, address))
        {
            return Policy::Use;
        }
        fallback
    });
    // CoreDNS v1.15.0 plugin/pkg/proxyproto/proxyproto.go: a zero or negative TTL disables session tracking.
    config.udp_tracking = (!ttl.is_zero()).then_some(UdpTracking { ttl, max_sessions });
    config.tlv_metadata = tlv_metadata;
    Ok(Proxyproto {
        config: Arc::new(config),
    })
}

// Go net.ParseCIDR: the prefix length is mandatory and the address family fixes its maximum.
fn parse_cidr(value: &str) -> Option<(IpAddr, u8)> {
    let (address, prefix) = value.split_once('/')?;
    let address: IpAddr = address.parse().ok()?;
    if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let prefix: u8 = prefix.parse().ok()?;
    (prefix <= if address.is_ipv4() { 32 } else { 128 }).then_some((address, prefix))
}
