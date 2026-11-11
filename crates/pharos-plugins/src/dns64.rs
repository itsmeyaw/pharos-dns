//! DNS64 address synthesis.

use std::net::Ipv6Addr;

use pharos_corefile::{Cursor, Error};
use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct Dns64 {
    prefix: [u8; 16],
    prefix_len: u8,
    translate_all: bool,
    allow_ipv4: bool,
}

impl Dns64 {
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        let mut result = Self {
            prefix: "64:ff9b::".parse::<Ipv6Addr>().unwrap().octets(),
            prefix_len: 96,
            translate_all: false,
            allow_ipv4: false,
        };
        while cursor.next() {
            let args = cursor.remaining_args();
            if let [prefix] = args.as_slice() {
                (result.prefix, result.prefix_len) = parse_prefix(cursor, prefix)?;
                continue;
            }
            if !args.is_empty() {
                return Err(cursor.arg_err());
            }
            while cursor.next_block() {
                match cursor.val() {
                    "prefix" => {
                        let args = cursor.remaining_args();
                        let Some(prefix) = args.first() else {
                            return Err(cursor.arg_err());
                        };
                        (result.prefix, result.prefix_len) = parse_prefix(cursor, prefix)?;
                    }
                    "translate_all" => result.translate_all = true,
                    "allow_ipv4" => result.allow_ipv4 = true,
                    _ => return Err(cursor.error("unknown dns64 property")),
                }
            }
        }
        Ok(result)
    }
}

fn parse_prefix(cursor: &Cursor<'_>, value: &str) -> Result<([u8; 16], u8), Error> {
    let (ip, len) = value
        .split_once('/')
        .ok_or_else(|| cursor.error("invalid dns64 prefix"))?;
    let ip: Ipv6Addr = ip
        .parse()
        .map_err(|_| cursor.error("invalid dns64 prefix"))?;
    let len: u8 = len
        .parse()
        .map_err(|_| cursor.error("invalid dns64 prefix"))?;
    // RFC 6052 §2.2: only these six prefix lengths are defined.
    if !matches!(len, 32 | 40 | 48 | 56 | 64 | 96) {
        return Err(cursor.error("invalid dns64 prefix length"));
    }
    let mut bytes = ip.octets();
    bytes[usize::from(len / 8)..].fill(0);
    Ok((bytes, len))
}

impl Plugin for Dns64 {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        next.run(cx).await
    }
}
