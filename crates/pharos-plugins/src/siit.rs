//! SIIT address synthesis.

use std::net::{Ipv4Addr, Ipv6Addr};

use pharos_corefile::{Cursor, Error};
use pharos_server::{Context, Next, Outcome, Plugin};

#[derive(Debug)]
pub struct Siit {
    prefix: [u8; 16],
    prefix_len: u8,
    eam: Vec<(Ipv6Addr, Ipv4Addr)>,
}

impl Siit {
    pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Self, Error> {
        let mut result = Self {
            prefix: "64:ff9b::".parse::<Ipv6Addr>().unwrap().octets(),
            prefix_len: 96,
            eam: Vec::new(),
        };
        while cursor.next() {
            if !cursor.remaining_args().is_empty() {
                return Err(cursor.arg_err());
            }
            while cursor.next_block() {
                match cursor.val() {
                    "ipv6_prefix" => {
                        let args = cursor.remaining_args();
                        let value = args.first().ok_or_else(|| cursor.arg_err())?;
                        let (ip, len) = value
                            .split_once('/')
                            .ok_or_else(|| cursor.error("invalid prefix"))?;
                        let ip: Ipv6Addr =
                            ip.parse().map_err(|_| cursor.error("invalid prefix"))?;
                        let len: u8 = len.parse().map_err(|_| cursor.error("invalid prefix"))?;
                        // RFC 6052 §2.2: only six prefix lengths are defined and the u octet is zero.
                        if !matches!(len, 32 | 40 | 48 | 56 | 64 | 96) {
                            return Err(cursor.error("invalid prefix length"));
                        }
                        let mut bytes = ip.octets();
                        bytes[usize::from(len / 8)..].fill(0);
                        if bytes[8] != 0 {
                            return Err(cursor.error("invalid reserved octet"));
                        }
                        result.prefix = bytes;
                        result.prefix_len = len;
                    }
                    "eam" => {
                        let args = cursor.remaining_args();
                        let [v4, v6] = args.as_slice() else {
                            return Err(cursor.arg_err());
                        };
                        let v4 = v4
                            .parse()
                            .map_err(|_| cursor.error("invalid IPv4 address"))?;
                        let v6: Ipv6Addr = v6
                            .parse()
                            .map_err(|_| cursor.error("invalid IPv6 address"))?;
                        if v6.to_ipv4_mapped().is_some() {
                            return Err(cursor.error("invalid IPv6 address"));
                        }
                        result.eam.retain(|(addr, _)| *addr != v6);
                        result.eam.push((v6, v4));
                    }
                    _ => return Err(cursor.error("unknown siit property")),
                }
            }
        }
        Ok(result)
    }
}

impl Plugin for Siit {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        next.run(cx).await
    }
}
