//! PROXY protocol v1 and v2 header parser.
//!
//! The grammar follows the HAProxy PROXY protocol specification and the limits of
//! `github.com/pires/go-proxyproto` v0.15.0, the library CoreDNS v1.15.0 uses.

use std::{
    fmt::{self, Write as _},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

// PROXY protocol §2.1: a v1 line, CRLF included, is at most 107 octets.
const MAX_V1: usize = 107;
// PROXY protocol §2.2: the v2 signature that opens every v2 header.
const V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
const V1_SIGNATURE: &[u8; 5] = b"PROXY";
// go-proxyproto MaxV2HeaderSize: a v2 length field above 4096 is rejected to bound memory.
pub const MAX_V2_PAYLOAD: usize = 4096;
// PROXY protocol §2.2: the fixed v2 prefix is signature, version/command, family, length.
const V2_PREFIX: usize = 16;
// PROXY protocol §2.2: PP2_TYPE_NOOP is padding.
const PP2_TYPE_NOOP: u8 = 0x04;

/// Whether the sender opened the connection itself (`Local`) or relays a client (`Proxy`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Local,
    Proxy,
}

/// A parsed PROXY header borrowing its TLV vector from the input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header<'a> {
    pub version: u8,
    pub command: Command,
    /// The transport protocol field names datagrams (UDP) rather than a stream.
    pub datagram: bool,
    /// The relayed client address; `None` for `Local`.
    pub source: Option<SocketAddr>,
    /// The raw v2 TLV vector; empty for v1 and `Local`.
    pub tlvs: &'a [u8],
    /// Octets of the input that the header occupies.
    pub length: usize,
}

/// Outcome of parsing the start of a byte stream or datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Parse<'a> {
    Header(Header<'a>),
    /// The input does not open with a PROXY signature.
    NotProxy,
    /// The input is a valid prefix; more octets are needed to decide.
    Incomplete,
}

/// Why an input that opens with a PROXY signature is not a valid header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error(pub &'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid PROXY protocol header: {}", self.0)
    }
}

impl std::error::Error for Error {}

/// Parse the PROXY header at the start of `input`.
///
/// # Errors
/// Returns an error when `input` opens with a PROXY signature but is malformed.
pub fn parse(input: &[u8]) -> Result<Parse<'_>, Error> {
    let Some(&first) = input.first() else {
        return Ok(Parse::Incomplete);
    };
    // PROXY protocol §2: a receiver tells the versions apart by their first octets.
    let (signature, version): (&[u8], u8) = match first {
        b'P' => (V1_SIGNATURE, 1),
        0x0D => (&V2_SIGNATURE, 2),
        _ => return Ok(Parse::NotProxy),
    };
    let seen = input.len().min(signature.len());
    if input[..seen] != signature[..seen] {
        return Ok(Parse::NotProxy);
    }
    if seen < signature.len() {
        return Ok(Parse::Incomplete);
    }
    if version == 1 {
        parse_v1(input)
    } else {
        parse_v2(input)
    }
}

fn parse_v1(input: &[u8]) -> Result<Parse<'_>, Error> {
    // PROXY protocol §2.1: the line ends at the first LF, at most 107 octets in.
    let window = &input[..input.len().min(MAX_V1)];
    let Some(lf) = window.iter().position(|&byte| byte == b'\n') else {
        return if input.len() >= MAX_V1 {
            Err(Error("v1 header longer than 107 octets"))
        } else {
            Ok(Parse::Incomplete)
        };
    };
    // PROXY protocol §2.1: the line is terminated by CRLF, not a bare LF.
    if lf == 0 || input[lf - 1] != b'\r' {
        return Err(Error("v1 header does not end with CRLF"));
    }
    let line = std::str::from_utf8(&input[..lf - 1]).map_err(|_| Error("v1 header is not text"))?;
    let length = lf + 1;
    // PROXY protocol §2.1: fields are separated by exactly one space.
    let mut fields = line.split(' ');
    if fields.next() != Some("PROXY") {
        return Err(Error("v1 header does not start with PROXY "));
    }
    let family = fields.next().ok_or(Error("v1 header lacks a protocol"))?;
    let source = match family {
        // PROXY protocol §2.1: UNKNOWN makes the receiver ignore the rest of the line.
        "UNKNOWN" => {
            return Ok(Parse::Header(Header {
                version: 1,
                command: Command::Local,
                datagram: false,
                source: None,
                tlvs: &[],
                length,
            }));
        }
        "TCP4" => v1_endpoints(&mut fields, |text| {
            text.parse::<Ipv4Addr>().map(IpAddr::V4).ok()
        })?,
        "TCP6" => v1_endpoints(&mut fields, |text| {
            text.parse::<Ipv6Addr>().map(IpAddr::V6).ok()
        })?,
        _ => return Err(Error("v1 header names an unknown protocol")),
    };
    Ok(Parse::Header(Header {
        version: 1,
        command: Command::Proxy,
        datagram: false,
        source: Some(source),
        tlvs: &[],
        length,
    }))
}

// PROXY protocol §2.1: `<source> <destination> <source port> <destination port>` end the line.
fn v1_endpoints<'a>(
    fields: &mut impl Iterator<Item = &'a str>,
    address: impl Fn(&str) -> Option<IpAddr>,
) -> Result<SocketAddr, Error> {
    let mut next = |what| fields.next().ok_or(Error(what));
    let source = address(next("v1 header lacks a source address")?)
        .ok_or(Error("v1 source address is invalid"))?;
    address(next("v1 header lacks a destination address")?)
        .ok_or(Error("v1 destination address is invalid"))?;
    let source_port = v1_port(next("v1 header lacks a source port")?)?;
    v1_port(next("v1 header lacks a destination port")?)?;
    if fields.next().is_some() {
        return Err(Error("v1 header has trailing fields"));
    }
    Ok(SocketAddr::new(source, source_port))
}

// PROXY protocol §2.1: a port is a decimal number in 0..=65535 without leading zeros.
fn v1_port(text: &str) -> Result<u16, Error> {
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(Error("v1 port is invalid"));
    }
    text.parse().map_err(|_| Error("v1 port is invalid"))
}

fn parse_v2(input: &[u8]) -> Result<Parse<'_>, Error> {
    if input.len() < V2_PREFIX {
        return Ok(Parse::Incomplete);
    }
    // PROXY protocol §2.2: the high nibble is version 2, the low nibble LOCAL (0) or PROXY (1).
    let command = match input[12] {
        0x20 => Command::Local,
        0x21 => Command::Proxy,
        _ => return Err(Error("v2 version or command is unsupported")),
    };
    let family = input[13];
    let length = usize::from(u16::from_be_bytes([input[14], input[15]]));
    if length > MAX_V2_PAYLOAD {
        return Err(Error("v2 length exceeds the accepted maximum"));
    }
    let total = V2_PREFIX + length;
    let datagram = family & 0x0F == 0x02;
    if command == Command::Local {
        // PROXY protocol §2.2: a LOCAL header's family, protocol and address block are ignored; skip the block.
        return Ok(if input.len() < total {
            Parse::Incomplete
        } else {
            Parse::Header(local_v2(datagram, total))
        });
    }
    // PROXY protocol §2.2: only these family/protocol pairs are defined; others must be rejected.
    if !matches!(family, 0x11 | 0x12 | 0x21 | 0x22 | 0x31 | 0x32) {
        return Err(Error(if family == 0x00 {
            "v2 PROXY command with unspecified address family"
        } else {
            "v2 address family or protocol is unsupported"
        }));
    }
    // PROXY protocol §2.2: the address block holds 12, 36 or 216 octets for IPv4, IPv6 or UNIX.
    let address_length = match family >> 4 {
        1 => 12,
        2 => 36,
        _ => 216,
    };
    if length < address_length {
        return Err(Error("v2 length is too short for its address family"));
    }
    if input.len() < total {
        return Ok(Parse::Incomplete);
    }
    let block = &input[V2_PREFIX..total];
    let source = match family >> 4 {
        1 => SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(block[0], block[1], block[2], block[3])),
            u16::from_be_bytes([block[8], block[9]]),
        ),
        2 => {
            let mut octets = [0; 16];
            octets.copy_from_slice(&block[..16]);
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                u16::from_be_bytes([block[32], block[33]]),
            )
        }
        // Pharos has no way to represent a UNIX-domain client, so the header is refused.
        _ => return Err(Error("v2 UNIX address family is unsupported")),
    };
    Ok(Parse::Header(Header {
        version: 2,
        command,
        datagram,
        source: Some(source),
        tlvs: &block[address_length..],
        length: total,
    }))
}

fn local_v2<'a>(datagram: bool, length: usize) -> Header<'a> {
    Header {
        version: 2,
        command: Command::Local,
        datagram,
        source: None,
        tlvs: &[],
        length,
    }
}

/// Hex-encode a v2 TLV vector into `out`, as the `proxyproto/tlv` Metadata value.
///
/// Like CoreDNS v1.15.0 `rawTLVs`, the vector is split and joined again, so a NOOP
/// record keeps its type but loses its padding. Returns whether `out` holds a value:
/// an empty or truncated vector yields none.
pub fn tlv_hex(tlvs: &[u8], out: &mut String) -> bool {
    out.clear();
    let mut rest = tlvs;
    while !rest.is_empty() {
        // PROXY protocol §2.2: a TLV is a type octet, a two-octet length and the value.
        let [kind, high, low, tail @ ..] = rest else {
            out.clear();
            return false;
        };
        let length = usize::from(u16::from_be_bytes([*high, *low]));
        if tail.len() < length {
            out.clear();
            return false;
        }
        let (value, after) = tail.split_at(length);
        let value = if *kind == PP2_TYPE_NOOP {
            &[][..]
        } else {
            value
        };
        let _ = write!(out, "{kind:02x}{:04x}", value.len());
        for byte in value {
            let _ = write!(out, "{byte:02x}");
        }
        rest = after;
    }
    !out.is_empty()
}

#[cfg(test)]
mod tests;
