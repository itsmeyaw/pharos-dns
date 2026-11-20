//! DNS over gRPC wire rules shared by the `grpc://` Listener and gRPC Upstream clients.
//!
//! CoreDNS `pb/dns.proto` is `service DnsService { rpc Query(DnsPacket) returns (DnsPacket) }` with
//! `message DnsPacket { bytes msg = 1 }`. The one-field protobuf and the gRPC length-prefixed framing
//! are small enough to write by hand, so neither tonic nor prost is needed. The module knows HTTP
//! only through the header values it parses; the connection handling lives with each user.

use std::{borrow::Cow, time::Duration};

use bytes::Buf;

/// `coredns.dns.DnsService/Query`, from CoreDNS v1.15.0 `pb/dns.proto`.
pub const PATH: &str = "/coredns.dns.DnsService/Query";
/// gRPC over HTTP/2 PROTOCOL-HTTP2 "Content-Type": the unary call's request and Response type.
pub const CONTENT_TYPE: &str = "application/grpc";
/// RFC 7301 §3.1: gRPC runs on HTTP/2 only, as CoreDNS v1.15.0 `NewServergRPC` offers.
pub const ALPN: &[&[u8]] = &[b"h2"];
/// CoreDNS v1.15.0 core/dnsserver `DefaultGRPCMaxStreams`.
pub const DEFAULT_MAX_STREAMS: u32 = 256;
/// CoreDNS v1.15.0 core/dnsserver `DefaultGRPCMaxConnections`.
pub const DEFAULT_MAX_CONNECTIONS: usize = 200;
/// RFC 1035 §4.2.2: a DNS Message over a stream is at most 65535 octets; CoreDNS `maxDNSMessageBytes`.
pub const MAX_MESSAGE_LEN: usize = 65535;
/// CoreDNS v1.15.0 core/dnsserver `maxProtobufPayloadBytes`: one tag octet and a three-octet length.
pub const MAX_PAYLOAD_LEN: usize = MAX_MESSAGE_LEN + 4;
/// PROTOCOL-HTTP2 "Length-Prefixed-Message": one compression flag octet and a four-octet length.
pub const HEADER_LEN: usize = 5;

/// PROTOCOL-HTTP2 "Status codes and their use in gRPC".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Code {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl Code {
    /// Parse a `grpc-status` value; PROTOCOL-HTTP2 says an unrecognised number is Unknown.
    #[must_use]
    pub fn from_header(value: &[u8]) -> Self {
        // PROTOCOL-HTTP2: "Status" is a decimal number without leading zeros.
        match std::str::from_utf8(value)
            .ok()
            .and_then(|text| text.parse::<u8>().ok())
        {
            Some(0) => Self::Ok,
            Some(1) => Self::Cancelled,
            Some(3) => Self::InvalidArgument,
            Some(4) => Self::DeadlineExceeded,
            Some(5) => Self::NotFound,
            Some(6) => Self::AlreadyExists,
            Some(7) => Self::PermissionDenied,
            Some(8) => Self::ResourceExhausted,
            Some(9) => Self::FailedPrecondition,
            Some(10) => Self::Aborted,
            Some(11) => Self::OutOfRange,
            Some(12) => Self::Unimplemented,
            Some(13) => Self::Internal,
            Some(14) => Self::Unavailable,
            Some(15) => Self::DataLoss,
            Some(16) => Self::Unauthenticated,
            _ => Self::Unknown,
        }
    }
}

/// A non-OK call outcome: the `grpc-status` code and its `grpc-message`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    pub code: Code,
    pub message: Cow<'static, str>,
}

impl Status {
    #[must_use]
    pub fn new(code: Code, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Percent-encode a `grpc-message` value.
// PROTOCOL-HTTP2 "Status-Message": every octet outside %x20-24, %x26-7E is encoded as %XX.
#[must_use]
pub fn escape_message(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    for &octet in message.as_bytes() {
        if (0x20..=0x7e).contains(&octet) && octet != b'%' {
            out.push(char::from(octet));
        } else {
            out.push_str(&format!("%{octet:02X}"));
        }
    }
    out
}

/// Decode a `grpc-message` value; an invalid escape is kept as written.
// PROTOCOL-HTTP2 "Status-Message": decoders must not fail on an invalid escape sequence.
#[must_use]
pub fn unescape_message(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let decoded = (bytes[index] == b'%')
            .then(|| bytes.get(index + 1..index + 3))
            .flatten()
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match decoded {
            Some(octet) => {
                out.push(octet);
                index += 3;
            }
            None => {
                out.push(bytes[index]);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse a `grpc-timeout` value.
// PROTOCOL-HTTP2 "Timeout": at most eight ASCII digits and a unit of H, M, S, m, u or n.
#[must_use]
pub fn parse_timeout(value: &str) -> Option<Duration> {
    let (digits, unit) = value.split_at(value.len().checked_sub(1)?);
    if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|octet| octet.is_ascii_digit())
    {
        return None;
    }
    let amount: u64 = digits.parse().ok()?;
    Some(match unit {
        "H" => Duration::from_secs(amount * 3600),
        "M" => Duration::from_secs(amount * 60),
        "S" => Duration::from_secs(amount),
        "m" => Duration::from_millis(amount),
        "u" => Duration::from_micros(amount),
        "n" => Duration::from_nanos(amount),
        _ => return None,
    })
}

/// The five-octet gRPC header and the protobuf tag and length that precede a DNS Message.
///
/// As a [`Buf`] it reads those octets, so `prefix.chain(message)` is a whole gRPC message with no copy.
#[derive(Clone, Debug)]
pub struct FramePrefix {
    octets: [u8; HEADER_LEN + 1 + 5],
    len: u8,
    position: u8,
}

impl FramePrefix {
    /// The prefix of an uncompressed message carrying a DNS Message of `message_len` octets.
    #[must_use]
    pub fn new(message_len: usize) -> Self {
        let message_len = u32::try_from(message_len).unwrap_or(u32::MAX);
        let mut octets = [0; HEADER_LEN + 1 + 5];
        // Protobuf encoding "Length-delimited": field 1, wire type 2, then a base-128 varint length.
        let mut varint = [0; 5];
        let mut count = 0;
        let mut rest = message_len;
        loop {
            let low = (rest & 0x7f) as u8;
            rest >>= 7;
            varint[count] = if rest == 0 { low } else { low | 0x80 };
            count += 1;
            if rest == 0 {
                break;
            }
        }
        // proto3: a zero-length bytes field is the default value and is not encoded.
        let payload = if message_len == 0 { 0 } else { 1 + count };
        // PROTOCOL-HTTP2 "Length-Prefixed-Message": compression flag 0, then the big-endian length.
        let framed = payload as u32 + message_len;
        octets[1..HEADER_LEN].copy_from_slice(&framed.to_be_bytes());
        if message_len != 0 {
            octets[HEADER_LEN] = 0x0a;
            octets[HEADER_LEN + 1..HEADER_LEN + 1 + count].copy_from_slice(&varint[..count]);
        }
        Self {
            octets,
            len: (HEADER_LEN + payload) as u8,
            position: 0,
        }
    }
}

impl Buf for FramePrefix {
    fn remaining(&self) -> usize {
        usize::from(self.len - self.position)
    }
    fn chunk(&self) -> &[u8] {
        &self.octets[usize::from(self.position)..usize::from(self.len)]
    }
    fn advance(&mut self, count: usize) {
        assert!(count <= self.remaining(), "advance past the prefix");
        self.position += count as u8;
    }
}

/// The five-octet header of a length-prefixed message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    /// Whether the payload is compressed with the `grpc-encoding` algorithm.
    pub compressed: bool,
    /// Payload length in octets, not counting this header.
    pub len: usize,
}

/// Read the header at the start of `buffer`, or `None` while fewer than five octets have arrived.
#[must_use]
pub fn parse_header(buffer: &[u8]) -> Option<Result<Header, Status>> {
    let header = buffer.get(..HEADER_LEN)?;
    // PROTOCOL-HTTP2 "Compressed-Flag": 0 or 1; anything else is a protocol error.
    let compressed = match header[0] {
        0 => false,
        1 => true,
        flag => {
            return Some(Err(Status::new(
                Code::Internal,
                format!("grpc: received message with invalid compression flag {flag} (not 0 or 1)"),
            )));
        }
    };
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    Some(Ok(Header {
        compressed,
        len: len as usize,
    }))
}

/// The DNS Message inside a `DnsPacket` payload.
// Protobuf encoding: fields may repeat, the last one of a singular field wins and unknown fields are skipped.
pub fn decode_packet(payload: &[u8]) -> Result<&[u8], &'static str> {
    let mut rest = payload;
    let mut message: &[u8] = &[];
    while !rest.is_empty() {
        let (field, wire_type) = tag(&mut rest)?;
        if wire_type == 2 {
            let value = length_delimited(&mut rest)?;
            // Protobuf encoding: a mismatched wire type for a known field is an unknown field.
            if field == 1 {
                message = value;
            }
        } else {
            skip_value(&mut rest, field, wire_type, 0)?;
        }
    }
    Ok(message)
}

/// Protobuf encoding "Message Structure": a tag is a varint of `field << 3 | wire type`.
fn tag(rest: &mut &[u8]) -> Result<(u64, u64), &'static str> {
    let tag = varint(rest)?;
    let field = tag >> 3;
    // Protobuf encoding "Field numbers": 1 to 2^29 - 1.
    if field == 0 || field > MAX_FIELD_NUMBER {
        return Err("invalid field number");
    }
    Ok((field, tag & 7))
}

fn length_delimited<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8], &'static str> {
    let len = usize::try_from(varint(rest)?).map_err(|_| "truncated message")?;
    let value = rest.get(..len).ok_or("truncated message")?;
    *rest = &rest[len..];
    Ok(value)
}

/// Skip an unknown field's value whose tag was just read.
fn skip_value(
    rest: &mut &[u8],
    field: u64,
    wire_type: u64,
    depth: usize,
) -> Result<(), &'static str> {
    match wire_type {
        0 => {
            varint(rest)?;
        }
        1 => skip(rest, 8)?,
        2 => {
            length_delimited(rest)?;
        }
        // Protobuf encoding "Groups" (deprecated): a start-group tag to the end-group tag of the same field.
        3 => {
            // shortcut: protobuf-go allows 10000 nested groups, 100 here keeps the stack small; raise on demand.
            if depth >= MAX_GROUP_DEPTH {
                return Err("group nesting too deep");
            }
            loop {
                let (inner, inner_type) = tag(rest)?;
                if inner_type == 4 {
                    return if inner == field {
                        Ok(())
                    } else {
                        Err("mismatched end group")
                    };
                }
                skip_value(rest, inner, inner_type, depth + 1)?;
            }
        }
        5 => skip(rest, 4)?,
        _ => return Err("unsupported wire type"),
    }
    Ok(())
}

fn varint(rest: &mut &[u8]) -> Result<u64, &'static str> {
    let mut value = 0u64;
    // Protobuf encoding "Base 128 Varints": at most ten octets, least significant group first.
    for (index, &octet) in rest.iter().take(10).enumerate() {
        // Protobuf encoding: the tenth octet holds bit 63 only; larger values overflow 64 bits.
        if index == 9 && octet > 1 {
            return Err("varint overflow");
        }
        value |= u64::from(octet & 0x7f) << (7 * index);
        if octet & 0x80 == 0 {
            *rest = &rest[index + 1..];
            return Ok(value);
        }
    }
    Err("truncated varint")
}

fn skip(rest: &mut &[u8], count: usize) -> Result<(), &'static str> {
    *rest = rest.get(count..).ok_or("truncated message")?;
    Ok(())
}

const MAX_FIELD_NUMBER: u64 = (1 << 29) - 1;
const MAX_GROUP_DEPTH: usize = 100;

#[cfg(test)]
mod tests {
    use super::*;

    fn flatten(mut buf: impl Buf) -> Vec<u8> {
        let mut out = Vec::new();
        while buf.has_remaining() {
            let chunk = buf.chunk();
            out.extend_from_slice(chunk);
            let count = chunk.len();
            buf.advance(count);
        }
        out
    }

    #[test]
    fn prefix_frames_a_message_as_one_field_protobuf() {
        let message = [1, 2, 3];
        let frame = flatten(FramePrefix::new(3).chain(&message[..]));
        // flag 0, length 5, tag 0x0a, length 3, message.
        assert_eq!(frame, [0, 0, 0, 0, 5, 0x0a, 3, 1, 2, 3]);
    }

    #[test]
    fn prefix_uses_a_multi_octet_varint_for_a_maximum_size_message() {
        let prefix = flatten(FramePrefix::new(MAX_MESSAGE_LEN));
        // 65535 = 0xff 0xff 0x03 as a varint; the gRPC length is 1 + 3 + 65535.
        assert_eq!(prefix, [0, 0, 1, 0, 3, 0x0a, 0xff, 0xff, 0x03]);
    }

    #[test]
    fn prefix_omits_the_default_empty_field() {
        assert_eq!(flatten(FramePrefix::new(0)), [0, 0, 0, 0, 0]);
    }

    #[test]
    fn packet_roundtrips_through_the_prefix() {
        let message: Vec<u8> = (0..=255).cycle().take(300).collect();
        let frame = flatten(FramePrefix::new(message.len()).chain(&message[..]));
        let header = parse_header(&frame).unwrap().unwrap();
        assert_eq!(header.len, frame.len() - HEADER_LEN);
        assert_eq!(decode_packet(&frame[HEADER_LEN..]).unwrap(), message);
    }

    #[test]
    fn header_reports_incomplete_flag_and_length() {
        assert_eq!(parse_header(&[0, 0, 0, 0]), None);
        assert_eq!(
            parse_header(&[1, 0, 0, 1, 2]),
            Some(Ok(Header {
                compressed: true,
                len: 258
            }))
        );
        let invalid = parse_header(&[2, 0, 0, 0, 0]).unwrap().unwrap_err();
        assert_eq!(invalid.code, Code::Internal);
    }

    // Protobuf encoding: the last occurrence of a singular field wins; unknown fields are skipped.
    #[test]
    fn decode_takes_the_last_field_one_and_skips_unknown_fields() {
        let payload = [
            0x08, 0x96, 0x01, // field 1 as a varint is an unknown field
            0x0a, 0x01, 0xaa, // field 1: [0xaa]
            0x15, 1, 2, 3, 4, // field 2, fixed32
            0x19, 1, 2, 3, 4, 5, 6, 7, 8, // field 3, fixed64
            0x22, 0x02, 9, 9, // field 4, length-delimited
            0x0a, 0x02, 0xbb, 0xcc, // field 1: [0xbb, 0xcc]
        ];
        assert_eq!(decode_packet(&payload).unwrap(), [0xbb, 0xcc]);
        assert_eq!(decode_packet(&[]).unwrap(), &[] as &[u8]);
    }

    // Protobuf encoding "Groups": a well-formed unknown group, nested or not, is skipped.
    #[test]
    fn decode_skips_unknown_groups() {
        let payload = [
            0x1b, 0x08, 0x01, 0x23, 0x24,
            0x1c, // field 3 group holding a nested field 4 group
            0x0a, 0x01, 0xaa, // field 1
        ];
        assert_eq!(decode_packet(&payload).unwrap(), [0xaa]);
    }

    #[test]
    fn decode_rejects_malformed_protobuf() {
        for payload in [
            &[0x0a][..],         // no length
            &[0x0a, 0x05, 1, 2], // length past the end
            &[0x0a, 0x80],       // unterminated varint
            &[0x00, 0x01],       // field number zero
            &[0x0b],             // start group, never closed
            &[0x1b, 0x24],       // group of field 3 closed by field 4
            &[0x24],             // end group with no start
            &[
                0x0a, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02, 0x0a, 0x01, 0xaa,
            ], // varint over 64 bits
            &[0xf8, 0xff, 0xff, 0xff, 0x1f, 0x00], // field number 2^29
            &[0x15, 1, 2],       // short fixed32
            &[0x19, 1, 2, 3],    // short fixed64
            &[
                0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
            ], // huge length
        ] {
            assert!(decode_packet(payload).is_err(), "{payload:02x?}");
        }
    }

    #[test]
    fn status_numbers_and_unknown_numbers() {
        assert_eq!(Code::from_header(b"0"), Code::Ok);
        assert_eq!(Code::from_header(b"12"), Code::Unimplemented);
        assert_eq!(Code::from_header(b"13"), Code::Internal);
        assert_eq!(Code::from_header(b"99"), Code::Unknown);
        assert_eq!(Code::from_header(b"x"), Code::Unknown);
        assert_eq!(Code::from_header(b""), Code::Unknown);
    }

    #[test]
    fn message_escaping_roundtrips() {
        assert_eq!(escape_message("a b%c"), "a b%25c");
        assert_eq!(escape_message("é\n"), "%C3%A9%0A");
        assert_eq!(unescape_message("a b%25c %C3%A9%0A"), "a b%c é\n");
        assert_eq!(unescape_message("100%"), "100%");
        assert_eq!(unescape_message("%zz"), "%zz");
    }

    #[test]
    fn timeouts_parse_to_durations() {
        assert_eq!(parse_timeout("1S"), Some(Duration::from_secs(1)));
        assert_eq!(parse_timeout("250m"), Some(Duration::from_millis(250)));
        assert_eq!(parse_timeout("2H"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_timeout("3M"), Some(Duration::from_secs(180)));
        assert_eq!(parse_timeout("7u"), Some(Duration::from_micros(7)));
        assert_eq!(parse_timeout("9n"), Some(Duration::from_nanos(9)));
        assert_eq!(
            parse_timeout("99999999S"),
            Some(Duration::from_secs(99_999_999))
        );
        for invalid in ["", "S", "1", "123456789S", "1x", "-1S", "1.5S", "1 S"] {
            assert_eq!(parse_timeout(invalid), None, "{invalid:?}");
        }
    }
}
