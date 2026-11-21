//! dnstap protobuf encoding: `Dnstap` wrapping a `Message`, written into a caller-provided buffer.
//!
//! The schema is `dnstap.proto` (<https://github.com/dnstap/dnstap.pb>). `query_zone` (field 11)
//! is never set by CoreDNS v1.15.0, so it is not encoded.

use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
pub(crate) mod decode;
#[cfg(test)]
mod tests;

/// dnstap.proto `Message.Type`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageType {
    AuthQuery = 1,
    AuthResponse = 2,
    ResolverQuery = 3,
    ResolverResponse = 4,
    ClientQuery = 5,
    ClientResponse = 6,
    ForwarderQuery = 7,
    ForwarderResponse = 8,
    StubQuery = 9,
    StubResponse = 10,
    ToolQuery = 11,
    ToolResponse = 12,
    UpdateQuery = 13,
    UpdateResponse = 14,
}

/// dnstap.proto `SocketFamily`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketFamily {
    Inet = 1,
    Inet6 = 2,
}

/// dnstap.proto `SocketProtocol`. CoreDNS v1.15.0 only emits `Udp` and `Tcp`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketProtocol {
    Udp = 1,
    Tcp = 2,
    Dot = 3,
    Doh = 4,
}

/// The `Dnstap` envelope fields that do not change per message.
#[derive(Clone, Copy, Debug)]
pub struct Header<'a> {
    pub identity: &'a [u8],
    pub version: &'a [u8],
    /// Encoded whenever set, even if empty, as CoreDNS sets `Extra` whenever `extra` is configured.
    pub extra: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug)]
struct Peer {
    octets: [u8; 16],
    len: u8,
    port: u16,
}

impl Peer {
    fn address(&self) -> &[u8] {
        &self.octets[..usize::from(self.len)]
    }
}

#[derive(Clone, Copy, Debug)]
struct Timestamp {
    sec: u64,
    nsec: u32,
}

impl Timestamp {
    fn new(time: SystemTime) -> Self {
        // CoreDNS v1.15.0 msg.go SetQueryTime casts Unix() to uint64; a pre-epoch clock saturates to zero instead of wrapping.
        let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
        Self {
            sec: since.as_secs(),
            nsec: since.subsec_nanos(),
        }
    }
}

/// One dnstap `Message`. Setters follow CoreDNS v1.15.0 `plugin/dnstap/msg/msg.go`.
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    kind: MessageType,
    family: Option<SocketFamily>,
    protocol: Option<SocketProtocol>,
    query: Option<Peer>,
    response: Option<Peer>,
    query_time: Option<Timestamp>,
    response_time: Option<Timestamp>,
    query_message: Option<&'a [u8]>,
    response_message: Option<&'a [u8]>,
}

// dnstap.proto Dnstap: field 14 `message`, field 15 `type` (always MESSAGE = 1).
const DNSTAP_MESSAGE_FIELD: u8 = 14;
const DNSTAP_TYPE_MESSAGE: u8 = 1;

impl<'a> Message<'a> {
    #[must_use]
    pub fn new(kind: MessageType) -> Self {
        Self {
            kind,
            family: None,
            protocol: None,
            query: None,
            response: None,
            query_time: None,
            response_time: None,
            query_message: None,
            response_message: None,
        }
    }

    /// Sets the query address and port, plus `SocketFamily` and `SocketProtocol`.
    pub fn set_query_address(&mut self, addr: SocketAddr, protocol: SocketProtocol) {
        let (family, peer) = peer(addr);
        self.family = Some(family);
        self.protocol = Some(protocol);
        self.query = Some(peer);
    }

    /// Sets the response address and port, plus `SocketFamily` and `SocketProtocol`.
    /// Like CoreDNS, the last of the two setters decides family and protocol.
    pub fn set_response_address(&mut self, addr: SocketAddr, protocol: SocketProtocol) {
        let (family, peer) = peer(addr);
        self.family = Some(family);
        self.protocol = Some(protocol);
        self.response = Some(peer);
    }

    pub fn set_query_time(&mut self, time: SystemTime) {
        self.query_time = Some(Timestamp::new(time));
    }

    pub fn set_response_time(&mut self, time: SystemTime) {
        self.response_time = Some(Timestamp::new(time));
    }

    /// The raw wire-format query (`full` mode).
    pub fn set_query_message(&mut self, wire: &'a [u8]) {
        self.query_message = Some(wire);
    }

    /// The raw wire-format response (`full` mode).
    pub fn set_response_message(&mut self, wire: &'a [u8]) {
        self.response_message = Some(wire);
    }

    /// Appends the encoded `Dnstap` envelope and this `Message` to `buf`; allocates only if `buf` must grow.
    pub fn encode(&self, header: &Header<'_>, buf: &mut Vec<u8>) {
        let start = buf.len();
        let body = self.body_len();
        let total = bytes_len(header.identity.len())
            + bytes_len(header.version.len())
            + header.extra.map_or(0, |extra| bytes_len(extra.len()))
            + bytes_len(body)
            + 2;
        buf.reserve(total);
        // dnstap.proto Dnstap: fields in ascending number order, as Go's protobuf marshals them.
        put_bytes(buf, 1, header.identity);
        put_bytes(buf, 2, header.version);
        if let Some(extra) = header.extra {
            put_bytes(buf, 3, extra);
        }
        put_tag(buf, DNSTAP_MESSAGE_FIELD, WIRE_LEN);
        put_varint(buf, body as u64);
        self.encode_body(buf);
        put_tag(buf, 15, WIRE_VARINT);
        buf.push(DNSTAP_TYPE_MESSAGE);
        debug_assert_eq!(buf.len() - start, total);
    }

    fn body_len(&self) -> usize {
        // Protobuf: tag byte plus value; every Message field number is below 16, so each tag is one byte.
        let mut len = 1 + varint_len(self.kind as u64);
        len += self
            .family
            .map_or(0, |family| 1 + varint_len(family as u64));
        len += self
            .protocol
            .map_or(0, |protocol| 1 + varint_len(protocol as u64));
        for peer in [&self.query, &self.response].into_iter().flatten() {
            len += bytes_len(peer.address().len()) + 1 + varint_len(u64::from(peer.port));
        }
        for time in [&self.query_time, &self.response_time]
            .into_iter()
            .flatten()
        {
            len += 1 + varint_len(time.sec) + 1 + 4;
        }
        for raw in [self.query_message, self.response_message]
            .into_iter()
            .flatten()
        {
            len += bytes_len(raw.len());
        }
        len
    }

    fn encode_body(&self, buf: &mut Vec<u8>) {
        // dnstap.proto Message: fields in ascending number order.
        put_varint_field(buf, 1, self.kind as u64);
        if let Some(family) = self.family {
            put_varint_field(buf, 2, family as u64);
        }
        if let Some(protocol) = self.protocol {
            put_varint_field(buf, 3, protocol as u64);
        }
        if let Some(peer) = &self.query {
            put_bytes(buf, 4, peer.address());
        }
        if let Some(peer) = &self.response {
            put_bytes(buf, 5, peer.address());
        }
        if let Some(peer) = &self.query {
            put_varint_field(buf, 6, u64::from(peer.port));
        }
        if let Some(peer) = &self.response {
            put_varint_field(buf, 7, u64::from(peer.port));
        }
        if let Some(time) = &self.query_time {
            put_varint_field(buf, 8, time.sec);
            put_fixed32_field(buf, 9, time.nsec);
        }
        if let Some(raw) = self.query_message {
            put_bytes(buf, 10, raw);
        }
        if let Some(time) = &self.response_time {
            put_varint_field(buf, 12, time.sec);
            put_fixed32_field(buf, 13, time.nsec);
        }
        if let Some(raw) = self.response_message {
            put_bytes(buf, 14, raw);
        }
    }
}

// CoreDNS v1.15.0 plugin/dnstap/msg/msg.go socketFamilyAndAddress: IPv4, including IPv4-mapped IPv6 (`::ffff:a.b.c.d`), is a 4-octet INET address; anything else is a 16-octet INET6 address.
fn peer(addr: SocketAddr) -> (SocketFamily, Peer) {
    let mut octets = [0; 16];
    let (family, len) = match addr.ip().to_canonical() {
        IpAddr::V4(ip) => {
            octets[..4].copy_from_slice(&ip.octets());
            (SocketFamily::Inet, 4)
        }
        IpAddr::V6(ip) => {
            octets = ip.octets();
            (SocketFamily::Inet6, 16)
        }
    };
    (
        family,
        Peer {
            octets,
            len,
            port: addr.port(),
        },
    )
}

const WIRE_VARINT: u8 = 0;
const WIRE_LEN: u8 = 2;
const WIRE_FIXED32: u8 = 5;

// Protobuf encoding: key = (field_number << 3) | wire_type; all dnstap field numbers fit one byte.
fn put_tag(buf: &mut Vec<u8>, field: u8, wire: u8) {
    buf.push(field << 3 | wire);
}

// Protobuf encoding: base-128 varint, least significant group first.
fn put_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push(value as u8 | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

fn varint_len(value: u64) -> usize {
    (64 - (value | 1).leading_zeros() as usize).div_ceil(7)
}

fn put_varint_field(buf: &mut Vec<u8>, field: u8, value: u64) {
    put_tag(buf, field, WIRE_VARINT);
    put_varint(buf, value);
}

// dnstap.proto: `query_time_nsec` and `response_time_nsec` are `fixed32`, little-endian.
fn put_fixed32_field(buf: &mut Vec<u8>, field: u8, value: u32) {
    put_tag(buf, field, WIRE_FIXED32);
    buf.extend_from_slice(&value.to_le_bytes());
}

// Protobuf encoding: length-delimited field = key, varint length, bytes.
fn put_bytes(buf: &mut Vec<u8>, field: u8, bytes: &[u8]) {
    put_tag(buf, field, WIRE_LEN);
    put_varint(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn bytes_len(len: usize) -> usize {
    1 + varint_len(len as u64) + len
}
