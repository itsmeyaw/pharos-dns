//! The protobuf messages of the etcd v3 API that the Plugin uses, written by hand.
//!
//! Field numbers are from etcd `api/etcdserverpb/rpc.proto` and `api/mvccpb/kv.proto`. Decoding
//! skips fields it does not know, checks every length against what is left of the buffer, and
//! allocates only for what the buffer holds, so it is safe on any input.

use std::fmt;

/// A message that does not decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeError(pub &'static str);

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid protobuf message: {}", self.0)
    }
}

impl std::error::Error for DecodeError {}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    // Protobuf encoding "Base 128 Varints": seven bits at a time, least significant group first.
    loop {
        let low = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

// proto3: a field with the default value (zero, empty) is not written.
fn put_int(out: &mut Vec<u8>, field: u32, value: i64) {
    if value != 0 {
        put_varint(out, u64::from(field) << 3);
        put_varint(out, value as u64);
    }
}

fn put_bool(out: &mut Vec<u8>, field: u32, value: bool) {
    put_int(out, field, i64::from(value));
}

fn put_bytes(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    if !value.is_empty() {
        put_message(out, field, value);
    }
}

// Protobuf encoding "Length-delimited": a nested message is present even when it is empty.
fn put_message(out: &mut Vec<u8>, field: u32, value: &[u8]) {
    put_varint(out, (u64::from(field) << 3) | 2);
    put_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

/// etcd v3 rpc.proto `RangeRequest`: `key` = 1, `range_end` = 2, `count_only` = 9.
pub fn range_request(key: &[u8], range_end: &[u8], count_only: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(key.len() + range_end.len() + 8);
    put_bytes(&mut out, 1, key);
    put_bytes(&mut out, 2, range_end);
    put_bool(&mut out, 9, count_only);
    out
}

/// etcd v3 rpc.proto `LeaseTimeToLiveRequest`: `ID` = 1.
pub fn lease_time_to_live_request(id: i64) -> Vec<u8> {
    let mut out = Vec::new();
    put_int(&mut out, 1, id);
    out
}

/// etcd v3 rpc.proto `AuthenticateRequest`: `name` = 1, `password` = 2.
pub fn authenticate_request(name: &str, password: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + password.len() + 4);
    put_bytes(&mut out, 1, name.as_bytes());
    put_bytes(&mut out, 2, password.as_bytes());
    out
}

/// etcd v3 rpc.proto `WatchRequest` with `create_request` = 1 of `WatchCreateRequest`: `key` = 1,
/// `range_end` = 2. Without `start_revision` the watch starts at the next revision.
pub fn watch_create_request(key: &[u8], range_end: &[u8]) -> Vec<u8> {
    let mut create = Vec::with_capacity(key.len() + range_end.len() + 4);
    put_bytes(&mut create, 1, key);
    put_bytes(&mut create, 2, range_end);
    let mut out = Vec::with_capacity(create.len() + 2);
    put_message(&mut out, 1, &create);
    out
}

enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

/// The fields of one message, in order.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut value = 0_u64;
        for (index, &octet) in self.0.iter().take(10).enumerate() {
            // Protobuf encoding "Base 128 Varints": the tenth octet holds bit 63 only.
            if index == 9 && octet > 1 {
                return Err(DecodeError("varint overflow"));
            }
            value |= u64::from(octet & 0x7f) << (7 * index);
            if octet & 0x80 == 0 {
                self.0 = &self.0[index + 1..];
                return Ok(value);
            }
        }
        Err(DecodeError("truncated varint"))
    }

    fn take(&mut self, len: u64) -> Result<&'a [u8], DecodeError> {
        let len = usize::try_from(len).map_err(|_| DecodeError("truncated message"))?;
        let value = self.0.get(..len).ok_or(DecodeError("truncated message"))?;
        self.0 = &self.0[len..];
        Ok(value)
    }

    fn next_field(&mut self) -> Result<Option<(u32, Value<'a>)>, DecodeError> {
        loop {
            if self.0.is_empty() {
                return Ok(None);
            }
            let tag = self.varint()?;
            let field = tag >> 3;
            // Protobuf encoding "Field numbers": 1 to 2^29 - 1.
            if field == 0 || field >= 1 << 29 {
                return Err(DecodeError("invalid field number"));
            }
            let field = field as u32;
            match tag & 7 {
                0 => return Ok(Some((field, Value::Varint(self.varint()?)))),
                2 => {
                    let len = self.varint()?;
                    return Ok(Some((field, Value::Bytes(self.take(len)?))));
                }
                // Protobuf encoding: unknown fixed-size fields are skipped.
                1 => {
                    self.take(8)?;
                }
                5 => {
                    self.take(4)?;
                }
                // shortcut: groups are deprecated and etcd never sends them, so they are an error; skip them if a server needs it.
                _ => return Err(DecodeError("unsupported wire type")),
            }
        }
    }
}

/// `ResponseHeader.revision` = 3.
fn header_revision(buffer: &[u8]) -> Result<i64, DecodeError> {
    let mut fields = Fields(buffer);
    let mut revision = 0;
    while let Some((field, value)) = fields.next_field()? {
        if let (3, Value::Varint(value)) = (field, value) {
            revision = value as i64;
        }
    }
    Ok(revision)
}

/// etcd v3 api/mvccpb/kv.proto `KeyValue`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KeyValue {
    pub key: Vec<u8>,
    pub create_revision: i64,
    pub mod_revision: i64,
    pub version: i64,
    pub value: Vec<u8>,
    /// The lease the key is attached to; 0 for none.
    pub lease: i64,
}

impl KeyValue {
    fn decode(buffer: &[u8]) -> Result<Self, DecodeError> {
        let mut fields = Fields(buffer);
        let mut kv = Self::default();
        while let Some(field) = fields.next_field()? {
            match field {
                (1, Value::Bytes(value)) => kv.key = value.to_vec(),
                (2, Value::Varint(value)) => kv.create_revision = value as i64,
                (3, Value::Varint(value)) => kv.mod_revision = value as i64,
                (4, Value::Varint(value)) => kv.version = value as i64,
                (5, Value::Bytes(value)) => kv.value = value.to_vec(),
                (6, Value::Varint(value)) => kv.lease = value as i64,
                _ => {}
            }
        }
        Ok(kv)
    }
}

/// etcd v3 rpc.proto `RangeResponse`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RangeResponse {
    /// The revision of the store when the request was applied.
    pub revision: i64,
    pub kvs: Vec<KeyValue>,
    pub more: bool,
    /// The number of keys in the range, whatever `kvs` holds.
    pub count: i64,
}

pub fn range_response(buffer: &[u8]) -> Result<RangeResponse, DecodeError> {
    let mut fields = Fields(buffer);
    let mut response = RangeResponse::default();
    while let Some(field) = fields.next_field()? {
        match field {
            (1, Value::Bytes(value)) => response.revision = header_revision(value)?,
            (2, Value::Bytes(value)) => response.kvs.push(KeyValue::decode(value)?),
            (3, Value::Varint(value)) => response.more = value != 0,
            (4, Value::Varint(value)) => response.count = value as i64,
            _ => {}
        }
    }
    Ok(response)
}

/// etcd v3 rpc.proto `LeaseTimeToLiveResponse`: `ID` = 2, `TTL` = 3, `grantedTTL` = 4.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LeaseTimeToLiveResponse {
    pub id: i64,
    /// Remaining seconds; -1 for a lease that does not exist or has expired.
    pub ttl: i64,
    pub granted_ttl: i64,
}

pub fn lease_time_to_live_response(buffer: &[u8]) -> Result<LeaseTimeToLiveResponse, DecodeError> {
    let mut fields = Fields(buffer);
    let mut response = LeaseTimeToLiveResponse::default();
    while let Some(field) = fields.next_field()? {
        match field {
            (2, Value::Varint(value)) => response.id = value as i64,
            (3, Value::Varint(value)) => response.ttl = value as i64,
            (4, Value::Varint(value)) => response.granted_ttl = value as i64,
            _ => {}
        }
    }
    Ok(response)
}

/// The `token` = 2 of etcd v3 rpc.proto `AuthenticateResponse`.
pub fn authenticate_response(buffer: &[u8]) -> Result<String, DecodeError> {
    let mut fields = Fields(buffer);
    let mut token = &[][..];
    while let Some(field) = fields.next_field()? {
        if let (2, Value::Bytes(value)) = field {
            token = value;
        }
    }
    String::from_utf8(token.to_vec()).map_err(|_| DecodeError("token is not UTF-8"))
}

/// etcd v3 api/mvccpb/kv.proto `Event.EventType`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    Put,
    Delete,
}

/// etcd v3 api/mvccpb/kv.proto `Event`: `type` = 1, `kv` = 2 (`prev_kv` = 3 is not requested).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub kind: EventKind,
    pub kv: KeyValue,
}

impl Event {
    fn decode(buffer: &[u8]) -> Result<Self, DecodeError> {
        let mut fields = Fields(buffer);
        let mut event = Self {
            kind: EventKind::Put,
            kv: KeyValue::default(),
        };
        while let Some(field) = fields.next_field()? {
            match field {
                // Protobuf encoding "Enum": an unknown number is kept as is; one that is not DELETE counts as PUT.
                (1, Value::Varint(1)) => event.kind = EventKind::Delete,
                (2, Value::Bytes(value)) => event.kv = KeyValue::decode(value)?,
                _ => {}
            }
        }
        Ok(event)
    }
}

/// etcd v3 rpc.proto `WatchResponse`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WatchResponse {
    pub revision: i64,
    pub watch_id: i64,
    /// The response acknowledges a create request.
    pub created: bool,
    /// The watcher is gone, by request or because the server dropped it.
    pub canceled: bool,
    /// Not zero when the watcher fell behind a compaction.
    pub compact_revision: i64,
    pub cancel_reason: String,
    pub events: Vec<Event>,
}

pub fn watch_response(buffer: &[u8]) -> Result<WatchResponse, DecodeError> {
    let mut fields = Fields(buffer);
    let mut response = WatchResponse::default();
    while let Some(field) = fields.next_field()? {
        match field {
            (1, Value::Bytes(value)) => response.revision = header_revision(value)?,
            (2, Value::Varint(value)) => response.watch_id = value as i64,
            (3, Value::Varint(value)) => response.created = value != 0,
            (4, Value::Varint(value)) => response.canceled = value != 0,
            (5, Value::Varint(value)) => response.compact_revision = value as i64,
            (6, Value::Bytes(value)) => {
                response.cancel_reason = String::from_utf8_lossy(value).into_owned();
            }
            (11, Value::Bytes(value)) => response.events.push(Event::decode(value)?),
            _ => {}
        }
    }
    Ok(response)
}

#[cfg(test)]
mod tests;
