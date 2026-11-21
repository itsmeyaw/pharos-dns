//! Test-only protobuf decoder for `dnstap.proto` `Dnstap` and `Message`.
//! Panics on anything the schema does not allow, so a wrong wire type fails a test.

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct Dnstap {
    pub identity: Option<Vec<u8>>,
    pub version: Option<Vec<u8>>,
    pub extra: Option<Vec<u8>>,
    pub kind: Option<u64>,
    pub message: Option<Message>,
}

#[derive(Debug, Default, Eq, PartialEq)]
pub(crate) struct Message {
    pub kind: Option<u64>,
    pub family: Option<u64>,
    pub protocol: Option<u64>,
    pub query_address: Option<Vec<u8>>,
    pub response_address: Option<Vec<u8>>,
    pub query_port: Option<u64>,
    pub response_port: Option<u64>,
    pub query_time_sec: Option<u64>,
    pub query_time_nsec: Option<u32>,
    pub query_message: Option<Vec<u8>>,
    pub response_time_sec: Option<u64>,
    pub response_time_nsec: Option<u32>,
    pub response_message: Option<Vec<u8>>,
}

enum Value<'a> {
    Varint(u64),
    Fixed32(u32),
    Bytes(&'a [u8]),
}

fn varint(buf: &mut &[u8]) -> u64 {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let (&byte, rest) = buf.split_first().expect("truncated varint");
        *buf = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
    }
    panic!("varint longer than 10 bytes");
}

// Fields must come in ascending number order, as Go's protobuf marshals them.
fn fields(mut buf: &[u8]) -> Vec<(u64, Value<'_>)> {
    let mut out = Vec::new();
    let mut last = 0;
    while !buf.is_empty() {
        let tag = varint(&mut buf);
        let (number, wire) = (tag >> 3, tag & 7);
        assert!(number >= last, "field {number} after {last}");
        last = number;
        let value = match wire {
            0 => Value::Varint(varint(&mut buf)),
            5 => {
                let (bytes, rest) = buf.split_at(4);
                buf = rest;
                Value::Fixed32(u32::from_le_bytes(bytes.try_into().unwrap()))
            }
            2 => {
                let length = usize::try_from(varint(&mut buf)).unwrap();
                let (bytes, rest) = buf.split_at(length);
                buf = rest;
                Value::Bytes(bytes)
            }
            other => panic!("wire type {other}"),
        };
        out.push((number, value));
    }
    out
}

pub(crate) fn dnstap(buf: &[u8]) -> Dnstap {
    let mut out = Dnstap::default();
    for (number, value) in fields(buf) {
        match (number, value) {
            (1, Value::Bytes(bytes)) => out.identity = Some(bytes.to_vec()),
            (2, Value::Bytes(bytes)) => out.version = Some(bytes.to_vec()),
            (3, Value::Bytes(bytes)) => out.extra = Some(bytes.to_vec()),
            (14, Value::Bytes(bytes)) => out.message = Some(message(bytes)),
            (15, Value::Varint(kind)) => out.kind = Some(kind),
            (number, _) => panic!("unexpected Dnstap field {number}"),
        }
    }
    out
}

fn message(buf: &[u8]) -> Message {
    let mut out = Message::default();
    for (number, value) in fields(buf) {
        match (number, value) {
            (1, Value::Varint(value)) => out.kind = Some(value),
            (2, Value::Varint(value)) => out.family = Some(value),
            (3, Value::Varint(value)) => out.protocol = Some(value),
            (4, Value::Bytes(bytes)) => out.query_address = Some(bytes.to_vec()),
            (5, Value::Bytes(bytes)) => out.response_address = Some(bytes.to_vec()),
            (6, Value::Varint(value)) => out.query_port = Some(value),
            (7, Value::Varint(value)) => out.response_port = Some(value),
            (8, Value::Varint(value)) => out.query_time_sec = Some(value),
            (9, Value::Fixed32(value)) => out.query_time_nsec = Some(value),
            (10, Value::Bytes(bytes)) => out.query_message = Some(bytes.to_vec()),
            (12, Value::Varint(value)) => out.response_time_sec = Some(value),
            (13, Value::Fixed32(value)) => out.response_time_nsec = Some(value),
            (14, Value::Bytes(bytes)) => out.response_message = Some(bytes.to_vec()),
            (number, _) => panic!("unexpected Message field {number}"),
        }
    }
    out
}
