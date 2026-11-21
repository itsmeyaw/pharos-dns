//! Fixed-size span record handed from the Query path to the exporter.

use std::{
    net::IpAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pharos_proto::{Message, NameRef, Rcode, Type};
use pharos_server::{Context, Error, Outcome, Protocol};

#[derive(Clone, Debug)]
pub(super) struct SpanRecord {
    // zipkin-go StartSpan: a root span's ID is also its trace ID, and Pharos draws 64-bit trace IDs.
    pub id: u64,
    pub start_micros: u64,
    pub duration_nanos: u64,
    name: [u8; 255],
    name_len: u8,
    pub qtype: Type,
    pub protocol: Protocol,
    pub remote: IpAddr,
    pub rcode: Option<Rcode>,
    pub error: Option<Error>,
}

// zipkin-go model.TraceID.String: 16 lowercase hex digits for a 64-bit ID.
pub(super) fn hex_id(id: u64, out: &mut [u8; 16]) -> &str {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = DIGITS[(id >> (60 - 4 * index) & 0xf) as usize];
    }
    std::str::from_utf8(out).expect("hex digits are ASCII")
}

// CoreDNS v1.15.0 request/request.go Proto: the transport protocol of the Query.
pub(super) fn proto(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Udp => "udp",
        Protocol::Tcp => "tcp",
    }
}

pub(super) fn unix_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros() as u64)
}

impl SpanRecord {
    // CoreDNS v1.15.0 plugin/trace/trace.go setZipkinSpanTags: tags describe the Query and the status that went to the client.
    pub(super) fn capture(
        id: u64,
        start_micros: u64,
        elapsed: Duration,
        cx: &Context<'_, '_>,
        outcome: &Outcome,
    ) -> Self {
        let mut name = [0; 255];
        let mut name_len = 0;
        let mut qtype = Type(0);
        if let Some(question) = cx.query.questions().next() {
            qtype = question.qtype;
            for label in question.name.labels() {
                // RFC 1035 §3.1: a name is length-prefixed labels, at most 255 octets with the root.
                let end = name_len + 1 + label.len();
                if end >= name.len() {
                    break;
                }
                name[name_len] = label.len() as u8;
                name[name_len + 1..end].copy_from_slice(label);
                name_len = end;
            }
            name_len += 1;
        }
        let (rcode, error) = match outcome {
            // RFC 1035 §4.1.1: the RCODE of the Response the Listener writes.
            Outcome::Response => (Message::parse(cx.response).ok().map(|m| m.rcode()), None),
            Outcome::Stream(_) => (Some(Rcode::NOERROR), None),
            Outcome::Drop => (None, None),
            // CoreDNS v1.15.0 plugin/trace/trace.go: with no Response written, the status the Plugin returned is the RCODE.
            Outcome::Unanswered(code) => (Some(*code), None),
            // The Listener answers an Error with SERVFAIL (pharos-server Outcome docs).
            Outcome::Error(error) => (Some(Rcode::SERVFAIL), Some(*error)),
        };
        Self {
            id,
            start_micros,
            duration_nanos: elapsed.as_nanos().min(u128::from(u64::MAX)) as u64,
            name,
            name_len: name_len as u8,
            qtype,
            protocol: cx.protocol,
            remote: cx.client.ip(),
            rcode,
            error,
        }
    }

    /// The Query name, or `None` for a Query without a question.
    pub(super) fn name(&self) -> Option<NameRef<'_>> {
        (self.name_len != 0)
            .then(|| NameRef::parse(&self.name[..usize::from(self.name_len)], 0).ok())
            .flatten()
    }
}
