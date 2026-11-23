//! Datadog agent trace API (v0.4, MessagePack) span encoding.

use super::{
    span::{SpanRecord, hex_id, proto},
    zipkin::SPAN_NAME,
};

// CoreDNS v1.15.0 plugin/trace/trace.go tagByProvider["datadog"].
const TAG_NAME: &str = "coredns.io@name";
const TAG_TYPE: &str = "coredns.io@type";
const TAG_RCODE: &str = "coredns.io@rcode";
const TAG_PROTO: &str = "coredns.io@proto";
const TAG_REMOTE: &str = "coredns.io@remote";
// dd-trace-go v2.10.1 ddtrace/tracer/span.go keyTraceID128: the upper 64 bits of the trace ID, hex encoded.
const TAG_TRACE_ID_UPPER: &str = "_dd.p.tid";
// dd-trace-go v2.10.1 ddtrace/ext/tags.go: ErrorMsg, ErrorType and EventSampleRate.
const TAG_ERROR_MESSAGE: &str = "error.message";
const TAG_ERROR_TYPE: &str = "error.type";
const METRIC_ANALYTICS_RATE: &str = "_dd1.sr.eausr";
// dd-trace-go v2.10.1 ddtrace/tracer/span.go keySamplingPriority and keyTopLevel; ext.Pid.
const METRIC_SAMPLING_PRIORITY: &str = "_sampling_priority_v1";
const METRIC_TOP_LEVEL: &str = "_dd.top_level";
const METRIC_PID: &str = "process_id";
// CoreDNS v1.15.0 plugin/trace/trace.go setDatadogSpanTags: `error.type` is always dns_error.
const ERROR_TYPE: &str = "dns_error";
// dd-trace-go v2.10.1 ddtrace/ext/app_types.go SpanTypeDNS.
const SPAN_TYPE: &str = "dns";
// CoreDNS v1.15.0 plugin/trace/setup.go OnStartup: WithGlobalTag(ext.SpanTypeDNS, true) sets the tag `dns` to "true" on each span.
const GLOBAL_TAG: &str = "dns";

/// Datadog agent API: the path of the trace intake, appended to the agent URL as dd-trace-go does.
const TRACES_PATH: &str = "/v0.4/traces";

/// The trace-intake URL for an agent endpoint: `host[:port]` or an `http(s)://` base URL.
// dd-trace-go v2.10.1 WithAgentAddr builds `http://ADDR`, and transport.go appends tracesAPIPath.
pub(super) fn traces_url(endpoint: &str) -> String {
    let lower = endpoint.to_ascii_lowercase();
    let base = endpoint.trim_end_matches('/');
    if lower.starts_with("http://") || lower.starts_with("https://") {
        format!("{base}{TRACES_PATH}")
    } else {
        format!("http://{base}{TRACES_PATH}")
    }
}

// dd-trace-go v2.10.1 spancontext.go: the upper word of a new 128-bit trace ID is the start second above 32 zero bits.
fn upper_trace_id(start_micros: u64) -> u64 {
    u64::from((start_micros / 1_000_000) as u32) << 32
}

/// The trace ID as dd-trace-go v2 `Span.Context().TraceID()` prints it: 32 lowercase hex digits.
// dd-trace-go v2.10.1 spancontext.go TraceID: the hex of `<upper 64 bits><lower 64 bits>`, and a root span's lower word is its span ID.
pub(super) fn hex_trace_id(start_micros: u64, id: u64, out: &mut [u8; 32]) -> &str {
    let (upper, lower) = out.split_at_mut(16);
    hex_id(upper_trace_id(start_micros), upper.try_into().unwrap());
    hex_id(id, lower.try_into().unwrap());
    std::str::from_utf8(out).expect("hex digits are ASCII")
}

// MessagePack spec: the smallest header that holds `len`, as fix, 16-bit and 32-bit forms.
fn header(out: &mut Vec<u8>, len: usize, fix: (u8, usize), wide: (u8, u8)) {
    if len <= fix.1 {
        out.push(fix.0 | len as u8);
    } else if let Ok(len) = u16::try_from(len) {
        out.push(wide.0);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        out.push(wide.1);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

// MessagePack spec, array format family.
fn array_header(out: &mut Vec<u8>, len: usize) {
    header(out, len, (0x90, 15), (0xdc, 0xdd));
}

// MessagePack spec, map format family.
fn map_header(out: &mut Vec<u8>, len: usize) {
    header(out, len, (0x80, 15), (0xde, 0xdf));
}

// MessagePack spec, str format family.
fn string(out: &mut Vec<u8>, value: &str) {
    let len = value.len();
    if len <= 31 {
        out.push(0xa0 | len as u8);
    } else if let Ok(len) = u8::try_from(len) {
        out.extend_from_slice(&[0xd9, len]);
    } else if let Ok(len) = u16::try_from(len) {
        out.push(0xda);
        out.extend_from_slice(&len.to_be_bytes());
    } else {
        out.push(0xdb);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.extend_from_slice(value.as_bytes());
}

// MessagePack spec, uint format family.
fn uint(out: &mut Vec<u8>, value: u64) {
    if value <= 0x7f {
        out.push(value as u8);
    } else if let Ok(value) = u8::try_from(value) {
        out.extend_from_slice(&[0xcc, value]);
    } else if let Ok(value) = u16::try_from(value) {
        out.push(0xcd);
        out.extend_from_slice(&value.to_be_bytes());
    } else if let Ok(value) = u32::try_from(value) {
        out.push(0xce);
        out.extend_from_slice(&value.to_be_bytes());
    } else {
        out.push(0xcf);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

// MessagePack spec, float 64.
fn float(out: &mut Vec<u8>, value: f64) {
    out.push(0xcb);
    out.extend_from_slice(&value.to_be_bytes());
}

fn tag(out: &mut Vec<u8>, key: &str, value: &str) {
    string(out, key);
    string(out, value);
}

fn metric(out: &mut Vec<u8>, key: &str, value: f64) {
    string(out, key);
    float(out, value);
}

/// Encode `spans` as one `/v0.4/traces` body: an array of traces, each trace an array of spans.
// Datadog agent API v0.4: each sampled Query is a trace of one root span.
pub(super) fn encode<'a>(
    spans: impl ExactSizeIterator<Item = &'a SpanRecord>,
    service: &str,
    analytics_rate: f64,
    out: &mut Vec<u8>,
) {
    array_header(out, spans.len());
    for span in spans {
        array_header(out, 1);
        encode_span(span, service, analytics_rate, out);
    }
}

fn encode_span(span: &SpanRecord, service: &str, analytics_rate: f64, out: &mut Vec<u8>) {
    let mut tid = [0; 16];
    let tid = hex_id(upper_trace_id(span.start_micros), &mut tid).to_owned();
    let mut meta: Vec<(&str, String)> =
        vec![(TAG_TRACE_ID_UPPER, tid), (GLOBAL_TAG, "true".to_owned())];
    // CoreDNS v1.15.0 request/request.go Name and Type: the name is lowercased and the type is its mnemonic.
    if let Some(name) = span.name() {
        meta.push((TAG_NAME, name.to_string().to_ascii_lowercase()));
        meta.push((TAG_TYPE, span.qtype.to_string()));
    }
    meta.push((TAG_PROTO, proto(span.protocol).to_owned()));
    meta.push((TAG_REMOTE, span.remote.to_string()));
    if let Some(rcode) = span.rcode {
        meta.push((TAG_RCODE, rcode.to_string()));
    }
    if let Some(error) = span.error {
        meta.push((TAG_ERROR_MESSAGE, error.to_string()));
        meta.push((TAG_ERROR_TYPE, ERROR_TYPE.to_owned()));
    }
    // Datadog agent API v0.4 span fields, in the order dd-trace-go v2.10.1 span_msgp.go EncodeMsg writes them.
    map_header(out, 12);
    tag(out, "name", SPAN_NAME);
    tag(out, "service", service);
    // dd-trace-go v2.10.1 StartSpan: the resource defaults to the operation name.
    tag(out, "resource", SPAN_NAME);
    tag(out, "type", SPAN_TYPE);
    string(out, "start");
    uint(out, span.start_micros.saturating_mul(1000));
    string(out, "duration");
    uint(out, span.duration_nanos);
    string(out, "meta");
    map_header(out, meta.len());
    for (key, value) in &meta {
        tag(out, key, value);
    }
    string(out, "metrics");
    let rate = analytics_rate > 0.0;
    map_header(out, 3 + usize::from(rate));
    metric(out, METRIC_SAMPLING_PRIORITY, 1.0);
    metric(out, METRIC_TOP_LEVEL, 1.0);
    metric(out, METRIC_PID, f64::from(std::process::id()));
    if rate {
        // dd-trace-go v2.10.1 ext.EventSampleRate: the analytics rate of a span; its core tracer never applies the global rate itself.
        metric(out, METRIC_ANALYTICS_RATE, analytics_rate);
    }
    string(out, "span_id");
    uint(out, span.id);
    string(out, "trace_id");
    uint(out, span.id);
    string(out, "parent_id");
    uint(out, 0);
    string(out, "error");
    uint(out, u64::from(span.error.is_some()));
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, time::Duration};

    use pharos_proto::{Message, Name, Rcode};
    use pharos_server::{Context, Error as ServerError, Metadata, Outcome, Protocol, Transport};

    use super::*;

    #[derive(Clone, Debug, PartialEq)]
    enum Value {
        Uint(u64),
        Float(f64),
        Str(String),
        Array(Vec<Value>),
        Map(Vec<(String, Value)>),
    }

    impl Value {
        fn entries(&self) -> &[(String, Value)] {
            let Self::Map(entries) = self else {
                panic!("{self:?} is not a map")
            };
            entries
        }

        fn get(&self, key: &str) -> &Value {
            self.entries()
                .iter()
                .find_map(|(name, value)| (name == key).then_some(value))
                .unwrap_or_else(|| panic!("no key {key} in {self:?}"))
        }

        fn has(&self, key: &str) -> bool {
            self.entries().iter().any(|(name, _)| name == key)
        }

        fn str(&self) -> &str {
            let Self::Str(text) = self else {
                panic!("{self:?} is not a string")
            };
            text
        }

        fn array(&self) -> &[Value] {
            let Self::Array(items) = self else {
                panic!("{self:?} is not an array")
            };
            items
        }
    }

    // A minimal MessagePack reader for the forms the encoder writes, so the tests check the wire rather than the writer.
    fn read(input: &mut &[u8]) -> Value {
        fn take(input: &mut &[u8], n: usize) -> u64 {
            let (head, tail) = input.split_at(n);
            *input = tail;
            head.iter().fold(0, |acc, byte| acc << 8 | u64::from(*byte))
        }
        fn text(input: &mut &[u8], len: u64) -> Value {
            let (head, tail) = input.split_at(len as usize);
            *input = tail;
            Value::Str(String::from_utf8(head.to_vec()).unwrap())
        }
        let prefix = take(input, 1) as u8;
        match prefix {
            0x00..=0x7f => Value::Uint(u64::from(prefix)),
            0x80..=0x8f | 0xde | 0xdf => {
                let len = match prefix {
                    0xde => take(input, 2),
                    0xdf => take(input, 4),
                    _ => u64::from(prefix & 0x0f),
                };
                Value::Map(
                    (0..len)
                        .map(|_| (read(input).str().to_owned(), read(input)))
                        .collect(),
                )
            }
            0x90..=0x9f | 0xdc | 0xdd => {
                let len = match prefix {
                    0xdc => take(input, 2),
                    0xdd => take(input, 4),
                    _ => u64::from(prefix & 0x0f),
                };
                Value::Array((0..len).map(|_| read(input)).collect())
            }
            0xa0..=0xbf => text(input, u64::from(prefix & 0x1f)),
            0xd9 => {
                let len = take(input, 1);
                text(input, len)
            }
            0xda => {
                let len = take(input, 2);
                text(input, len)
            }
            0xdb => {
                let len = take(input, 4);
                text(input, len)
            }
            0xcb => Value::Float(f64::from_bits(take(input, 8))),
            0xcc => Value::Uint(take(input, 1)),
            0xcd => Value::Uint(take(input, 2)),
            0xce => Value::Uint(take(input, 4)),
            0xcf => Value::Uint(take(input, 8)),
            other => panic!("unsupported MessagePack prefix {other:#x}"),
        }
    }

    fn decode(bytes: &[u8]) -> Value {
        let mut input = bytes;
        let value = read(&mut input);
        assert!(input.is_empty(), "{} trailing bytes", input.len());
        value
    }

    // MessagePack spec: the smallest encoding of each size class.
    #[test]
    fn primitives_use_the_smallest_encoding() {
        let mut out = Vec::new();
        for (value, expected) in [
            (0, &[0x00][..]),
            (127, &[0x7f]),
            (128, &[0xcc, 0x80]),
            (255, &[0xcc, 0xff]),
            (256, &[0xcd, 0x01, 0x00]),
            (65_536, &[0xce, 0, 1, 0, 0]),
            (1 << 32, &[0xcf, 0, 0, 0, 1, 0, 0, 0, 0]),
        ] {
            out.clear();
            uint(&mut out, value);
            assert_eq!(out, expected, "{value}");
        }
        for (len, prefix) in [
            (0, &[0xa0][..]),
            (31, &[0xbf]),
            (32, &[0xd9, 32]),
            (256, &[0xda, 1, 0]),
        ] {
            out.clear();
            string(&mut out, &"x".repeat(len));
            assert_eq!(&out[..prefix.len()], prefix, "{len}");
            assert_eq!(out.len(), prefix.len() + len);
        }
        for (len, expected) in [
            (0, &[0x90][..]),
            (15, &[0x9f]),
            (16, &[0xdc, 0, 16]),
            (65_536, &[0xdd, 0, 1, 0, 0]),
        ] {
            out.clear();
            array_header(&mut out, len);
            assert_eq!(out, expected, "{len}");
        }
        for (len, expected) in [(15, &[0x8f][..]), (16, &[0xde, 0, 16])] {
            out.clear();
            map_header(&mut out, len);
            assert_eq!(out, expected, "{len}");
        }
        out.clear();
        float(&mut out, 0.5);
        assert_eq!(out, [0xcb, 0x3f, 0xe0, 0, 0, 0, 0, 0, 0]);
    }

    // Example.org. IN A from 192.0.2.7 over TCP, started at 1_700_000_000.123456 s.
    fn span(outcome: &Outcome) -> SpanRecord {
        let wire = b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0\x07Example\x03org\0\0\x01\0\x01";
        let domain: Name = ".".parse().unwrap();
        let mut response = Vec::new();
        let mut slots = [];
        let cx = Context {
            query: Message::parse(wire).unwrap(),
            client: "192.0.2.7:5353".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Tcp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        let mut span = SpanRecord::capture(
            0x1234_5678_9abc,
            1_700_000_000_123_456,
            Duration::from_nanos(1500),
            &cx,
            outcome,
        );
        span.id = 0x1234_5678_9abc;
        span
    }

    fn first_span(spans: &[SpanRecord], rate: f64) -> Value {
        let mut out = Vec::new();
        encode(spans.iter(), "pharos-test", rate, &mut out);
        let traces = decode(&out);
        let trace = traces.array()[0].array();
        assert_eq!(trace.len(), 1);
        trace[0].clone()
    }

    // Datadog agent API v0.4 and dd-trace-go v2.10.1 span_msgp.go: the fields and types of a span.
    #[test]
    fn span_has_the_v04_fields() {
        let span = first_span(&[span(&Outcome::Unanswered(Rcode::NXDOMAIN))], 0.0);
        assert_eq!(span.get("name").str(), "servedns");
        assert_eq!(span.get("resource").str(), "servedns");
        assert_eq!(span.get("service").str(), "pharos-test");
        assert_eq!(span.get("type").str(), "dns");
        assert_eq!(span.get("start"), &Value::Uint(1_700_000_000_123_456_000));
        assert_eq!(span.get("duration"), &Value::Uint(1500));
        assert_eq!(span.get("span_id"), &Value::Uint(0x1234_5678_9abc));
        assert_eq!(span.get("trace_id"), &Value::Uint(0x1234_5678_9abc));
        assert_eq!(span.get("parent_id"), &Value::Uint(0));
        assert_eq!(span.get("error"), &Value::Uint(0));
        let meta = span.get("meta");
        for (key, value) in [
            ("coredns.io@name", "example.org."),
            ("coredns.io@type", "A"),
            ("coredns.io@proto", "tcp"),
            ("coredns.io@remote", "192.0.2.7"),
            ("coredns.io@rcode", "NXDOMAIN"),
            ("_dd.p.tid", "6553f10000000000"),
            ("dns", "true"),
        ] {
            assert_eq!(meta.get(key).str(), value, "{key}");
        }
        assert!(!meta.has("error.message"));
        let metrics = span.get("metrics");
        assert_eq!(metrics.get("_sampling_priority_v1"), &Value::Float(1.0));
        assert_eq!(metrics.get("_dd.top_level"), &Value::Float(1.0));
        assert!(metrics.has("process_id"));
        assert!(!metrics.has("_dd1.sr.eausr"));
    }

    // CoreDNS v1.15.0 plugin/trace/trace.go setDatadogSpanTags: an error sets error.message, error and error.type=dns_error.
    #[test]
    fn error_span_carries_error_tags() {
        let span = first_span(&[span(&Outcome::Error(ServerError::Internal))], 0.0);
        assert_eq!(span.get("error"), &Value::Uint(1));
        let meta = span.get("meta");
        assert_eq!(meta.get("error.message").str(), "internal plugin error");
        assert_eq!(meta.get("error.type").str(), "dns_error");
        assert_eq!(meta.get("coredns.io@rcode").str(), "SERVFAIL");
    }

    #[test]
    fn analytics_rate_is_a_span_metric_only_when_set() {
        let span = first_span(&[span(&Outcome::Drop)], 0.25);
        assert_eq!(
            span.get("metrics").get("_dd1.sr.eausr"),
            &Value::Float(0.25)
        );
        // No Response written and no status: the span has no rcode tag.
        assert!(!span.get("meta").has("coredns.io@rcode"));
    }

    #[test]
    fn many_spans_become_many_traces() {
        let spans: VecDeque<SpanRecord> = (0..20).map(|_| span(&Outcome::Drop)).collect();
        let mut out = Vec::new();
        encode(spans.iter(), "s", 0.0, &mut out);
        assert_eq!(&out[..3], [0xdc, 0, 20]);
        assert_eq!(decode(&out).array().len(), 20);
    }

    // dd-trace-go v2.10.1 spancontext.go and TraceID(): 32 hex digits, the start second in the upper word.
    #[test]
    fn trace_id_is_32_hex_digits_with_the_start_second_above() {
        let mut out = [0; 32];
        assert_eq!(
            hex_trace_id(1_700_000_000_123_456, 0x1234_5678_9abc, &mut out),
            "6553f100000000000000123456789abc"
        );
    }

    #[test]
    fn traces_url_accepts_the_endpoint_forms() {
        for (endpoint, expected) in [
            ("localhost", "http://localhost/v0.4/traces"),
            ("localhost:8126", "http://localhost:8126/v0.4/traces"),
            ("http://localhost:8127", "http://localhost:8127/v0.4/traces"),
            ("HTTPS://agent:8126/", "HTTPS://agent:8126/v0.4/traces"),
            ("[::1]:8126", "http://[::1]:8126/v0.4/traces"),
        ] {
            assert_eq!(traces_url(endpoint), expected);
        }
    }
}
