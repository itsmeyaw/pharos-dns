//! Zipkin v2 JSON span encoding.

use std::{fmt::Write, net::IpAddr};

use pharos_server::Protocol;

use super::span::{SpanRecord, hex_id};

// CoreDNS v1.15.0 plugin/trace/trace.go defaultTopLevelSpanName.
const SPAN_NAME: &str = "servedns";
// CoreDNS v1.15.0 plugin/trace/trace.go tagByProvider["default"].
const TAG_NAME: &str = "coredns.io/name";
const TAG_TYPE: &str = "coredns.io/type";
const TAG_RCODE: &str = "coredns.io/rcode";
const TAG_PROTO: &str = "coredns.io/proto";
const TAG_REMOTE: &str = "coredns.io/remote";

// Zipkin v2 API spec: Span JSON strings follow RFC 8259 §7 escaping.
fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => write!(out, "\\u{:04x}", u32::from(c)).unwrap(),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn tag(out: &mut String, first: &mut bool, key: &str, value: &str) {
    if !std::mem::take(first) {
        out.push(',');
    }
    json_string(out, key);
    out.push(':');
    json_string(out, value);
}

/// The Zipkin `localEndpoint` object, or `None` when it has no field to report.
// zipkin-go model/endpoint.go MarshalJSON: lowercase service name, `ipv4`/`ipv6` and `port`, each omitted when empty.
pub(super) fn local_endpoint(
    service: &str,
    ipv4: Option<IpAddr>,
    ipv6: Option<IpAddr>,
    port: u16,
) -> Option<String> {
    let quoted = |value: &str| {
        let mut out = String::new();
        json_string(&mut out, value);
        out
    };
    let mut fields = Vec::new();
    if !service.is_empty() {
        fields.push(format!(
            "\"serviceName\":{}",
            quoted(&service.to_lowercase())
        ));
    }
    if let Some(ip) = ipv4 {
        fields.push(format!("\"ipv4\":{}", quoted(&ip.to_string())));
    }
    if let Some(ip) = ipv6 {
        fields.push(format!("\"ipv6\":{}", quoted(&ip.to_string())));
    }
    if port != 0 {
        fields.push(format!("\"port\":{port}"));
    }
    (!fields.is_empty()).then(|| format!("{{{}}}", fields.join(",")))
}

/// Encode `spans` as one Zipkin v2 `POST /api/v2/spans` body.
// Zipkin v2 API spec: the body is a JSON array of Span objects.
pub(super) fn encode<'a>(
    spans: impl IntoIterator<Item = &'a SpanRecord>,
    local_endpoint: Option<&str>,
    out: &mut String,
) {
    out.push('[');
    for (index, span) in spans.into_iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        let mut id = [0; 16];
        let id = hex_id(span.id, &mut id);
        // zipkin-go model/span.go MarshalJSON: a sub-microsecond duration is reported as 1µs, otherwise rounded to the microsecond.
        let duration = match span.duration_nanos {
            0 => 0,
            nanos => ((nanos + 500) / 1000).max(1),
        };
        // Zipkin v2 API spec: `kind` SERVER marks the receiving side, as RPCServerOption does in CoreDNS.
        write!(
            out,
            "{{\"traceId\":\"{id}\",\"id\":\"{id}\",\"name\":\"{SPAN_NAME}\",\"kind\":\"SERVER\",\"timestamp\":{},\"duration\":{duration}",
            span.start_micros
        )
        .unwrap();
        if let Some(endpoint) = local_endpoint {
            write!(out, ",\"localEndpoint\":{endpoint}").unwrap();
        }
        if let Some(error) = span.error {
            // zipkin-go-opentracing span.go LogFields: each log field becomes an annotation of its string form.
            let at = span.start_micros + duration;
            write!(out, ",\"annotations\":[{{\"timestamp\":{at},\"value\":\"event:error\"}},{{\"timestamp\":{at},\"value\":").unwrap();
            json_string(out, &format!("error:{error}"));
            out.push_str("}]");
        }
        out.push_str(",\"tags\":{");
        let mut first = true;
        // CoreDNS v1.15.0 request/request.go Name and Type: the name is lowercased and the type is its mnemonic.
        if let Some(name) = span.name() {
            tag(
                out,
                &mut first,
                TAG_NAME,
                &name.to_string().to_ascii_lowercase(),
            );
            tag(out, &mut first, TAG_TYPE, &span.qtype.to_string());
        }
        tag(
            out,
            &mut first,
            TAG_PROTO,
            match span.protocol {
                Protocol::Udp => "udp",
                Protocol::Tcp => "tcp",
            },
        );
        tag(out, &mut first, TAG_REMOTE, &span.remote.to_string());
        if let Some(rcode) = span.rcode {
            tag(out, &mut first, TAG_RCODE, &rcode.to_string());
        }
        if span.error.is_some() {
            // zipkin-go-opentracing span.go SetTag: ext.Error true is stored as the string "true".
            tag(out, &mut first, "error", "true");
        }
        out.push_str("}}");
    }
    out.push(']');
}
