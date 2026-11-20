//! DNS over HTTPS (RFC 8484) request and response rules shared by every HTTP Transport.
//!
//! The module knows HTTP semantics only through the `http` types, so `https://` (hyper over TLS)
//! and later HTTP/3 and DoH Upstreams can share one definition of paths, methods, size limits,
//! status codes and `Cache-Control`.

use std::sync::OnceLock;

use base64::{
    Engine,
    alphabet::URL_SAFE,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};
use hyper::{
    Method, Request, StatusCode, Uri,
    header::{ACCEPT, CONTENT_TYPE, HOST, HeaderValue},
};
use pharos_proto::{Message, ResponseType, Type, typify_response};

use crate::metrics::{Registry, TransportStatus};

/// RFC 8484 §4.1: the URI Template's path; CoreDNS v1.15.0 plugin/pkg/doh `Path`.
pub const PATH: &str = "/dns-query";
/// RFC 8484 §6: the media type of a DNS Message.
pub const MEDIA_TYPE: &str = "application/dns-message";
/// RFC 8484 §5.2: HTTP/2 is the recommended minimum, HTTP/1.1 stays available.
pub const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
/// RFC 9114 §3.1: HTTP/3 is identified by the ALPN token "h3".
pub const H3_ALPN: &[&[u8]] = &[b"h3"];
/// CoreDNS v1.15.0 plugin/pkg/doh `maxDNSQuerySize`.
pub const MAX_QUERY_LEN: usize = 65536;
/// CoreDNS v1.15.0 core/dnsserver `DefaultHTTPSMaxConnections`.
pub const DEFAULT_MAX_CONNECTIONS: usize = 200;
/// CoreDNS v1.15.0 core/dnsserver `DefaultHTTPSMaxStreams`.
pub const DEFAULT_MAX_STREAMS: u32 = 250;
/// CoreDNS v1.15.0 core/dnsserver `DefaultHTTPS3MaxStreams`.
pub const DEFAULT_H3_MAX_STREAMS: u32 = 256;

/// Room for a 64 KiB request target plus ordinary header fields.
pub const MAX_HEADER_LIST: u32 = 128 * 1024;

// CoreDNS v1.15.0 plugin/pkg/doh `maxBase64Len`.
const MAX_ENCODED_LEN: usize = (MAX_QUERY_LEN * 8).div_ceil(6);
// CoreDNS v1.15.0 plugin/pkg/dnsutil `MinimalDefaultTTL` and `MaximumDefaultTTL`, in seconds.
const MINIMAL_TTL: u32 = 5;
const MAXIMUM_TTL: u32 = 3600;

// RFC 8484 §6: base64url without padding. Go's RawURLEncoding, which CoreDNS uses, tolerates
// non-zero trailing bits.
const BASE64URL: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::RequireNone)
        .with_decode_allow_trailing_bits(true),
);

/// Where a request carries its DNS Message.
#[derive(Debug, Eq, PartialEq)]
pub enum Source<'a> {
    /// The base64url value of the `dns` query parameter.
    Get(&'a str),
    /// The request body.
    Post,
}

/// Select the DNS Message source of a request, or the status that rejects it.
// CoreDNS v1.15.0 core/dnsserver/server_https.go ServeHTTP: path first (404), then the method and parameters (400).
pub fn locate<'a>(method: &Method, uri: &'a Uri) -> Result<Source<'a>, StatusCode> {
    if uri.path() != PATH {
        return Err(StatusCode::NOT_FOUND);
    }
    if method == Method::POST {
        // RFC 8484 §4.1: POST carries the Message as the body.
        return Ok(Source::Post);
    }
    if method != Method::GET {
        return Err(StatusCode::BAD_REQUEST);
    }
    // RFC 8484 §4.1: GET carries exactly one `dns` variable.
    let mut found = None;
    for pair in uri.query().unwrap_or_default().split('&') {
        // Go's url.ParseQuery drops a pair that holds a semicolon.
        if pair.contains(';') {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "dns" && found.replace(value).is_some() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    found.map(Source::Get).ok_or(StatusCode::BAD_REQUEST)
}

/// Decode a GET `dns` value into `out`, which is appended to.
pub fn decode_get(value: &str, out: &mut Vec<u8>) -> Result<(), StatusCode> {
    // CoreDNS v1.15.0 plugin/pkg/doh requestToMsgGet: "dns query too large".
    if value.len() > MAX_ENCODED_LEN {
        return Err(StatusCode::BAD_REQUEST);
    }
    BASE64URL
        .decode_vec(value, out)
        .map_err(|_| StatusCode::BAD_REQUEST)
}

/// The parts of a DoH request that stay the same for one server, built once so a Query reuses them.
#[derive(Clone, Debug)]
pub struct Endpoint {
    authority: String,
    /// The absolute-form POST target HTTP/2 needs for `:scheme` and `:authority`.
    absolute: Uri,
    /// The origin-form POST target of HTTP/1.1, which names the host in `host` instead.
    origin: Uri,
    host: HeaderValue,
}

impl Endpoint {
    /// The endpoint of the DoH server at `authority`, or `None` if it is not a valid HTTP authority.
    #[must_use]
    pub fn new(authority: &str) -> Option<Self> {
        Some(Self {
            authority: authority.to_owned(),
            absolute: format!("https://{authority}{PATH}").parse().ok()?,
            origin: Uri::from_static(PATH),
            host: HeaderValue::from_str(authority).ok()?,
        })
    }

    /// The request that carries `wire` to the server, or `None` for a method DoH lacks.
    ///
    /// `absolute` selects the absolute-form target HTTP/2 needs; HTTP/1.1 gets the origin form and a
    /// `Host` field. `body` is cleared and left holding the request body: `wire` for POST, nothing
    /// for GET, whose target is encoded in `body` first, so a caller's pooled buffer serves both.
    // CoreDNS v1.15.0 plugin/pkg/doh NewRequestWithContext: both methods set Content-Type and Accept.
    #[must_use]
    pub fn request(
        &self,
        method: &Method,
        absolute: bool,
        wire: &[u8],
        body: &mut Vec<u8>,
    ) -> Option<Request<()>> {
        body.clear();
        let uri = match *method {
            // RFC 8484 §4.1: POST carries the Message as the body.
            Method::POST => {
                body.extend_from_slice(wire);
                if absolute {
                    self.absolute.clone()
                } else {
                    self.origin.clone()
                }
            }
            // RFC 8484 §4.1: GET carries the Message as the unpadded base64url `dns` variable.
            Method::GET => {
                if absolute {
                    body.extend_from_slice(b"https://");
                    body.extend_from_slice(self.authority.as_bytes());
                }
                body.extend_from_slice(PATH.as_bytes());
                body.extend_from_slice(b"?dns=");
                let at = body.len();
                body.resize(at + base64::encoded_len(wire.len(), false)?, 0);
                BASE64URL.encode_slice(wire, &mut body[at..]).ok()?;
                let uri = Uri::try_from(body.as_slice()).ok();
                body.clear();
                uri?
            }
            _ => return None,
        };
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE))
            .header(ACCEPT, HeaderValue::from_static(MEDIA_TYPE));
        if !absolute {
            // RFC 9112 §3.2: HTTP/1.1 requests name the host in a Host field.
            builder = builder.header(HOST, self.host.clone());
        }
        builder.body(()).ok()
    }
}

/// Whether a DNS Message is a Query the Listener should answer.
// miekg/dns v1.1.73 acceptfunc.go defaultMsgAcceptFunc, then the parse CoreDNS dnsutil.UnpackRequest performs.
#[must_use]
pub fn accept(wire: &[u8]) -> bool {
    let Some(header) = wire.get(..12) else {
        return false;
    };
    let flags = u16::from_be_bytes([header[2], header[3]]);
    let count = |index: usize| u16::from_be_bytes([header[index], header[index + 1]]);
    // RFC 1035 §4.1.1: QR=1 is a Response; opcode 0 is QUERY and 4 is NOTIFY (RFC 1996 §3.1).
    let opcode = (flags >> 11) & 0xf;
    flags & 0x8000 == 0
        && matches!(opcode, 0 | 4)
        && count(4) == 1
        && count(6) <= 1
        && count(8) <= 1
        && count(10) <= 2
        && Message::parse(wire).is_ok()
}

/// The HTTP freshness lifetime, in seconds, of a DNS Response.
// RFC 8484 §5.1: freshness must not exceed the smallest TTL; CoreDNS v1.15.0 dnsutil.MinimalTTLWithMaximum.
#[must_use]
pub fn max_age(response: &[u8], now: i64) -> u32 {
    let Ok(message) = Message::parse(response) else {
        return MINIMAL_TTL;
    };
    if !matches!(
        typify_response(Some(&message), now),
        ResponseType::Positive | ResponseType::NxDomain | ResponseType::NoData
    ) {
        return MINIMAL_TTL;
    }
    let mut records = message
        .answers()
        .chain(message.authorities())
        .chain(message.additionals().filter(|rr| rr.rtype != Type::OPT))
        .map(|rr| rr.ttl)
        .peekable();
    // A Response with no records, or only an OPT, gets the short fail-safe lifetime.
    if records.peek().is_none() {
        return MINIMAL_TTL;
    }
    records.fold(MAXIMUM_TTL, u32::min)
}

/// A `Cache-Control` field value for a freshness lifetime.
#[must_use]
pub fn cache_control(max_age: u32) -> HeaderValue {
    // Values are built once, so a Response clones a reference-counted value instead of allocating one.
    static VALUES: OnceLock<Vec<HeaderValue>> = OnceLock::new();
    let values = VALUES.get_or_init(|| {
        (0..=MAXIMUM_TTL)
            .map(|seconds| {
                HeaderValue::from_str(&format!("max-age={seconds}"))
                    .expect("ASCII digits form a header value")
            })
            .collect()
    });
    values[max_age.min(MAXIMUM_TTL) as usize].clone()
}

/// Response counters of one HTTP Listener, resolved on first use like CoreDNS's label values.
pub struct Status {
    registry: Registry,
    transport: &'static str,
    server: String,
    common: [OnceLock<TransportStatus>; 4],
}

impl Status {
    /// Counters for `transport` ("https" or "https3") on the Listener labelled `server`.
    #[must_use]
    pub fn new(registry: Registry, transport: &'static str, server: String) -> Self {
        Self {
            registry,
            transport,
            server,
            common: Default::default(),
        }
    }

    /// Count one HTTP response.
    pub fn count(&self, status: StatusCode) {
        // CoreDNS v1.15.0 core/dnsserver/server_https.go countResponse: label is the numeric status.
        let slot = match status {
            StatusCode::OK => Some(0),
            StatusCode::BAD_REQUEST => Some(1),
            StatusCode::NOT_FOUND => Some(2),
            StatusCode::INTERNAL_SERVER_ERROR => Some(3),
            _ => None,
        };
        let resolve = || {
            self.registry
                .transport_status(self.transport, &self.server, status.as_str())
        };
        match slot {
            Some(slot) => self.common[slot].get_or_init(resolve).increment(),
            None => resolve().increment(),
        }
    }
}
