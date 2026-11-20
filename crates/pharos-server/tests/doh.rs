#![forbid(unsafe_code)]

use hyper::{Method, StatusCode, Uri};
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Section, Type};
use pharos_server::doh::{self, Source};

fn uri(text: &str) -> Uri {
    text.parse().unwrap()
}

fn query_wire(flags: u16) -> Vec<u8> {
    let mut wire = Vec::new();
    let name: Name = "example.org.".parse().unwrap();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, flags).unwrap();
    builder
        .question(
            NameRef::parse(name.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    wire
}

fn response_wire(ttls: &[u32], authority: &[u32]) -> Vec<u8> {
    let mut wire = Vec::new();
    let name: Name = "example.org.".parse().unwrap();
    let owner = NameRef::parse(name.as_wire(), 0).unwrap();
    let mut builder = MessageBuilder::new(&mut wire, 512, 0, 0x8180).unwrap();
    builder.question(owner, Type::A, Class::IN).unwrap();
    for ttl in ttls {
        builder
            .record(
                Section::Answer,
                owner,
                Type::A,
                Class::IN,
                *ttl,
                &[192, 0, 2, 1],
            )
            .unwrap();
    }
    for ttl in authority {
        builder
            .record(
                Section::Authority,
                owner,
                Type::SOA,
                Class::IN,
                *ttl,
                &[0; 22],
            )
            .unwrap();
    }
    let _ = builder.finish();
    wire
}

// CoreDNS v1.15.0 core/dnsserver/server_https_test.go TestCustomHTTPRequestValidator: default path only.
#[test]
fn only_the_dns_query_path_is_served() {
    assert_eq!(
        doh::locate(&Method::POST, &uri("/dns-query")),
        Ok(Source::Post)
    );
    for path in ["/", "/dns-query/", "/b10cada", "/DNS-QUERY"] {
        assert_eq!(
            doh::locate(&Method::POST, &uri(path)),
            Err(StatusCode::NOT_FOUND),
            "{path}"
        );
    }
}

// RFC 8484 §4.1: GET carries the Query as the base64url `dns` variable.
#[test]
fn get_extracts_the_single_dns_parameter() {
    assert_eq!(
        doh::locate(&Method::GET, &uri("/dns-query?dns=AAAB&x=1")),
        Ok(Source::Get("AAAB"))
    );
    for target in [
        "/dns-query",
        "/dns-query?x=1",
        "/dns-query?dns=AAAB&dns=AAAC",
    ] {
        assert_eq!(
            doh::locate(&Method::GET, &uri(target)),
            Err(StatusCode::BAD_REQUEST),
            "{target}"
        );
    }
}

// CoreDNS v1.15.0 plugin/pkg/doh/doh.go RequestToMsgWire: other methods are rejected as invalid.
#[test]
fn other_methods_are_bad_requests() {
    for method in [Method::PUT, Method::HEAD, Method::DELETE] {
        assert_eq!(
            doh::locate(&method, &uri("/dns-query")),
            Err(StatusCode::BAD_REQUEST)
        );
    }
}

// RFC 8484 §6: base64url without padding.
#[test]
fn get_decodes_unpadded_base64url() {
    let wire = query_wire(0x0100);
    let encoded = base64_url(&wire);
    let mut out = Vec::new();
    doh::decode_get(&encoded, &mut out).unwrap();
    assert_eq!(out, wire);
    for bad in ["AAAB=", "AA+B", "AA/B", "!!!!"] {
        out.clear();
        assert_eq!(
            doh::decode_get(bad, &mut out),
            Err(StatusCode::BAD_REQUEST),
            "{bad}"
        );
    }
}

// CoreDNS v1.15.0 plugin/pkg/doh/doh_test.go TestDoHGETRejectsOversizedDNSQuery.
#[test]
fn get_rejects_oversized_queries_before_decoding() {
    let mut out = Vec::new();
    let at_limit = base64_url(&vec![0; 65536]);
    assert!(doh::decode_get(&at_limit, &mut out).is_ok());
    let over = base64_url(&vec![0; 65537]);
    out.clear();
    assert_eq!(
        doh::decode_get(&over, &mut out),
        Err(StatusCode::BAD_REQUEST)
    );
    assert!(out.is_empty());
}

// CoreDNS v1.15.0 plugin/pkg/doh/doh.go NewRequestWithContext: POST carries the wire as the body.
#[test]
fn post_request_carries_the_wire_as_the_body() {
    let wire = query_wire(0x0100);
    let mut body = Vec::new();
    let request = doh::Endpoint::new("dns.example")
        .unwrap()
        .request(&Method::POST, true, &wire, &mut body)
        .unwrap();
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.uri(), "https://dns.example/dns-query");
    assert_eq!(request.headers()["content-type"], doh::MEDIA_TYPE);
    assert_eq!(request.headers()["accept"], doh::MEDIA_TYPE);
    assert_eq!(body, wire);
}

// RFC 8484 §4.1: GET carries the unpadded base64url Query in the `dns` variable and no body.
#[test]
fn get_request_encodes_the_wire_in_the_dns_variable() {
    let wire = query_wire(0x0100);
    let mut body = vec![1, 2, 3];
    let request = doh::Endpoint::new("dns.example:8443")
        .unwrap()
        .request(&Method::GET, true, &wire, &mut body)
        .unwrap();
    assert_eq!(
        request.uri().to_string(),
        format!(
            "https://dns.example:8443/dns-query?dns={}",
            base64_url(&wire)
        )
    );
    assert_eq!(request.headers()["accept"], doh::MEDIA_TYPE);
    assert!(body.is_empty());
}

// RFC 8484 §4.1: the origin form of a GET target carries the same `dns` variable.
#[test]
fn http1_get_request_encodes_the_wire_in_the_origin_form() {
    let wire = query_wire(0x0100);
    let request = doh::Endpoint::new("dns.example")
        .unwrap()
        .request(&Method::GET, false, &wire, &mut Vec::new())
        .unwrap();
    assert_eq!(
        request.uri().to_string(),
        format!("/dns-query?dns={}", base64_url(&wire))
    );
    assert_eq!(request.headers()["host"], "dns.example");
}

// RFC 9112 §3.2: HTTP/1.1 sends the origin form and names the host in a header.
#[test]
fn http1_request_uses_origin_form_and_a_host_header() {
    let request = doh::Endpoint::new("192.0.2.1")
        .unwrap()
        .request(&Method::POST, false, &query_wire(0), &mut Vec::new())
        .unwrap();
    assert_eq!(request.uri(), "/dns-query");
    assert_eq!(request.headers()["host"], "192.0.2.1");
}

// CoreDNS v1.15.0 plugin/pkg/doh/doh.go NewRequestWithContext: "method not allowed".
#[test]
fn other_methods_build_no_request() {
    let endpoint = doh::Endpoint::new("dns.example").unwrap();
    assert!(
        endpoint
            .request(&Method::PUT, true, &[], &mut Vec::new())
            .is_none()
    );
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(bytes)
}

// miekg/dns v1.1.73 acceptfunc.go defaultMsgAcceptFunc via CoreDNS dnsutil.UnpackRequest.
#[test]
fn accept_follows_the_default_message_accept_policy() {
    assert!(doh::accept(&query_wire(0x0100)));
    // Opcode NOTIFY (4) is accepted.
    assert!(doh::accept(&query_wire(0x2000)));
    // Responses, UPDATE (5), IQUERY (1) and STATUS (2) are not.
    for flags in [0x8100, 0x2800, 0x0800, 0x1000] {
        assert!(!doh::accept(&query_wire(flags)), "{flags:#x}");
    }
    assert!(!doh::accept(&[]));
    assert!(!doh::accept(&[0; 11]));
    // QDCOUNT of zero.
    assert!(!doh::accept(&[0; 12]));
    let mut truncated = query_wire(0x0100);
    truncated.truncate(truncated.len() - 3);
    assert!(!doh::accept(&truncated));
    let mut many_additionals = query_wire(0x0100);
    many_additionals[11] = 3;
    assert!(!doh::accept(&many_additionals));
}

// CoreDNS v1.15.0 plugin/pkg/dnsutil/ttl.go MinimalTTLWithMaximum.
#[test]
fn max_age_is_the_lowest_ttl_capped_at_one_hour() {
    assert_eq!(doh::max_age(&response_wire(&[300, 60, 600], &[]), 0), 60);
    assert_eq!(doh::max_age(&response_wire(&[86400], &[]), 0), 3600);
    assert_eq!(doh::max_age(&response_wire(&[300], &[30]), 0), 30);
    assert_eq!(doh::max_age(&response_wire(&[0], &[]), 0), 0);
}

#[test]
fn max_age_falls_back_to_five_seconds() {
    // No records at all, a SERVFAIL, and an unparsable body.
    assert_eq!(doh::max_age(&response_wire(&[], &[]), 0), 5);
    let mut servfail = response_wire(&[300], &[]);
    servfail[3] |= 2;
    assert_eq!(doh::max_age(&servfail, 0), 5);
    assert_eq!(doh::max_age(&[1, 2, 3], 0), 5);
}

#[test]
fn cache_control_names_the_max_age() {
    assert_eq!(doh::cache_control(0).to_str().unwrap(), "max-age=0");
    assert_eq!(doh::cache_control(3600).to_str().unwrap(), "max-age=3600");
}
