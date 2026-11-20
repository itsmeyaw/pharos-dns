use super::{ServerBlockKey, go_lowercase, normalize_key};

fn key(transport: &str, domain: &str, port: &str) -> ServerBlockKey {
    ServerBlockKey {
        transport: transport.into(),
        domain: domain.into(),
        port: port.into(),
    }
}

#[test]
fn transport_and_port_defaults() {
    for (input, transport, port) in [
        (".", "dns", "53"),
        ("dns://Example.ORG", "dns", "53"),
        ("tls://Example.ORG.", "tls", "853"),
        ("quic://example.org", "quic", "853"),
        ("grpc://example.org", "grpc", "443"),
        ("https://example.org", "https", "443"),
        ("https3://example.org", "https3", "443"),
        ("unix://example.org", "unix", ""),
    ] {
        let domain = if input == "." { "." } else { "example.org." };
        assert_eq!(
            normalize_key(input).unwrap(),
            [key(transport, domain, port)],
            "{input}"
        );
    }
}

#[test]
fn numeric_ports_are_canonicalized_without_range_validation() {
    for (input, domain, port) in [
        ("Example.Org:0053", "example.org.", "53"),
        ("example.org:+53", "example.org.", "53"),
        ("example.org:-1", "example.org.", "-1"),
        ("example.org:99999", "example.org.", "99999"),
        ("example.org:http", "example.org:http.", "53"),
        ("unknown://Example.org", "unknown://example.org.", "53"),
        ("2001:db8::1", "2001:db8:.", "1"),
    ] {
        assert_eq!(
            normalize_key(input).unwrap(),
            [key("dns", domain, port)],
            "{input}"
        );
    }
}

#[test]
fn expands_ipv4_networks_on_octet_boundaries() {
    assert_eq!(
        normalize_key("10.0.0.0/8:53").unwrap(),
        [key("dns", "10.in-addr.arpa.", "53")]
    );
    assert_eq!(
        normalize_key("tls://192.168.1.1/23:0054").unwrap(),
        [
            key("tls", "0.168.192.in-addr.arpa.", "54"),
            key("tls", "1.168.192.in-addr.arpa.", "54"),
        ]
    );
    let expanded = normalize_key("10.9.3.0/18").unwrap();
    assert_eq!(expanded.len(), 64);
    assert_eq!(expanded[0], key("dns", "0.9.10.in-addr.arpa.", "53"));
    assert_eq!(expanded[63], key("dns", "63.9.10.in-addr.arpa.", "53"));
    assert_eq!(
        normalize_key("0.0.0.0/0").unwrap(),
        [key("dns", "in-addr.arpa.", "53")]
    );
}

#[test]
fn expands_ipv6_networks_on_nibble_boundaries() {
    assert_eq!(
        normalize_key("2001:db8::/31").unwrap(),
        [
            key("dns", "8.b.d.0.1.0.0.2.ip6.arpa.", "53"),
            key("dns", "9.b.d.0.1.0.0.2.ip6.arpa.", "53"),
        ]
    );
    let expanded = normalize_key("2001:db8::/29:853").unwrap();
    assert_eq!(expanded.len(), 8);
    assert_eq!(expanded[7], key("dns", "f.b.d.0.1.0.0.2.ip6.arpa.", "853"));
    assert_eq!(
        normalize_key("::1/128").unwrap_err(),
        "invalid CIDR ::1/128"
    );
    assert_eq!(
        normalize_key("0:1::/32").unwrap_err(),
        "invalid CIDR 0:1::/32"
    );
    assert_eq!(
        normalize_key("2001:db8::/0").unwrap(),
        [key("dns", "ip6.arpa.", "53")]
    );
}

#[test]
fn go_lowercase_preserves_all_coredns_unicode_exclusions() {
    let mut codepoints = vec![
        0x1c89, 0xa7cb, 0xa7cc, 0xa7ce, 0xa7d2, 0xa7d4, 0xa7da, 0xa7dc,
    ];
    codepoints.extend(0x10d50..=0x10d65);
    codepoints.extend(0x16ea0..=0x16eb8);
    assert_eq!(codepoints.len(), 55);

    for codepoint in codepoints {
        let character = char::from_u32(codepoint).unwrap();
        assert_ne!(
            character.to_lowercase().next(),
            Some(character),
            "U+{codepoint:04X}"
        );
        assert_eq!(go_lowercase(character), character, "U+{codepoint:04X}");
    }
}

#[test]
fn unicode_server_block_domains_use_escaped_octet_presentation() {
    // RFC 4343 §2.1: UTF-8 name octets use three-digit decimal escapes in ASCII presentation.
    assert_eq!(
        normalize_key("MÜNICH.Example.").unwrap(),
        [key("dns", r"m\195\188nich.example.", "53")]
    );
}

#[test]
fn trailing_dot_and_invalid_cidr_remain_domains() {
    for (input, domain) in [
        ("10.0.0.0/8.", "10.0.0.0/8."),
        ("2001:db8::/32.", "2001:db8::/32."),
        ("10.0.0.0/99", "10.0.0.0/99."),
        ("10.0.0/8", "10.0.0/8."),
    ] {
        assert_eq!(
            normalize_key(input).unwrap(),
            [key("dns", domain, "53")],
            "{input}"
        );
    }
}

#[test]
fn validates_domain_names_like_coredns() {
    for input in ["", "dns://", "example:", ".example", "a..b", "a\\", "ȶ\\."] {
        assert!(normalize_key(input).is_err(), "{input:?}");
    }
    assert!(normalize_key(&format!("{}.example", "a".repeat(64))).is_err());
    assert!(normalize_key(&"a".repeat(256)).is_err());
    assert_eq!(
        normalize_key("A\\.B.Example").unwrap(),
        [key("dns", "a\\.b.example.", "53")]
    );
    assert_eq!(normalize_key("A\\.").unwrap(), [key("dns", "a\\..", "53")]);
    assert_eq!(
        normalize_key("AİᲉ\u{10d50}\u{16ea0}").unwrap(),
        [key(
            "dns",
            r"ai\225\178\137\240\144\181\144\240\150\186\160.",
            "53"
        )]
    );
}

#[test]
fn enforces_corefile_presentation_cap_and_wire_limits() {
    let escaped = |lengths: &[usize]| {
        lengths
            .iter()
            .map(|length| "\\065".repeat(*length))
            .collect::<Vec<_>>()
            .join(".")
    };
    let escaped_label = escaped(&[63]);
    assert_eq!(
        normalize_key(&escaped_label).unwrap()[0].domain,
        format!("{escaped_label}.")
    );
    assert!(normalize_key(r"\255").is_ok());
    assert!(normalize_key(r"\999").is_err());
    assert_eq!(normalize_key(r"a\\").unwrap(), [key("dns", r"a\\.", "53")]);

    let max_wire_length = [
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(61),
    ]
    .join(".");
    assert_eq!(
        normalize_key(&max_wire_length).unwrap()[0].domain,
        format!("{max_wire_length}.")
    );
    let overlong_wire_name = [
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(62),
    ]
    .join(".");
    assert!(normalize_key(&overlong_wire_name).is_err());

    let wire_257_name = vec!["a".repeat(63); 4].join(".");
    assert!(normalize_key(&wire_257_name).is_err());

    // ADR 0003: CoreDNS rejects long presentation strings before counting wire octets.
    assert!(normalize_key(&escaped(&[63, 63, 63, 61])).is_err());
}
