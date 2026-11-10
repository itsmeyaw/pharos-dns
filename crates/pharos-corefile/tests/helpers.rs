use pharos_corefile::{Fallthrough, normalize_domain, origins_from_args_or_server_block};

#[test]
fn origins_prefer_arguments_and_expand_networks() {
    assert_eq!(normalize_domain("TLS://bad:"), Vec::<String>::new());
    assert_eq!(normalize_domain("tls://Example.COM:853"), ["example.com."]);
    assert_eq!(
        origins_from_args_or_server_block(&["10.0.0.0/15", "bad:"], &["other"]),
        ["0.10.in-addr.arpa.", "1.10.in-addr.arpa."]
    );
    assert_eq!(
        origins_from_args_or_server_block(&[], &["10.0.0.0/15", "bad:"]),
        ["0.10.in-addr.arpa.", "bad:"]
    );
    assert!(origins_from_args_or_server_block(&["bad:"], &["other"]).is_empty());
}

#[test]
fn fallthrough_matches_domains_at_label_boundaries() {
    let mut fall = Fallthrough::default();
    assert!(!fall.through("anything.example."));
    fall.set_domains_from_args(&[]);
    assert!(fall.through("anything.example."));
    fall.set_domains_from_args(&["EXAMPLE.COM", "bad:"]);
    assert!(fall.through("a.example.com."));
    assert!(fall.through("example.com."));
    assert!(!fall.through("notexample.com."));
    assert!(!fall.through("example.net."));
    assert_eq!(
        fall,
        Fallthrough {
            domains: vec!["example.com.".into()]
        }
    );
    assert_ne!(fall, Fallthrough::default());
    assert!(!fall.through("x\\.example.com."));
    assert!(fall.through("x\\\\.example.com."));
}

#[test]
fn coredns_normalize_exact_fixtures() {
    for (host, expected) in [
        (".:53", vec!["."]),
        ("example.org:53", vec!["example.org."]),
        ("example.org.:53", vec!["example.org."]),
        ("dns://example.org", vec!["example.org."]),
        ("10.0.0.0/8:53", vec!["10.in-addr.arpa."]),
        (
            "10.0.0.0/15",
            vec!["0.10.in-addr.arpa.", "1.10.in-addr.arpa."],
        ),
        ("::fFFF:B:F/115", vec![]),
        (
            "2001:db8::/112",
            vec!["0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."],
        ),
        (
            "2001:db8::/108",
            vec!["0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."],
        ),
    ] {
        assert_eq!(normalize_domain(host), expected, "{host}");
    }
    for (prefix, count) in [(29, 8), (30, 4), (113, 8), (114, 4), (115, 2)] {
        let domains = normalize_domain(&format!("2001:db8::/{prefix}"));
        assert_eq!(domains.len(), count);
        let first = if prefix <= 30 {
            "8.b.d.0.1.0.0.2.ip6.arpa."
        } else {
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        };
        assert_eq!(domains[0], first);
    }
    let domains = normalize_domain("10.9.3.0/18");
    assert_eq!(domains.len(), 64);
    assert_eq!(
        &domains[..3],
        [
            "0.9.10.in-addr.arpa.",
            "1.9.10.in-addr.arpa.",
            "2.9.10.in-addr.arpa."
        ]
    );
}
