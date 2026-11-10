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
}
