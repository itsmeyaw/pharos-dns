use super::*;
use pharos_corefile::{Cursor, lex};
use std::time::Duration;

fn parse_text(text: &str) -> Result<Config, pharos_corefile::Error> {
    let tokens = lex("Corefile", text);
    parse(&mut Cursor::new("Corefile", &tokens), None)
}

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

fn tls(address: &str, server_name: Option<&str>) -> Target {
    Target::Tls {
        address: address.parse().unwrap(),
        server_name: server_name.map(str::to_owned),
        quic: false,
    }
}

fn quic(address: &str, server_name: Option<&str>) -> Target {
    Target::Tls {
        address: address.parse().unwrap(),
        server_name: server_name.map(str::to_owned),
        quic: true,
    }
}

#[test]
fn defaults_and_numeric_upstreams() {
    let config = parse_text("forward Example.ORG 127.0.0.1 dns://[::1]:5353").unwrap();
    assert_eq!(config.from, "example.org.");
    assert_eq!(
        config.upstreams,
        [
            Target::Address("127.0.0.1:53".parse().unwrap()),
            Target::Address("[::1]:5353".parse().unwrap())
        ]
    );
    assert_eq!(config.max_fails, 2);
    assert_eq!(config.expire, Duration::from_secs(10));
    assert_eq!(config.health_interval, Duration::from_millis(500));
    assert!(config.health_recursion_desired);
    assert_eq!(config.health_domain, ".");
    assert_eq!(config.policy, Policy::Random);
    assert_eq!(config.max_connect_attempts, None);
}

#[test]
fn parses_options_and_preserves_zero_attempts() {
    let config = parse_text("forward . 192.0.2.1 {\nexcept example.org 10.0.0.0/8\nforce_tcp\nprefer_udp\nexpire 1m2.5s\nmax_age 90s\nmax_idle_conns 4\nread_timeout 3s\nmax_fails 0\nmax_connect_attempts 0\npolicy round_robin\nhealth_check 250ms no_rec domain Example.org\nmax_concurrent 10\nnext NXDOMAIN servfail\nnext_on_nodata\nallow_special\nfailover REFUSED\nfailfast_all_unhealthy_upstreams\nsource_address 192.0.2.9\n}").unwrap();
    assert_eq!(config.except, ["example.org.", "10.in-addr.arpa."]);
    assert!(config.force_tcp && config.prefer_udp);
    assert_eq!(config.expire, Duration::from_millis(62500));
    assert_eq!(config.max_age, Duration::from_secs(90));
    assert_eq!(config.max_idle_conns, 4);
    assert_eq!(config.read_timeout, Duration::from_secs(3));
    assert_eq!(config.max_fails, 0);
    assert_eq!(config.max_connect_attempts, Some(0));
    assert_eq!(config.policy, Policy::RoundRobin);
    assert_eq!(config.health_interval, Duration::from_millis(250));
    assert!(!config.health_recursion_desired);
    assert_eq!(config.health_domain, "example.org.");
    assert_eq!(config.max_concurrent, 10);
    assert_eq!(config.next, [3, 2]);
    assert!(config.next_on_nodata && config.failfast_all_unhealthy_upstreams);
    assert!(config.allow_special);
    assert_eq!(config.failover, [5]);
    assert_eq!(config.source_address, Some("192.0.2.9".parse().unwrap()));
}

#[test]
fn rejects_invalid_options_and_encrypted_transports() {
    for text in [
        "forward .",
        "forward . invalid..domain",
        "forward . grpc://1.1.1.1",
        "forward . unix:///run/dns.sock",
        "forward . 1.1.1.1 {\nunknown x\n}",
        "forward . 1.1.1.1 {\nforce_tcp x\n}",
        "forward . 1.1.1.1 {\nallow_special x\n}",
        "forward . 1.1.1.1 {\nhealth_check -1s\n}",
        "forward . 1.1.1.1 {\nhealth_check 1s domain a..b\n}",
        "forward . 1.1.1.1 {\nhealth_check 1s nonsense\n}",
        "forward . 1.1.1.1 {\nmax_fails -1\n}",
        "forward . 1.1.1.1 {\nmax_fails +1\n}",
        "forward . 1.1.1.1 {\nmax_connect_attempts +1\n}",
        "forward . 1.1.1.1 {\nmax_concurrent -1\n}",
        "forward . 1.1.1.1 {\nfailover NOERROR\n}",
        "forward . 1.1.1.1 {\nnext INVALID\n}",
        "forward . 1.1.1.1 {\nexpire 10s\nmax_age 9s\n}",
        "forward . 1.1.1.1 {\nread_timeout 0\n}",
    ] {
        assert!(parse_text(text).is_err(), "accepted {text}");
    }
    assert!(
        parse_text("forward . grpc://1.1.1.1")
            .unwrap_err()
            .to_string()
            .contains("grpc Upstreams are not supported")
    );
}

// CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: `quic://` defaults to port 853.
#[test]
fn quic_upstreams_default_to_port_853() {
    let config = parse_text(
            "forward . quic://9.9.9.9 quic://[2620:fe::fe]:8853 quic://[::1] quic://127.0.0.1%Example.net:854",
        )
        .unwrap();
    assert_eq!(
        config.upstreams,
        [
            quic("9.9.9.9:853", None),
            quic("[2620:fe::fe]:8853", None),
            quic("[::1]:853", None),
            quic("127.0.0.1:854", Some("example.net")),
        ]
    );
}

// CoreDNS v1.15.0 plugin/forward/setup.go: `tls_servername` covers `quic://` and conflicts with its zone.
#[test]
fn tls_servername_applies_to_quic_upstreams() {
    let config =
        parse_text("forward . quic://127.0.0.1 tls://127.0.0.2 {\ntls_servername dns.example\n}")
            .unwrap();
    assert_eq!(
        config.upstreams,
        [quic("127.0.0.1:853", None), tls("127.0.0.2:853", None)]
    );
    assert_eq!(
        parse_text("forward . quic://127.0.0.3%Other {\ntls_servername dns.example\n}")
            .unwrap_err()
            .to_string(),
        "Corefile:3: both forward ('dns.example') and proxy level ('other') TLS servernames are set for upstream proxy 'quic://127.0.0.3:853'"
    );
}

#[test]
fn dns_tls_and_quic_upstreams_at_one_address_stay_distinct() {
    let config = parse_text("forward . tls://127.0.0.1 quic://127.0.0.1 quic://127.0.0.1").unwrap();
    assert_eq!(
        config.upstreams,
        [tls("127.0.0.1:853", None), quic("127.0.0.1:853", None)]
    );
}

// CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: `tls://` defaults to port 853.
#[test]
fn tls_upstreams_default_to_port_853() {
    let config =
        parse_text("forward . tls://9.9.9.9 tls://[2620:fe::fe]:8853 tls://[::1]").unwrap();
    assert_eq!(
        config.upstreams,
        [
            tls("9.9.9.9:853", None),
            tls("[2620:fe::fe]:8853", None),
            tls("[::1]:853", None),
        ]
    );
}

// CoreDNS v1.15.0 plugin/forward/setup_test.go TestSplitZone, TestSetupTLS.
#[test]
fn tls_endpoint_zone_sets_the_server_name() {
    let config = parse_text(
            "forward . tls://127.0.0.1%Example.net:854 tls://127.0.0.2%example.net tls://[fe80::1%example.com] tls://[2400:3200::1%dns.alidns.com]:853",
        )
        .unwrap();
    assert_eq!(
        config.upstreams,
        [
            tls("127.0.0.1:854", Some("example.net")),
            tls("127.0.0.2:853", Some("example.net")),
            tls("[fe80::1]:853", Some("example.com")),
            tls("[2400:3200::1]:853", Some("dns.alidns.com")),
        ]
    );
}

// CoreDNS v1.15.0 plugin/forward/setup_test.go TestSetupTLS.
#[test]
fn tls_servername_applies_to_every_tls_upstream_only() {
    let config = parse_text(
        "forward . tls://127.0.0.1 127.0.0.2 tls://127.0.0.3%Other {\ntls_servername dns.example\n}",
    );
    assert_eq!(
        config.unwrap_err().to_string(),
        "Corefile:3: both forward ('dns.example') and proxy level ('other') TLS servernames are set for upstream proxy 'tls://127.0.0.3:853'"
    );
    let config =
        parse_text("forward . tls://127.0.0.1 127.0.0.2 {\ntls_servername dns.example\n}").unwrap();
    assert_eq!(
        config.upstreams,
        [
            tls("127.0.0.1:853", None),
            Target::Address("127.0.0.2:53".parse().unwrap()),
        ]
    );
    assert_eq!(config.tls_servername.as_deref(), Some("dns.example"));
}

fn https(address: &str, server_name: Option<&str>) -> Target {
    Target::Https {
        address: address.parse().unwrap(),
        server_name: server_name.map(str::to_owned),
    }
}

// CoreDNS v1.15.0 plugin/forward/setup_test.go TestSetupForward: `https://` defaults to port 443.
#[test]
fn https_upstreams_default_to_port_443_and_take_a_zone_as_server_name() {
    let config = parse_text(
            "forward . https://127.0.0.1 https://127.0.0.1%example.net:8443 https://[::1%example.net]:443 https://127.0.0.1",
        )
        .unwrap();
    assert_eq!(
        config.upstreams,
        [
            https("127.0.0.1:443", None),
            https("127.0.0.1:8443", Some("example.net")),
            https("[::1]:443", Some("example.net")),
        ]
    );
    assert_eq!(config.doh_method, "POST");
}

// CoreDNS v1.15.0 plugin/forward/setup_test.go TestSetupForward: paths are not allowed in HTTPS Upstreams.
#[test]
fn https_upstreams_reject_paths() {
    for text in [
        "forward . https://1.1.1.1/",
        "forward . https://1.1.1.1/dns-query",
        "forward . https://1.1.1.1:443/x",
    ] {
        let to = text.trim_start_matches("forward . ");
        assert_eq!(
            parse_text(text).unwrap_err().to_string(),
            format!(
                "Corefile:1: paths are not allowed in HTTPS upstream addresses (the /dns-query path is used by default): {to}"
            ),
            "{text}"
        );
    }
}

// CoreDNS v1.15.0 plugin/forward/setup.go: a proxy-level server name conflicts with `tls_servername` for HTTPS too.
#[test]
fn tls_servername_conflicts_with_an_https_zone() {
    let error = parse_text("forward . https://127.0.0.1%Other {\ntls_servername dns.example\n}")
        .unwrap_err()
        .to_string();
    assert_eq!(
        error,
        "Corefile:3: both forward ('dns.example') and proxy level ('other') TLS servernames are set for upstream proxy 'https://127.0.0.1:443'"
    );
    assert!(
        parse_text("forward . https://127.0.0.1 {\ntls_servername dns.example\ndoh_method GET\n}")
            .is_ok()
    );
}

#[test]
fn dns_zone_is_a_scope_not_a_server_name() {
    let config =
        parse_text("forward . 127.0.0.1%eth0 dns://127.0.0.1%eth1 {\ntls_servername dns\n}")
            .unwrap();
    assert_eq!(
        config.upstreams,
        [Target::Address("127.0.0.1:53".parse().unwrap())]
    );
}

// CoreDNS v1.15.0 plugin/forward/resolve.go dedupKey: transport and server name keep upstreams distinct.
#[test]
fn dns_and_tls_upstreams_at_one_address_stay_distinct() {
    let config = parse_text("forward . 127.0.0.1:853 tls://127.0.0.1 tls://127.0.0.1 tls://127.0.0.1%A tls://127.0.0.1%a tls://127.0.0.1%b").unwrap();
    assert_eq!(
        config.upstreams,
        [
            Target::Address("127.0.0.1:853".parse().unwrap()),
            tls("127.0.0.1:853", None),
            tls("127.0.0.1:853", Some("a")),
            tls("127.0.0.1:853", Some("b")),
        ]
    );
}

// CoreDNS v1.15.0 plugin/forward/setup_test.go TestSetupTLS: the options are accepted without a TLS upstream.
#[test]
fn tls_options_are_accepted_for_plain_upstreams() {
    assert!(parse_text("forward . 127.0.0.1 {\ntls\ntls_servername dns\n}").is_ok());
    assert!(parse_text("forward . tls://127.0.0.1%example.net {\ntls\n}").is_ok());
}

// CoreDNS v1.15.0 plugin/pkg/tls/tls.go NewTLSConfigFromArgs: zero to three arguments.
#[test]
fn tls_option_takes_ca_or_cert_key_and_optional_ca() {
    let ca = format!("{FIXTURES}/ca.pem");
    let cert = format!("{FIXTURES}/client.pem");
    let key = format!("{FIXTURES}/client.key.pem");
    assert!(
        parse_text("forward . tls://127.0.0.1 {\ntls\n}")
            .unwrap()
            .tls_client
            .is_none()
    );
    for line in [
        format!("tls {ca}"),
        format!("tls {cert} {key}"),
        format!("tls {cert} {key} {ca}"),
    ] {
        let config = parse_text(&format!("forward . tls://127.0.0.1 {{\n{line}\n}}"))
            .unwrap_or_else(|error| panic!("{line}: {error}"));
        assert!(config.tls_client.is_some(), "{line}");
    }
}

#[test]
fn tls_option_rejects_bad_arguments_and_files() {
    let ca = format!("{FIXTURES}/ca.pem");
    let key = format!("{FIXTURES}/client.key.pem");
    let missing = format!("{FIXTURES}/missing.pem");
    for line in [
        format!("tls {ca} {ca} {ca} {ca}"),
        format!("tls {missing}"),
        format!("tls {ca} {key} {ca}"),
        format!("tls {ca} {missing}"),
        format!("tls {key}"),
    ] {
        assert!(
            parse_text(&format!("forward . 127.0.0.1 {{\n{line}\n}}")).is_err(),
            "accepted {line}"
        );
    }
}

// CoreDNS v1.15.0 plugin/forward/setup.go parseBlock: relative `tls` paths join the `root`.
#[test]
fn tls_option_paths_resolve_against_root() {
    let tokens = lex("Corefile", "forward . tls://127.0.0.1 {\ntls ca.pem\n}");
    let root = std::path::Path::new(FIXTURES);
    let config = parse(&mut Cursor::new("Corefile", &tokens), Some(root)).unwrap();
    assert!(config.tls_client.is_some());
    assert!(parse_text("forward . tls://127.0.0.1 {\ntls ca.pem\n}").is_err());
}

#[test]
fn duration_units_and_bounds() {
    assert_eq!(duration("1h2m3.5s"), Some(Duration::from_millis(3_723_500)));
    assert_eq!(duration("0"), Some(Duration::ZERO));
    assert_eq!(duration("1us"), Some(Duration::from_micros(1)));
    assert_eq!(duration("1µs"), Some(Duration::from_micros(1)));
    assert_eq!(duration("-0.0s"), Some(Duration::ZERO));
    for bad in ["-1s", "1", "NaNs", "1s2", "999999999999999999999h"] {
        assert_eq!(duration(bad), None, "{bad}");
    }
}

#[test]
fn coredns_rcodes_and_bracketed_ipv6() {
    let config = parse_text("forward . [::1] {\nnext notimpl DSOTYPENI\n}").unwrap();
    assert_eq!(
        config.upstreams,
        [Target::Address("[::1]:53".parse().unwrap())]
    );
    assert_eq!(config.next, [4, 11]);
    assert!(parse_text("forward . 1.1.1.1 {\nnext BADVERS\n}").is_err());
}

#[test]
fn successive_directives_share_cursor() {
    let tokens = lex(
        "Corefile",
        "forward . 192.0.2.1 {\npolicy sequential\n}\nforward example.org 192.0.2.2",
    );
    let mut cursor = Cursor::new("Corefile", &tokens);
    assert_eq!(parse(&mut cursor, None).unwrap().policy, Policy::Sequential);
    assert_eq!(parse(&mut cursor, None).unwrap().from, "example.org.");
}

#[test]
fn reads_resolv_conf_and_deduplicates() {
    let path = std::env::temp_dir().join(format!("pharos-forward-{}.conf", std::process::id()));
    std::fs::write(
        &path,
        "# comment\nnameserver 192.0.2.1\nnameserver ::1\nnameserver 192.0.2.1\n",
    )
    .unwrap();
    let config = parse_text(&format!("forward . {} 192.0.2.1", path.display())).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(
        config.upstreams,
        [
            Target::Address("192.0.2.1:53".parse().unwrap()),
            Target::Address("[::1]:53".parse().unwrap())
        ]
    );
}

#[test]
fn upstream_limit_counts_nonempty_entries_not_expanded_addresses() {
    let path =
        std::env::temp_dir().join(format!("pharos-forward-many-{}.conf", std::process::id()));
    let nameservers = (1..=16)
        .map(|i| format!("nameserver 192.0.2.{i}\n"))
        .collect::<String>();
    std::fs::write(&path, nameservers).unwrap();
    let config = parse_text(&format!("forward . {}", path.display())).unwrap();
    assert_eq!(config.upstreams.len(), 16);
    std::fs::write(&path, "# empty\n").unwrap();
    let empty_files = vec![path.to_string_lossy().to_string(); 16].join(" ");
    assert!(parse_text(&format!("forward . {empty_files} 192.0.2.1")).is_ok());
    let addresses = (1..=16)
        .map(|i| format!("192.0.2.{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(parse_text(&format!("forward . {addresses}")).is_err());
    let fifteen = (1..=15)
        .map(|i| format!("192.0.2.{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    assert!(parse_text(&format!("forward . {fifteen}")).is_ok());
    std::fs::write(&path, "nameserver 192.0.2.20\n").unwrap();
    assert!(parse_text(&format!("forward . {} {fifteen}", path.display())).is_err());
    std::fs::remove_file(path).unwrap();
}

#[test]
fn scoped_and_invalid_resolv_conf_nameservers_follow_coredns() {
    let path =
        std::env::temp_dir().join(format!("pharos-forward-scoped-{}.conf", std::process::id()));
    std::fs::write(&path, "nameserver fe80::1%eth0\nnameserver #\nnameserver\n").unwrap();
    let config = parse_text(&format!("forward . {}", path.display())).unwrap();
    assert_eq!(
        config.upstreams,
        [
            Target::Address("[fe80::1]:53".parse().unwrap()),
            Target::Invalid("#:53".into())
        ]
    );
    let config = parse_text("forward . [fe80::1%eth0]:5300").unwrap();
    assert_eq!(
        config.upstreams,
        [Target::Address("[fe80::1]:5300".parse().unwrap())]
    );
    let config = parse_text("forward . 127.0.0.1%eth0:5300").unwrap();
    assert_eq!(
        config.upstreams,
        [Target::Address("127.0.0.1:5300".parse().unwrap())]
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn hostname_upstream_uses_configured_resolver_at_setup() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let address = socket.local_addr().unwrap();
    let resolver = std::thread::spawn(move || {
        let mut wire = [0; 512];
        for expected_type in [1, 28] {
            let (len, peer) = socket.recv_from(&mut wire).unwrap();
            let query = pharos_proto::Message::parse(&wire[..len]).unwrap();
            let question = query.questions().next().unwrap();
            assert_eq!(question.name.to_string(), "upstream.example.");
            assert_eq!(question.qtype.0, expected_type);
            assert!(query.rd());
            wire[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            let mut response = wire[..len].to_vec();
            if expected_type == 1 {
                response[6..8].copy_from_slice(&1_u16.to_be_bytes());
                response
                    .extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 42]);
            }
            socket.send_to(&response, peer).unwrap();
        }
    });
    let config = parse_text(&format!(
        "forward . upstream.example:5300 {{\n resolver {address}\n}}"
    ))
    .unwrap();
    assert_eq!(
        config.upstreams,
        [Target::Address("127.0.0.42:5300".parse().unwrap())]
    );
    resolver.join().unwrap();
}
