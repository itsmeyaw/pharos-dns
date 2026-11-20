use super::*;
use pharos_corefile::lex;

fn parse_text(text: &str) -> Result<Grpc, Error> {
    let tokens = lex("Corefile", text);
    parse(&mut Cursor::new("Corefile", &tokens), None)
}

fn name(text: &str) -> Name {
    text.parse().unwrap()
}

fn labels(grpc: &Grpc) -> Vec<&str> {
    grpc.upstreams.iter().map(|u| u.to.as_str()).collect()
}

// CoreDNS v1.15.0 plugin/grpc/setup_test.go TestSetup.
#[test]
fn setup_accepts_and_rejects_what_coredns_does() {
    for input in [
        "grpc . 127.0.0.1",
        "grpc . 127.0.0.1 {\nexcept miek.nl\n}\n",
        "grpc . 127.0.0.1:53",
        "grpc . 127.0.0.1:8080",
        "grpc . [::1]:53",
        "grpc . [2003::1]:53",
        "grpc . unix:///var/run/g.sock",
    ] {
        let grpc = parse_text(input).unwrap_or_else(|error| panic!("{input}: {error}"));
        assert_eq!(grpc.from, name("."), "{input}");
    }
    for (input, expected) in [
        ("grpc . a27.0.0.1", "not an IP"),
        ("grpc . 127.0.0.1 {\nblaatl\n}\n", "unknown property"),
        (
            "grpc xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 127.0.0.1",
            "unable to normalize 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
        ),
    ] {
        let error = parse_text(input).unwrap_err().to_string();
        assert!(error.contains(expected), "{input}: {error}");
    }
}

fn targets_of(grpc: &Grpc) -> Vec<&Target> {
    grpc.upstreams.iter().map(|u| &u.client.target).collect()
}

fn tcp(text: &str) -> Target {
    Target::Tcp(text.parse().unwrap())
}

fn host(host: &str, port: u16) -> Target {
    Target::Host {
        host: host.into(),
        port,
    }
}

// CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: an address without a port gets 53 and keeps its zone.
#[test]
fn addresses_default_to_port_53_and_keep_their_text() {
    let grpc = parse_text(
            "grpc . 127.0.0.1 [::1] 127.0.0.2:8080 fe80::1%eth0 [fe80::1%eth0] [fe80::2%2]:853 [0:0:0:0:0:0:0:1]:53 dns://10.0.0.1",
        )
        .unwrap();
    assert_eq!(
        labels(&grpc),
        [
            "127.0.0.1:53",
            "[::1]:53",
            "127.0.0.2:8080",
            "[fe80::1%eth0]:53",
            "[fe80::1%eth0]:53",
            "[fe80::2%2]:853",
            "[0:0:0:0:0:0:0:1]:53",
            "10.0.0.1:53",
        ]
    );
    assert_eq!(
        targets_of(&grpc),
        [
            &tcp("127.0.0.1:53"),
            &tcp("[::1]:53"),
            &tcp("127.0.0.2:8080"),
            &host("fe80::1%eth0", 53),
            &host("fe80::1%eth0", 53),
            &host("fe80::2%2", 853),
            &tcp("[::1]:53"),
            &tcp("10.0.0.1:53"),
        ]
    );
}

// CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: a scheme other than dns:// and unix:// passes setup and fails at dial.
#[test]
fn other_schemes_and_bad_ports_are_accepted_and_fail_at_dial() {
    let grpc = parse_text(
            "grpc . tls://127.0.0.1 grpc://127.0.0.1:8080 https://[::1] quic://10.0.0.1:853 https3://10.0.0.1 dns://127.0.0.1:53 127.0.0.1:99999 127.0.0.1:",
        )
        .unwrap();
    assert_eq!(
        labels(&grpc),
        [
            "tls://127.0.0.1:853",
            "grpc://127.0.0.1:8080",
            "https://[::1]:443",
            "quic://10.0.0.1:853",
            "",
            "dns://127.0.0.1:53",
            "127.0.0.1:99999",
            "127.0.0.1:",
        ]
    );
    assert!(
        targets_of(&grpc)
            .iter()
            .all(|target| matches!(target, Target::Invalid(_)))
    );
}

// CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: a port is not checked, so port 0 is accepted.
#[test]
fn port_zero_is_accepted() {
    let grpc = parse_text("grpc . 127.0.0.1:0").unwrap();
    assert_eq!(targets_of(&grpc), [&tcp("127.0.0.1:0")]);
}

#[test]
fn except_names_are_normalized() {
    let grpc =
        parse_text("grpc . 127.0.0.1 {\nexcept Miek.nl example.org.\nexcept a.b\n}").unwrap();
    assert_eq!(
        grpc.ignored,
        [name("miek.nl."), name("example.org."), name("a.b.")]
    );
    assert!(parse_text("grpc . 127.0.0.1 {\nexcept\n}").is_err());
}

// CoreDNS v1.15.0 plugin/grpc/setup_test.go TestSetupTLS.
#[test]
fn tls_options_are_accepted() {
    for input in [
        "grpc . 127.0.0.1 {\ntls_servername dns\n}",
        "grpc . 127.0.0.1 {\ntls\n}",
        "grpc . 127.0.0.1",
    ] {
        parse_text(input).unwrap_or_else(|error| panic!("{input}: {error}"));
    }
    for input in [
        "grpc . 127.0.0.1 {\ntls a b c d\n}",
        "grpc . 127.0.0.1 {\ntls_servername\n}",
        "grpc . 127.0.0.1 {\ntls_servername a b\n}",
        "grpc . 127.0.0.1 {\ntls /nonexistent/ca.pem\n}",
    ] {
        assert!(parse_text(input).is_err(), "accepted {input}");
    }
}

// CoreDNS v1.15.0 plugin/grpc/setup_test.go TestSetupResolvconf.
#[test]
fn resolv_conf_nameservers_become_upstreams() {
    let dir = std::env::temp_dir().join(format!("pharos-grpc-resolv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("resolv.conf");
    std::fs::write(
            &file,
            "# comment\nsearch example.org\nnameserver 10.10.255.252\nnameserver 10.10.255.253\nnameserver fe80::1%eth0\nnameserver dns.example.org\nnameserver 10.0.0.1:5\n",
        )
        .unwrap();
    let grpc = parse_text(&format!("grpc . {}", file.display())).unwrap();
    // CoreDNS v1.15.0 plugin/pkg/parse/host.go tryFile: the zone is dropped, and any other name is kept for the dial.
    assert_eq!(
        labels(&grpc),
        [
            "10.10.255.252:53",
            "10.10.255.253:53",
            "[fe80::1]:53",
            "dns.example.org:53",
            "[10.0.0.1:5]:53"
        ]
    );
    let targets = targets_of(&grpc);
    assert_eq!(targets[2], &tcp("[fe80::1]:53"));
    assert_eq!(targets[3], &host("dns.example.org", 53));
    assert!(matches!(targets[4], Target::Invalid(_)));
    std::fs::write(&file, "search example.org\n").unwrap();
    assert!(
        parse_text(&format!("grpc . {}", file.display()))
            .unwrap_err()
            .to_string()
            .contains("no nameservers found")
    );
    std::fs::remove_dir_all(dir).unwrap();
}

// CoreDNS v1.15.0 plugin/grpc/setup_test.go TestSetupFallthrough.
#[test]
fn fallthrough_zones() {
    let zones = |input: &str| parse_text(input).unwrap().fallthrough;
    assert_eq!(zones("grpc . 127.0.0.1 {\nfallthrough\n}"), [name(".")]);
    assert_eq!(
        zones("grpc . 127.0.0.1 {\nfallthrough example.org\n}"),
        [name("example.org.")]
    );
    assert_eq!(
        zones("grpc . 127.0.0.1 {\nfallthrough example.org example.com\n}"),
        [name("example.org."), name("example.com.")]
    );
    assert!(zones("grpc . 127.0.0.1").is_empty());
}

// CoreDNS v1.15.0 plugin/grpc/setup_policy_test.go TestSetupPolicy.
#[test]
fn policy_names() {
    for (policy, expected) in [
        ("random", Policy::Random),
        ("round_robin", Policy::RoundRobin),
        ("sequential", Policy::Sequential),
    ] {
        let grpc = parse_text(&format!("grpc . 127.0.0.1 {{\npolicy {policy}\n}}")).unwrap();
        assert_eq!(grpc.policy, expected);
    }
    assert_eq!(
        parse_text("grpc . 127.0.0.1").unwrap().policy,
        Policy::Random
    );
    assert!(
        parse_text("grpc . 127.0.0.1 {\npolicy random2\n}\n")
            .unwrap_err()
            .to_string()
            .contains("unknown policy")
    );
}

// CoreDNS v1.15.0 plugin/grpc/setup.go setup: at most 15 TOs.
#[test]
fn at_most_fifteen_upstreams() {
    let hosts = |count: usize| {
        (1..=count)
            .map(|i| format!("127.0.0.{i}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    assert!(parse_text(&format!("grpc . {}", hosts(15))).is_ok());
    assert!(
        parse_text(&format!("grpc . {}", hosts(16)))
            .unwrap_err()
            .to_string()
            .contains("more than 15 TOs configured: 16")
    );
}

#[test]
fn missing_arguments_and_unusable_addresses_fail() {
    for input in [
        "grpc",
        "grpc .",
        "grpc . unix://",
        "grpc . tls://",
        "grpc . localhost",
        "grpc . example.com:53",
        "grpc . 127.0.0.1 localhost",
    ] {
        assert!(parse_text(input).is_err(), "accepted {input}");
    }
}

// Go net.SplitHostPort.
#[test]
fn host_and_port_split_as_go_does() {
    for (input, expected) in [
        ("127.0.0.1:53", Some(("127.0.0.1", "53"))),
        ("[::1]:53", Some(("::1", "53"))),
        ("[fe80::1%eth0]:", Some(("fe80::1%eth0", ""))),
        ("127.0.0.1", None),
        ("::1", None),
        ("[::1]", None),
        ("[::1]x:53", None),
        ("[::1:53", None),
        ("a[b:53", None),
        ("a]b:53", None),
    ] {
        assert_eq!(split_host_port(input), expected, "{input}");
    }
}
