//! Ported from CoreDNS v1.15.0 plugin/dnstap/setup_test.go.
use super::*;
use crate::dnstap::{Endpoint, Role, TlsFiles};
use pharos_corefile::{Cursor, lex};

fn parse_text(text: &str) -> Result<Vec<Config>, Error> {
    let tokens = lex("Corefile", text);
    parse(&mut Cursor::new("Corefile", &tokens))
}

fn hostname() -> Vec<u8> {
    nix::unistd::gethostname()
        .map(|name| name.into_encoded_bytes())
        .unwrap_or_default()
}

fn expect(role: Role, endpoint: Endpoint) -> Config {
    Config {
        role,
        endpoint,
        full: false,
        write_buffer: 1,
        queue: 1,
        identity: hostname(),
        version: DEFAULT_VERSION.as_bytes().to_vec(),
        extra: String::new(),
        skip_verify: false,
        tls: None,
    }
}

fn unix(path: &str) -> Config {
    expect(Role::Dial, Endpoint::Unix(path.to_owned()))
}

fn tcp(address: &str) -> Config {
    expect(Role::Dial, Endpoint::Tcp(address.to_owned()))
}

fn listen(endpoint: Endpoint) -> Config {
    expect(Role::Listen, endpoint)
}

fn full(config: Config) -> Config {
    Config {
        full: true,
        ..config
    }
}

fn named(config: Config, identity: &str, version: &str, extra: &str) -> Config {
    Config {
        identity: identity.as_bytes().to_vec(),
        version: version.as_bytes().to_vec(),
        extra: extra.to_owned(),
        ..config
    }
}

#[test]
fn parses_endpoints_and_options() {
    let tls_listener = |config: Config| Config {
        tls: Some(TlsFiles {
            cert: "/path/to/cert.pem".to_owned(),
            key: "/path/to/key.pem".to_owned(),
            ca: None,
        }),
        ..config
    };
    let cases: Vec<(&str, Vec<Config>)> = vec![
        ("dnstap dnstap.sock full", vec![full(unix("dnstap.sock"))]),
        ("dnstap unix://dnstap.sock", vec![unix("dnstap.sock")]),
        ("dnstap tcp://127.0.0.1:6000", vec![tcp("127.0.0.1:6000")]),
        ("dnstap tcp://[::1]:6000", vec![tcp("[::1]:6000")]),
        (
            "dnstap tcp://example.com:6000",
            vec![tcp("example.com:6000")],
        ),
        (
            "dnstap dnstap.sock full {\nidentity NAME\nversion VER\n}\n",
            vec![named(full(unix("dnstap.sock")), "NAME", "VER", "")],
        ),
        (
            "dnstap dnstap.sock full {\nidentity NAME\nversion VER\nextra EXTRA\n}\n",
            vec![named(full(unix("dnstap.sock")), "NAME", "VER", "EXTRA")],
        ),
        (
            "dnstap dnstap.sock {\nidentity NAME\nversion VER\nextra EXTRA\n}\n",
            vec![named(unix("dnstap.sock"), "NAME", "VER", "EXTRA")],
        ),
        (
            "dnstap dnstap.sock full {\n                identity NAME\n                version VER\n                extra EXTRA\n              }\n              dnstap tcp://127.0.0.1:6000 {\n                identity NAME2\n                version VER2\n                extra EXTRA2\n              }",
            vec![
                named(full(unix("dnstap.sock")), "NAME", "VER", "EXTRA"),
                named(tcp("127.0.0.1:6000"), "NAME2", "VER2", "EXTRA2"),
            ],
        ),
        (
            "dnstap tls://127.0.0.1:6000",
            vec![expect(
                Role::Dial,
                Endpoint::Tls("127.0.0.1:6000".to_owned()),
            )],
        ),
        (
            "dnstap dnstap.sock full 1024 2048",
            vec![Config {
                write_buffer: 1024,
                queue: 2048,
                ..full(unix("dnstap.sock"))
            }],
        ),
        (
            "dnstap listen tcp://127.0.0.1:6000",
            vec![listen(Endpoint::Tcp("127.0.0.1:6000".to_owned()))],
        ),
        (
            "dnstap listen tcp://127.0.0.1:6000 full",
            vec![full(listen(Endpoint::Tcp("127.0.0.1:6000".to_owned())))],
        ),
        (
            "dnstap listen unix:///tmp/dnstap.sock",
            vec![listen(Endpoint::Unix("/tmp/dnstap.sock".to_owned()))],
        ),
        (
            "dnstap listen /tmp/dnstap.sock full",
            vec![full(listen(Endpoint::Unix("/tmp/dnstap.sock".to_owned())))],
        ),
        (
            "dnstap listen tls://127.0.0.1:6000 full {\ntls /path/to/cert.pem /path/to/key.pem\n}\n",
            vec![tls_listener(full(listen(Endpoint::Tls(
                "127.0.0.1:6000".to_owned(),
            ))))],
        ),
        (
            "dnstap listen tls://127.0.0.1:6000 {\ntls /path/to/cert.pem /path/to/key.pem /path/to/ca.pem\n}\n",
            vec![Config {
                tls: Some(TlsFiles {
                    cert: "/path/to/cert.pem".to_owned(),
                    key: "/path/to/key.pem".to_owned(),
                    ca: Some("/path/to/ca.pem".to_owned()),
                }),
                ..listen(Endpoint::Tls("127.0.0.1:6000".to_owned()))
            }],
        ),
        (
            "dnstap listen tls://127.0.0.1:6000 {\ntls /path/to/cert.pem /path/to/key.pem\nskipverify\n}\n",
            vec![Config {
                skip_verify: true,
                ..tls_listener(listen(Endpoint::Tls("127.0.0.1:6000".to_owned())))
            }],
        ),
        (
            "dnstap tcp://remote.example.com:6000 full\n              dnstap listen tcp://127.0.0.1:6001",
            vec![
                full(tcp("remote.example.com:6000")),
                listen(Endpoint::Tcp("127.0.0.1:6001".to_owned())),
            ],
        ),
    ];
    for (text, expected) in cases {
        assert_eq!(parse_text(text).unwrap(), expected, "{text}");
    }
}

#[test]
fn rejects_invalid_directives() {
    for text in [
        "dnstap",
        "dnstap {\nidentity NAME\nversion VER\nextra EXTRA\n}\n",
        "dnstap dnstap.sock {\nidentity\n}\n",
        "dnstap dnstap.sock {\nversion\n}\n",
        "dnstap dnstap.sock {\nextra\n}\n",
        "dnstap dnstap.sock {\nidentitiy NAME\n}\n",
        "dnstap dnstap.sock full 1025 1",
        "dnstap dnstap.sock full 1 4097",
        "dnstap dnstap.sock full 0 10",
        "dnstap dnstap.sock full 10 0",
        "dnstap dnstap.sock full x 10",
        "dnstap dnstap.sock full 10 y",
        "dnstap listen",
        "dnstap listen tcp://127.0.0.1:6000 {\ntls /path/to/cert.pem\n}\n",
    ] {
        assert!(parse_text(text).is_err(), "accepted {text:?}");
    }
}

#[test]
fn reports_coredns_errors() {
    for (text, message) in [
        (
            "dnstap",
            "Corefile:1: Wrong argument count or unexpected line ending after 'dnstap'",
        ),
        (
            "dnstap listen",
            "Corefile:1: dnstap listen requires an endpoint argument",
        ),
        (
            "dnstap s full x",
            "Corefile:1: dnstap: invalid MultipleTcpWriteBuf \"x\": strconv.Atoi: parsing \"x\": invalid syntax",
        ),
        (
            "dnstap s full 99999999999999999999",
            "Corefile:1: dnstap: invalid MultipleTcpWriteBuf \"99999999999999999999\": strconv.Atoi: parsing \"99999999999999999999\": value out of range",
        ),
        (
            "dnstap s full 0",
            "Corefile:1: dnstap: MultipleTcpWriteBuf must be between 1 and 1024 (MiB units): 0",
        ),
        (
            "dnstap s full 1 y",
            "Corefile:1: dnstap: invalid MultipleQueue \"y\": strconv.Atoi: parsing \"y\": invalid syntax",
        ),
        (
            "dnstap s full 1 4097",
            "Corefile:1: dnstap: MultipleQueue must be between 1 and 4096 (x10k messages): 4097",
        ),
        (
            "dnstap s {\nbogus\n}",
            "Corefile:2: unknown property 'bogus'",
        ),
        (
            "dnstap s {\ntls a b\n}",
            "Corefile:2: tls directive only valid for listeners",
        ),
        (
            "dnstap tcp://h:1 {\ntls a b\n}",
            "Corefile:2: tls directive only valid for listeners",
        ),
        (
            "dnstap listen tcp://h:1 {\ntls a\n}",
            "Corefile:2: tls requires cert and key file paths",
        ),
        (
            "dnstap s {\nidentity\n}",
            "Corefile:2: Wrong argument count or unexpected line ending after 'identity'",
        ),
        (
            "dnstap tcp://h:port",
            "Corefile:1: Wrong argument count or unexpected line ending after 'tcp://h:port'",
        ),
    ] {
        assert_eq!(
            parse_text(text).unwrap_err().to_string(),
            message,
            "{text:?}"
        );
    }
}

// Go strconv.Atoi accepts a sign and, on a 64-bit host, any int64.
#[test]
fn accepts_signed_multipliers_like_atoi() {
    let config = parse_text("dnstap s full +5 +6").unwrap();
    assert_eq!((config[0].write_buffer, config[0].queue), (5, 6));
}

// net/url Parse: Host is the authority without userinfo, path, query or fragment.
#[test]
fn url_host_drops_userinfo_and_path() {
    let config = parse_text("dnstap tcp://user:pw@host:6000/path?q#f").unwrap();
    assert_eq!(config[0].endpoint, Endpoint::Tcp("host:6000".to_owned()));
}

// CoreDNS v1.15.0 setup.go: only `unix://` is stripped, so other schemes stay in the path.
#[test]
fn unknown_scheme_is_a_unix_path() {
    let config = parse_text("dnstap http://host:1").unwrap();
    assert_eq!(
        config[0].endpoint,
        Endpoint::Unix("http://host:1".to_owned())
    );
}

// CoreDNS v1.15.0 setup.go: a `full` value other than the literal keeps the message out.
#[test]
fn second_argument_other_than_full_is_ignored() {
    assert!(!parse_text("dnstap s other 2 3").unwrap()[0].full);
}

#[test]
fn skipverify_applies_to_dialers() {
    assert!(parse_text("dnstap tls://h:1 {\nskipverify\n}").unwrap()[0].skip_verify);
}

#[test]
fn several_directives_configure_taps_in_order() {
    let blocks = pharos_corefile::parse(
        "Corefile",
        ". {\n  dnstap dnstap1.sock\n  dnstap dnstap2.sock\n  dnstap dnstap3.sock\n}",
    )
    .unwrap();
    let configured =
        pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives()).unwrap();
    let dnstap = configured[0].config.dnstap.as_ref().unwrap();
    let endpoints: Vec<_> = dnstap
        .taps()
        .iter()
        .map(|tap| tap.config().endpoint.clone())
        .collect();
    assert_eq!(
        endpoints,
        [
            Endpoint::Unix("dnstap1.sock".to_owned()),
            Endpoint::Unix("dnstap2.sock".to_owned()),
            Endpoint::Unix("dnstap3.sock".to_owned()),
        ]
    );
}
