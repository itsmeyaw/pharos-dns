use super::*;
use pharos_corefile::lex;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

fn parse_with(text: &str, root: Option<&Path>, server_domains: &[&str]) -> Result<Config, Error> {
    let tokens = lex("Corefile", text);
    parse(&mut Cursor::new("Corefile", &tokens), root, server_domains)
}

fn parse_text(text: &str) -> Result<Config, Error> {
    parse_with(text, None, &["."])
}

fn name(text: &str) -> Name {
    text.parse().unwrap()
}

fn texts(config: &Config) -> Vec<&str> {
    config.endpoints.iter().map(|e| e.text.as_str()).collect()
}

fn fixture(file: &str) -> String {
    format!("{FIXTURES}/{file}")
}

// CoreDNS v1.15.0 plugin/etcd/setup_test.go TestSetupEtcd.
#[test]
fn setup_accepts_and_rejects_what_coredns_does() {
    type Accepted<'a> = (&'a str, &'a [&'a str], Option<(&'a str, &'a str)>);
    let accepted: [Accepted; 6] = [
        ("etcd", &["http://localhost:2379"], None),
        (
            "etcd {\n\tendpoint http://localhost:2379 http://localhost:3379 http://localhost:4379\n\n}",
            &[
                "http://localhost:2379",
                "http://localhost:3379",
                "http://localhost:4379",
            ],
            None,
        ),
        (
            "etcd skydns.local {\n\tendpoint localhost:300\n}\n",
            &["localhost:300"],
            None,
        ),
        (
            "etcd {\n\t\t\tendpoint http://localhost:2379\n\t\t\tcredentials username password\n\t\t}\n\t\t\t",
            &["http://localhost:2379"],
            Some(("username", "password")),
        ),
        (
            "etcd {\n\t\t\tendpoint http://localhost:2379\n\t\t\tmin-lease-ttl 60\n\t\t}\n\t\t\t",
            &["http://localhost:2379"],
            None,
        ),
        (
            "etcd {\n\t\t\tendpoint http://localhost:2379\n\t\t\tmax-lease-ttl 1h\n\t\t}\n\t\t\t",
            &["http://localhost:2379"],
            None,
        ),
    ];
    for (input, endpoints, credentials) in accepted {
        let config = parse_text(input).unwrap_or_else(|error| panic!("{input}: {error}"));
        assert_eq!(config.path_prefix, "skydns", "{input}");
        assert_eq!(texts(&config), endpoints, "{input}");
        assert_eq!(
            config
                .credentials
                .as_ref()
                .map(|c| (c.username.as_str(), c.password.as_str())),
            credentials,
            "{input}"
        );
    }
    for (input, expected) in [
        (
            "etcd {\n\tendpoints localhost:300\n}\n",
            "unknown property 'endpoints'",
        ),
        (
            "etcd {\n\t\t\tendpoint http://localhost:2379\n\t\t\tcredentials username\n\t\t}\n\t\t\t",
            "credentials requires 2 arguments",
        ),
        (
            "etcd {\n\t\t\tendpoint http://localhost:2379\n\t\t\tcredentials\n\t\t}\n\t\t\t",
            "Wrong argument count",
        ),
        (
            "etcd {\n\t\t\tcredentials a b c\n\t\t}\n",
            "credentials requires 2 arguments",
        ),
    ] {
        let error = parse_text(input).unwrap_err().to_string();
        assert!(error.contains(expected), "{input}: {error}");
    }
}

// CoreDNS v1.15.0 plugin/etcd/setup_test.go TestSetupEtcd: lease TTL options.
#[test]
fn lease_ttl_bounds_default_and_parse() {
    let config = parse_text("etcd").unwrap();
    assert_eq!((config.min_lease_ttl, config.max_lease_ttl), (30, 86400));
    let config = parse_text("etcd {\nmin-lease-ttl 60\n}").unwrap();
    assert_eq!((config.min_lease_ttl, config.max_lease_ttl), (60, 86400));
    let config = parse_text("etcd {\nmax-lease-ttl 1h\n}").unwrap();
    assert_eq!((config.min_lease_ttl, config.max_lease_ttl), (30, 3600));
    let config = parse_text("etcd {\nmin-lease-ttl 120\nmax-lease-ttl 7200\n}").unwrap();
    assert_eq!((config.min_lease_ttl, config.max_lease_ttl), (120, 7200));
    let config = parse_text("etcd {\nmin-lease-ttl 1m30s\nmax-lease-ttl 1.5h\n}").unwrap();
    assert_eq!((config.min_lease_ttl, config.max_lease_ttl), (90, 5400));
}

// CoreDNS v1.15.0 plugin/etcd/setup.go etcdParse: a bad TTL is `invalid OPTION value: REASON`, a missing one an argument error.
#[test]
fn lease_ttl_errors_name_the_option() {
    for (input, expected) in [
        (
            "etcd {\nmin-lease-ttl abc\n}",
            "invalid min-lease-ttl value: invalid TTL format",
        ),
        (
            "etcd {\nmax-lease-ttl -5s\n}",
            "invalid max-lease-ttl value: TTL must be non-negative",
        ),
        (
            "etcd {\nmax-lease-ttl 4294967296\n}",
            "invalid max-lease-ttl value: TTL too large",
        ),
        ("etcd {\nmin-lease-ttl\n}", "Wrong argument count"),
        ("etcd {\nmax-lease-ttl\n}", "Wrong argument count"),
    ] {
        let error = parse_text(input).unwrap_err().to_string();
        assert!(error.contains(expected), "{input}: {error}");
    }
}

// CoreDNS v1.15.0 plugin/etcd/setup_test.go TestSetupNoApexFallback.
#[test]
fn no_apex_fallback_is_a_flag() {
    assert!(!parse_text("etcd").unwrap().no_apex_fallback);
    assert!(
        parse_text("etcd {\nno_apex_fallback\n}")
            .unwrap()
            .no_apex_fallback
    );
    assert!(parse_text("etcd {\nno_apex_fallback unexpected\n}").is_err());
}

// CoreDNS v1.15.0 plugin/etcd/setup.go etcdParse: `path`, and `stubzones`, `debug` and `upstream` which are ignored.
#[test]
fn path_and_ignored_options() {
    assert_eq!(
        parse_text("etcd {\npath /mydns\n}").unwrap().path_prefix,
        "/mydns"
    );
    assert!(parse_text("etcd {\npath\n}").is_err());
    let config =
        parse_text("etcd {\nstubzones\ndebug\nupstream 1.1.1.1 2.2.2.2\nupstream\npath x\n}")
            .unwrap();
    assert_eq!(config.path_prefix, "x");
    assert!(parse_text("etcd {\nstubzones extra\n}").is_err());
}

// CoreDNS v1.15.0 plugin/etcd/setup.go etcdParse: `plugin.OriginsFromArgsOrServerBlock`.
#[test]
fn zones_come_from_arguments_or_the_server_block() {
    let config = parse_with("etcd skydns.local Example.ORG.", None, &["."]).unwrap();
    assert_eq!(config.zones, [name("skydns.local."), name("example.org.")]);
    let config = parse_with("etcd", None, &["skydns.local.", "10.in-addr.arpa."]).unwrap();
    assert_eq!(
        config.zones,
        [name("skydns.local."), name("10.in-addr.arpa.")]
    );
}

// CoreDNS v1.15.0 plugin/pkg/fall/fall.go SetZonesFromArgs.
#[test]
fn fallthrough_defaults_to_nothing_then_root_then_listed_zones() {
    assert!(parse_text("etcd").unwrap().fallthrough.is_empty());
    assert_eq!(
        parse_text("etcd {\nfallthrough\n}").unwrap().fallthrough,
        [name(".")]
    );
    assert_eq!(
        parse_text("etcd {\nfallthrough in-addr.arpa ip6.arpa\n}")
            .unwrap()
            .fallthrough,
        [name("in-addr.arpa."), name("ip6.arpa.")]
    );
}

// etcd clientv3 internal/endpoint/endpoint.go translateEndpoint and schemeToCredsRequirement.
#[test]
fn endpoints_follow_etcd_clientv3() {
    let parsed = |text: &str, tls: bool| {
        let endpoint = endpoint(text, tls).unwrap();
        (endpoint.host, endpoint.port, endpoint.tls)
    };
    let host = |host: &str, port: u16, tls: bool| (host.to_owned(), port, tls);
    assert_eq!(
        parsed("http://localhost:2379", false),
        host("localhost", 2379, false)
    );
    // `http` drops TLS credentials, `https` requires them, a bare address uses them when configured.
    assert_eq!(
        parsed("http://localhost:2379", true),
        host("localhost", 2379, false)
    );
    assert_eq!(
        parsed("https://etcd.example:2379", false),
        host("etcd.example", 2379, true)
    );
    assert_eq!(
        parsed("localhost:300", false),
        host("localhost", 300, false)
    );
    assert_eq!(parsed("localhost:300", true), host("localhost", 300, true));
    assert_eq!(
        parsed("10.0.0.1:2379", false),
        host("10.0.0.1", 2379, false)
    );
    assert_eq!(parsed("[::1]:2379", false), host("::1", 2379, false));
    assert_eq!(
        parsed("https://[fd00::1]:2379", false),
        host("fd00::1", 2379, true)
    );
    // grpc-go's default port, and url.Parse's host ends at the path or userinfo.
    assert_eq!(parsed("etcd.local", false), host("etcd.local", 443, false));
    assert_eq!(
        parsed("http://etcd.local", false),
        host("etcd.local", 443, false)
    );
    assert_eq!(
        parsed("http://user:pw@etcd.local:1/v3/x?y#z", false),
        host("etcd.local", 1, false)
    );
    for bad in [
        "unix:///var/run/etcd.sock",
        "unix://etcd.sock",
        "unixs:etcd.sock",
        "ftp://etcd:2379",
        "http://",
        "http://:2379",
        "localhost:port",
        "localhost:70000",
        "localhost:",
        "[::1",
        "[::1]x",
        "a:b:c",
    ] {
        assert!(endpoint(bad, false).is_err(), "{bad}");
    }
}

// etcd clientv3: `tls` applies to endpoints without a scheme, whichever order the options come in.
#[test]
fn tls_applies_to_bare_endpoints_in_any_order() {
    let ca = fixture("ca.pem");
    for text in [
        format!("etcd {{\nendpoint a:1 http://b:2 https://c:3\ntls {ca}\n}}"),
        format!("etcd {{\ntls {ca}\nendpoint a:1 http://b:2 https://c:3\n}}"),
    ] {
        let config = parse_text(&text).unwrap();
        let tls: Vec<bool> = config.endpoints.iter().map(|e| e.tls).collect();
        assert_eq!(tls, [true, false, true], "{text}");
        assert_eq!(
            config.tls.unwrap().alpn_protocols,
            [b"h2".to_vec()],
            "{text}"
        );
    }
    let config = parse_text("etcd {\nendpoint a:1 https://c:3\n}").unwrap();
    assert!(config.tls.is_none());
    assert_eq!(
        config.endpoints.iter().map(|e| e.tls).collect::<Vec<_>>(),
        [false, true]
    );
}

// CoreDNS v1.15.0 plugin/pkg/tls/tls.go NewTLSConfigFromArgs: `CA`, `CERT KEY` and `CERT KEY CA`.
#[test]
fn tls_takes_ca_or_cert_key_or_both() {
    let (ca, cert, key) = (
        fixture("ca.pem"),
        fixture("client.pem"),
        fixture("client.key.pem"),
    );
    for args in [
        ca.clone(),
        format!("{cert} {key}"),
        format!("{cert} {key} {ca}"),
    ] {
        parse_text(&format!("etcd {{\ntls {args}\n}}"))
            .unwrap_or_else(|error| panic!("{args}: {error}"));
    }
}

// CoreDNS v1.15.0 plugin/pkg/tls/tls.go NewTLSConfigFromArgs: at most three arguments; unreadable files are setup errors.
#[test]
fn tls_errors_surface_at_setup() {
    let error = parse_text("etcd {\ntls a b c d\n}")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("maximum of three arguments allowed for TLS config, found 4"),
        "{error}"
    );
    let error = parse_text("etcd {\ntls /nonexistent/ca.pem\n}")
        .unwrap_err()
        .to_string();
    assert!(error.contains("/nonexistent/ca.pem"), "{error}");
    let error = parse_text("etcd {\ntls /nonexistent/cert.pem /nonexistent/key.pem\n}")
        .unwrap_err()
        .to_string();
    assert!(error.contains("could not load TLS cert"), "{error}");
}

// CoreDNS v1.15.0 plugin/etcd/setup.go etcdParse: a relative `tls` path joins `root`.
#[test]
fn tls_relative_paths_join_root() {
    let error = parse_with(
        "etcd {\ntls ca.pem\n}",
        Some(Path::new("/nonexistent/root")),
        &["."],
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("/nonexistent/root/ca.pem"), "{error}");
    let root = Path::new(FIXTURES);
    parse_with("etcd {\ntls ca.pem\n}", Some(root), &["."]).unwrap();
    // An absolute path ignores `root`.
    let ca = fixture("ca.pem");
    parse_with(
        &format!("etcd {{\ntls {ca}\n}}"),
        Some(Path::new("/nonexistent")),
        &["."],
    )
    .unwrap();
}

// CoreDNS v1.15.0 plugin/etcd/setup.go newEtcdClient: setup never connects, so unreachable endpoints are accepted.
#[test]
fn setup_does_not_connect() {
    parse_text("etcd {\nendpoint http://192.0.2.1:2379 https://etcd.invalid:2379\n}").unwrap();
}

// CoreDNS v1.15.0 plugin/etcd/setup.go newEtcdClient: credentials apply only when both are non-empty.
#[test]
fn empty_credentials_are_ignored() {
    assert!(
        parse_text("etcd {\ncredentials \"\" pw\n}")
            .unwrap()
            .credentials
            .is_none()
    );
    let config = parse_text("etcd {\ncredentials user secret\n}").unwrap();
    assert_eq!(config.credentials.as_ref().unwrap().password, "secret");
    // The password stays out of logs.
    assert!(!format!("{config:?}").contains("secret"));
}

fn configure(text: &str) -> Result<Vec<BlockContext<crate::Chain>>, Error> {
    let blocks = pharos_corefile::parse("Corefile", text)?;
    pharos_corefile::configure::<crate::Chain>(&blocks, crate::directives())
}

// The `etcd` Directive builds a Plugin that holds the parsed Config.
#[test]
fn directive_builds_a_plugin_from_a_corefile() {
    let configured = configure(
        "skydns.local {\n  etcd {\n    path /sky\n    endpoint https://etcd:2379\n  }\n}",
    )
    .unwrap();
    let etcd = configured[0].config.etcd.as_ref().unwrap();
    assert_eq!(etcd.config().zones, [name("skydns.local.")]);
    assert_eq!(etcd.config().path_prefix, "/sky");
    assert_eq!(texts(etcd.config()), ["https://etcd:2379"]);
}

// Unlike CoreDNS, the Directive is accepted once per Server Block, as the Chain has one slot for it.
#[test]
fn directive_is_once_per_server_block() {
    let error = configure(".  {\n  etcd\n  etcd\n}")
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("this plugin can only be used once per Server Block"),
        "{error}"
    );
}
