#![forbid(unsafe_code)]
#![cfg(feature = "plugin-https3")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

fn configure_block(body: &str) -> Result<Vec<pharos_corefile::BlockContext<Chain>>, String> {
    let text = format!(".:53 {{\n{body}\n}}");
    configure(
        &parse("Corefile", &text).map_err(|e| e.to_string())?,
        directives(),
    )
    .map_err(|e| e.to_string())
}

fn limits(body: &str) -> (Option<usize>, Option<usize>) {
    let blocks = configure_block(body).unwrap_or_else(|error| panic!("{body}: {error}"));
    let https3 = blocks[0].config.https3.as_ref().unwrap();
    (https3.max_streams, https3.max_connections)
}

// CoreDNS v1.15.0 plugin/https3/setup_test.go TestSetup, valid configurations.
#[test]
fn setup_accepts_documented_syntax() {
    assert_eq!(limits("https3"), (None, None));
    assert_eq!(limits("https3 {\n}"), (None, None));
    assert_eq!(limits("https3 {\n# Comment\n}"), (None, None));
    assert_eq!(limits("https3 {\nmax_streams 100\n}"), (Some(100), None));
    assert_eq!(limits("https3 {\nmax_streams 0\n}"), (Some(0), None));
    assert_eq!(limits("https3 {\nmax_connections 50\n}"), (None, Some(50)));
    assert_eq!(limits("https3 {\nmax_connections 0\n}"), (None, Some(0)));
    assert_eq!(
        limits("https3 {\nmax_streams 100\nmax_connections 50\n}"),
        (Some(100), Some(50))
    );
}

// CoreDNS v1.15.0 plugin/https3/setup_test.go TestSetup, invalid configurations.
#[test]
fn setup_rejects_invalid_configurations() {
    for (input, expected) in [
        ("https3 extra_arg", "Wrong argument count"),
        ("https3 {\nmax_streams\n}", "Wrong argument count"),
        ("https3 {\nmax_streams abc\n}", "invalid max_streams value"),
        ("https3 {\nmax_streams -1\n}", "non-negative integer"),
        ("https3 {\nmax_streams 100 200\n}", "Wrong argument count"),
        ("https3 {\nmax_connections\n}", "Wrong argument count"),
        (
            "https3 {\nmax_connections abc\n}",
            "invalid max_connections value",
        ),
        ("https3 {\nmax_connections -1\n}", "non-negative integer"),
        (
            "https3 {\nmax_connections 100 200\n}",
            "Wrong argument count",
        ),
        (
            "https3 {\nmax_streams 100\nmax_streams 200\n}",
            "already defined",
        ),
        (
            "https3 {\nmax_connections 50\nmax_connections 100\n}",
            "already defined",
        ),
        ("https3 {\nunknown_option 123\n}", "unknown property"),
    ] {
        let error = configure_block(input).unwrap_err();
        assert!(error.contains(expected), "{input}: {error}");
    }
}

// CoreDNS v1.15.0 plugin/https3/README.md: the plugin can only be used once per Server Block.
#[test]
fn second_https3_directive_is_rejected() {
    let error = configure_block("https3\nhttps3").unwrap_err();
    assert!(error.contains("only be used once"), "{error}");
}

fn servers(text: &str) -> Result<pharos_plugins::Servers, String> {
    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");
    let text = text
        .replace("@CERT", &format!("{fixtures}/server.pem"))
        .replace("@KEY", &format!("{fixtures}/server.key.pem"));
    let blocks = parse("Corefile", &text).unwrap();
    pharos_plugins::servers(configure::<Chain>(&blocks, directives()).unwrap())
        .map(|(servers, _)| servers)
        .map_err(|error| error.to_string())
}

// CoreDNS v1.15.0 core/dnsserver/server_https3.go NewServerHTTPS3: port 443, defaults 256 streams / 200 connections.
#[test]
fn https3_server_block_listens_on_443_with_default_limits() {
    use pharos_server::Handler;
    let servers = servers("https3://.:443 {\n tls @CERT @KEY\n whoami\n}").unwrap();
    let (key, server) = servers.iter().next().unwrap();
    assert_eq!(key.transport, pharos_server::Transport::Https3);
    assert_eq!(key.address.port(), 443);
    assert!(server.tls().is_some());
    let options = server.https();
    assert_eq!((options.max_streams, options.max_connections), (256, 200));
    assert!(options.status.is_some());
}

#[test]
fn https3_directive_limits_reach_the_listener() {
    use pharos_server::Handler;
    let servers = servers(
        "https3://.:443 {\n tls @CERT @KEY\n https3 {\n max_streams 16\n max_connections 0\n }\n whoami\n}",
    )
    .unwrap();
    let options = servers.values().next().unwrap().https();
    assert_eq!((options.max_streams, options.max_connections), (16, 0));
}

// CoreDNS v1.15.0 core/dnsserver/server_https3.go NewServerHTTPS3: group[0], the first block, sets both limits.
#[test]
fn first_block_decides_the_limits_of_a_shared_listener() {
    use pharos_server::Handler;
    let block = |zone: &str, limits: &str| {
        format!("https3://{zone}:443 {{\n tls @CERT @KEY\n https3 {{\n{limits}\n }}\n whoami\n}}\n")
    };
    let text = block("a.example", "max_streams 3\nmax_connections 4")
        + &block("b.example", "max_streams 5\nmax_connections 6");
    let listeners = servers(&text).unwrap();
    let options = listeners.values().next().unwrap().https();
    assert_eq!((options.max_streams, options.max_connections), (3, 4));
    let text = block("a.example", "") + &block("b.example", "max_streams 5");
    let listeners = servers(&text).unwrap();
    let options = listeners.values().next().unwrap().https();
    assert_eq!(options.max_streams, 256);
}

#[test]
fn https3_blocks_sharing_a_listener_must_share_a_tls_identity() {
    let error = servers(
        "https3://a.example:443 {\n tls @CERT @KEY\n whoami\n}\nhttps3://b.example:443 {\n tls @CERT @KEY {\n client_auth require\n }\n whoami\n}",
    )
    .err()
    .expect("rejected");
    assert!(
        error.contains("conflicting TLS configuration for shared listener https3://"),
        "{error}"
    );
}
