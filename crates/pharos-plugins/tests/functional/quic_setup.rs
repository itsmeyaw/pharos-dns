#![forbid(unsafe_code)]
#![cfg(feature = "plugin-quic")]

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

fn limits(body: &str) -> (Option<usize>, Option<usize>, Option<usize>) {
    let blocks = configure_block(body).unwrap_or_else(|error| panic!("{body}: {error}"));
    let quic = blocks[0].config.quic.as_ref().unwrap();
    (
        quic.max_streams,
        quic.max_connections,
        quic.worker_pool_size,
    )
}

// CoreDNS v1.15.0 plugin/quic/setup_test.go TestQuicSetup, valid configurations.
#[test]
fn setup_accepts_documented_syntax() {
    assert_eq!(limits("quic"), (None, None, None));
    assert_eq!(limits("quic {\n}"), (None, None, None));
    assert_eq!(limits("quic {\n# Comment\n}"), (None, None, None));
    assert_eq!(
        limits("quic {\nmax_streams 100\n}"),
        (Some(100), None, None)
    );
    assert_eq!(
        limits("quic {\nmax_connections 50\n}"),
        (None, Some(50), None)
    );
    assert_eq!(
        limits("quic {\nmax_connections 0\n}"),
        (None, Some(0), None)
    );
    assert_eq!(
        limits("quic {\nworker_pool_size 1000\n}"),
        (None, None, Some(1000))
    );
    assert_eq!(
        limits("quic {\nmax_streams 100\nmax_connections 50\nworker_pool_size 1000\n}"),
        (Some(100), Some(50), Some(1000))
    );
}

// CoreDNS v1.15.0 plugin/quic/setup_test.go TestQuicSetup, invalid configurations.
#[test]
fn setup_rejects_invalid_configurations() {
    for (input, expected) in [
        ("quic arg", "Wrong argument count"),
        ("quic {\nmax_streams\n}", "Wrong argument count"),
        ("quic {\nmax_streams abc\n}", "invalid max_streams value"),
        ("quic {\nmax_streams 0\n}", "positive integer"),
        ("quic {\nmax_streams -10\n}", "positive integer"),
        ("quic {\nmax_streams 100 200\n}", "Wrong argument count"),
        ("quic {\nmax_connections\n}", "Wrong argument count"),
        (
            "quic {\nmax_connections abc\n}",
            "invalid max_connections value",
        ),
        ("quic {\nmax_connections -10\n}", "non-negative integer"),
        ("quic {\nmax_connections 100 200\n}", "Wrong argument count"),
        ("quic {\nworker_pool_size\n}", "Wrong argument count"),
        (
            "quic {\nworker_pool_size abc\n}",
            "invalid worker_pool_size value",
        ),
        ("quic {\nworker_pool_size 0\n}", "positive integer"),
        ("quic {\nworker_pool_size -10\n}", "positive integer"),
        (
            "quic {\nworker_pool_size 1000 2000\n}",
            "Wrong argument count",
        ),
        (
            "quic {\nmax_streams 100\nmax_streams 200\n}",
            "already defined",
        ),
        (
            "quic {\nmax_connections 50\nmax_connections 100\n}",
            "already defined",
        ),
        (
            "quic {\nworker_pool_size 1000\nworker_pool_size 2000\n}",
            "already defined",
        ),
        ("quic {\nunknown_directive\n}", "unknown property"),
    ] {
        let error = configure_block(input).unwrap_err();
        assert!(error.contains(expected), "{input}: {error}");
    }
}

// CoreDNS v1.15.0 plugin/quic/README.md: the plugin can only be used once per Server Block.
#[test]
fn second_quic_directive_is_rejected() {
    let error = configure_block("quic\nquic").unwrap_err();
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

// CoreDNS v1.15.0 core/dnsserver/server_quic.go NewServerQUIC: port 853, defaults 256 / 200 / 1024.
#[test]
fn quic_server_block_listens_on_853_with_default_limits() {
    use pharos_server::Handler;
    let servers = servers("quic://.:853 {\n tls @CERT @KEY\n whoami\n}").unwrap();
    let (key, server) = servers.iter().next().unwrap();
    assert_eq!(key.transport, pharos_server::Transport::Quic);
    assert_eq!(key.address.port(), 853);
    assert!(server.tls().is_some());
    assert_eq!(server.quic_options(), pharos_server::QuicOptions::default());
    assert_eq!(server.quic_options().max_streams, 256);
    assert_eq!(server.quic_options().max_connections, 200);
    assert_eq!(server.quic_options().worker_pool_size, 1024);
}

#[test]
fn quic_directive_limits_reach_the_listener() {
    use pharos_server::Handler;
    let servers = servers(
        "quic://.:853 {\n tls @CERT @KEY\n quic {\n max_streams 16\n max_connections 0\n worker_pool_size 7\n }\n whoami\n}",
    )
    .unwrap();
    let options = servers.values().next().unwrap().quic_options();
    assert_eq!(
        (
            options.max_streams,
            options.max_connections,
            options.worker_pool_size
        ),
        (16, 0, 7)
    );
}

#[test]
fn quic_blocks_sharing_a_listener_must_share_a_tls_identity() {
    let error = servers(
        "quic://a.example:853 {\n tls @CERT @KEY\n whoami\n}\nquic://b.example:853 {\n tls @CERT @KEY {\n client_auth require\n }\n whoami\n}",
    )
    .err()
    .expect("rejected");
    assert!(
        error.contains("conflicting TLS configuration for shared listener quic://"),
        "{error}"
    );
}
