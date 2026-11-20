#![forbid(unsafe_code)]
#![cfg(feature = "plugin-grpc-server")]

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

fn limits(body: &str) -> (Option<u32>, Option<usize>) {
    let blocks = configure_block(body).unwrap_or_else(|error| panic!("{body}: {error}"));
    let grpc = blocks[0].config.grpc_server.as_ref().unwrap();
    (grpc.max_streams, grpc.max_connections)
}

// CoreDNS v1.15.0 plugin/grpc_server/setup_test.go TestSetup, valid configurations.
#[test]
fn setup_accepts_documented_syntax() {
    assert_eq!(limits("grpc_server"), (None, None));
    assert_eq!(limits("grpc_server {\n}"), (None, None));
    assert_eq!(
        limits("grpc_server {\nmax_streams 100\n}"),
        (Some(100), None)
    );
    assert_eq!(
        limits("grpc_server {\nmax_connections 200\n}"),
        (None, Some(200))
    );
    assert_eq!(
        limits("grpc_server {\nmax_streams 50\nmax_connections 100\n}"),
        (Some(50), Some(100))
    );
    // Zero is unbounded.
    assert_eq!(limits("grpc_server {\nmax_streams 0\n}"), (Some(0), None));
    assert_eq!(
        limits("grpc_server {\nmax_connections 0\n}"),
        (None, Some(0))
    );
}

// CoreDNS v1.15.0 plugin/grpc_server/setup_test.go TestSetup, error cases.
#[test]
fn setup_rejects_invalid_configurations() {
    for (input, expected) in [
        ("grpc_server {\nmax_streams\n}", "Wrong argument count"),
        (
            "grpc_server {\nmax_streams abc\n}",
            "invalid max_streams value",
        ),
        (
            "grpc_server {\nmax_streams -1\n}",
            "must be a non-negative integer",
        ),
        ("grpc_server {\nmax_streams 1 2\n}", "Wrong argument count"),
        (
            "grpc_server {\nmax_streams 100\nmax_streams 200\n}",
            "already defined",
        ),
        ("grpc_server {\nmax_connections\n}", "Wrong argument count"),
        (
            "grpc_server {\nmax_connections abc\n}",
            "invalid max_connections value",
        ),
        (
            "grpc_server {\nmax_connections -1\n}",
            "must be a non-negative integer",
        ),
        (
            "grpc_server {\nmax_connections 1\nmax_connections 2\n}",
            "already defined",
        ),
        ("grpc_server {\nunknown_option 123\n}", "unknown property"),
        ("grpc_server extra_arg", "Wrong argument count"),
        // CoreDNS wraps the value to uint32; Pharos refuses it.
        (
            "grpc_server {\nmax_streams 4294967296\n}",
            "must not exceed 4294967295",
        ),
    ] {
        let error = configure_block(input).unwrap_err();
        assert!(error.contains(expected), "{input}: {error}");
    }
}

// CoreDNS v1.15.0 setup.go keeps its state on the block, so a repeated line merges and cannot redefine.
#[test]
fn repeated_directives_merge_but_cannot_redefine() {
    assert_eq!(
        limits("grpc_server {\nmax_streams 5\n}\ngrpc_server {\nmax_connections 7\n}"),
        (Some(5), Some(7))
    );
    let error = configure_block("grpc_server {\nmax_streams 5\n}\ngrpc_server {\nmax_streams 6\n}")
        .unwrap_err();
    assert!(error.contains("already defined"), "{error}");
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

// CoreDNS v1.15.0 core/dnsserver/server_grpc_test.go TestNewServergRPCDefaults: port 443, limits 256 / 200.
#[test]
fn grpc_server_block_listens_on_443_with_default_limits() {
    use pharos_server::Handler;
    let servers = servers("grpc://.:443 {\n tls @CERT @KEY\n whoami\n}").unwrap();
    let (key, server) = servers.iter().next().unwrap();
    assert_eq!(key.transport, pharos_server::Transport::Grpc);
    assert_eq!(key.address.port(), 443);
    assert!(server.tls().is_some());
    assert_eq!(server.grpc(), pharos_server::GrpcOptions::default());
    assert_eq!(server.grpc().max_streams, 256);
    assert_eq!(server.grpc().max_connections, 200);
}

// CoreDNS v1.15.0 core/dnsserver/server_grpc_test.go TestNewServergRPCWithCustomLimits and ...ZeroLimits.
#[test]
fn grpc_server_limits_reach_the_listener() {
    use pharos_server::Handler;
    let servers = servers(
        "grpc://.:443 {\n tls @CERT @KEY\n grpc_server {\n max_streams 50\n max_connections 100\n }\n whoami\n}\ngrpc://.:8443 {\n tls @CERT @KEY\n grpc_server {\n max_streams 0\n max_connections 0\n }\n whoami\n}",
    )
    .unwrap();
    let by_port = |port: u16| {
        servers
            .iter()
            .find(|(key, _)| key.address.port() == port)
            .unwrap()
            .1
            .grpc()
    };
    assert_eq!(
        (by_port(443).max_streams, by_port(443).max_connections),
        (50, 100)
    );
    assert_eq!(
        (by_port(8443).max_streams, by_port(8443).max_connections),
        (0, 0)
    );
}

// CoreDNS v1.15.0 core/dnsserver/server_grpc.go NewServergRPC: the first Server Block's limits apply.
#[test]
fn blocks_sharing_a_listener_use_the_first_blocks_limits() {
    use pharos_server::Handler;
    let servers = servers(
        "grpc://a.example:443 {\n tls @CERT @KEY\n grpc_server {\n max_streams 5\n }\n whoami\n}\ngrpc://b.example:443 {\n tls @CERT @KEY\n grpc_server {\n max_streams 9\n max_connections 3\n }\n whoami\n}",
    )
    .unwrap();
    let options = servers.values().next().unwrap().grpc();
    assert_eq!((options.max_streams, options.max_connections), (5, 200));
}

#[test]
fn grpc_blocks_sharing_a_listener_must_share_a_tls_identity() {
    let error = servers(
        "grpc://a.example:443 {\n tls @CERT @KEY\n whoami\n}\ngrpc://b.example:443 {\n tls @CERT @KEY {\n client_auth require\n }\n whoami\n}",
    )
    .err()
    .expect("rejected");
    assert!(
        error.contains("conflicting TLS configuration for shared listener grpc://"),
        "{error}"
    );
}
