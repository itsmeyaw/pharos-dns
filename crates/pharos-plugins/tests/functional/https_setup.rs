#![forbid(unsafe_code)]
#![cfg(feature = "plugin-https")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

fn fixtures(input: &str) -> String {
    input
        .replace("@CERT", &format!("{FIXTURES}/server.pem"))
        .replace("@KEY", &format!("{FIXTURES}/server.key.pem"))
}

fn configure_block(body: &str) -> Result<Vec<pharos_corefile::BlockContext<Chain>>, String> {
    let text = format!("https://.:443 {{\n{}\n}}", fixtures(body));
    configure(
        &parse("Corefile", &text).map_err(|e| e.to_string())?,
        directives(),
    )
    .map_err(|e| e.to_string())
}

// CoreDNS v1.15.0 plugin/https/setup_test.go TestSetup.
#[test]
fn setup_accepts_documented_syntax_and_rejects_the_rest() {
    let streams = u32::MAX;
    for (input, connections, streams) in [
        ("https", None, None),
        ("https {\n}", None, None),
        ("https {\nmax_connections 200\n}", Some(200), None),
        ("https {\nmax_streams 100\n}", None, Some(100)),
        (
            "https {\nmax_connections 200\nmax_streams 100\n}",
            Some(200),
            Some(100),
        ),
        ("https {\nmax_connections 0\n}", Some(0), None),
        ("https {\nmax_streams 0\n}", None, Some(0)),
        ("https {\nmax_streams 4294967295\n}", None, Some(streams)),
    ] {
        let blocks = configure_block(&format!("tls @CERT @KEY\n{input}")).expect(input);
        let https = blocks[0].config.https.as_ref().expect(input);
        assert_eq!(https.max_connections, connections, "{input}");
        assert_eq!(https.max_streams, streams, "{input}");
    }
    for (input, expected) in [
        ("https {\nmax_connections\n}", "Wrong argument count"),
        (
            "https {\nmax_connections abc\n}",
            "invalid max_connections value",
        ),
        (
            "https {\nmax_connections -1\n}",
            "must be a non-negative integer",
        ),
        (
            "https {\nmax_connections 100\nmax_connections 200\n}",
            "already defined",
        ),
        ("https {\nmax_streams\n}", "Wrong argument count"),
        ("https {\nmax_streams abc\n}", "invalid max_streams value"),
        (
            "https {\nmax_streams -1\n}",
            "must be a non-negative integer",
        ),
        ("https {\nmax_streams 4294967296\n}", "must not exceed"),
        (
            "https {\nmax_streams 100\nmax_streams 200\n}",
            "already defined",
        ),
        ("https {\nunknown_option 123\n}", "unknown property"),
        ("https extra_arg", "Wrong argument count"),
    ] {
        let error = configure_block(&format!("tls @CERT @KEY\n{input}"))
            .err()
            .unwrap_or_else(|| panic!("{input} accepted"));
        assert!(error.contains(expected), "{input}: {error}");
    }
}

fn servers(text: &str) -> Result<pharos_plugins::Servers, String> {
    let text = fixtures(text);
    let blocks = parse("Corefile", &text).unwrap();
    pharos_plugins::servers(configure::<Chain>(&blocks, directives()).unwrap())
        .map(|(servers, _)| servers)
        .map_err(|error| error.to_string())
}

#[test]
fn https_server_block_key_listens_on_443_with_h2_and_http11() {
    let servers = servers("https://.:443 {\n tls @CERT @KEY\n whoami\n}").unwrap();
    let (key, server) = servers.iter().next().unwrap();
    assert_eq!(key.transport, pharos_server::Transport::Https);
    assert_eq!(key.address.port(), 443);
    assert!(pharos_server::Handler::tls(server).is_some());
    // CoreDNS v1.15.0 core/dnsserver DefaultHTTPSMaxConnections and DefaultHTTPSMaxStreams.
    let options = pharos_server::Handler::https(server);
    assert_eq!((options.max_connections, options.max_streams), (200, 250));
}

#[test]
fn limits_reach_the_listener() {
    let servers =
        servers("https://.:443 {\n tls @CERT @KEY\n https {\n max_connections 0\n max_streams 7\n }\n whoami\n}")
            .unwrap();
    let options = pharos_server::Handler::https(servers.values().next().unwrap());
    assert_eq!((options.max_connections, options.max_streams), (0, 7));
}

// CoreDNS v1.15.0 core/dnsserver/server_https_test.go: shared Listener max_streams must agree.
#[test]
fn blocks_sharing_a_listener_must_agree_on_max_streams() {
    let block = |zone: &str, streams: &str| {
        format!("https://{zone}:443 {{\n tls @CERT @KEY\n https {{\n{streams}\n }}\n whoami\n}}\n")
    };
    let same = block("a.example", "max_streams 9") + &block("b.example", "max_streams 9");
    assert_eq!(servers(&same).unwrap().len(), 1);
    // A block that does not set max_streams does not conflict.
    let unset = block("a.example", "max_streams 9") + &block("b.example", "");
    assert_eq!(servers(&unset).unwrap().len(), 1);
    let error =
        servers(&(block("a.example", "max_streams 9") + &block("b.example", "max_streams 10")))
            .err()
            .expect("rejected");
    assert!(
        error.contains("conflicting max_streams values for shared HTTPS listener"),
        "{error}"
    );
}

// CoreDNS v1.15.0 core/dnsserver/server_https.go: the first block's max_connections wins.
#[test]
fn first_block_decides_max_connections_of_a_shared_listener() {
    let block = |zone: &str, limit: &str| {
        format!("https://{zone}:443 {{\n tls @CERT @KEY\n https {{\n{limit}\n }}\n whoami\n}}\n")
    };
    let servers = servers(
        &(block("a.example", "max_connections 3") + &block("b.example", "max_connections 4")),
    )
    .unwrap();
    let options = pharos_server::Handler::https(servers.values().next().unwrap());
    assert_eq!(options.max_connections, 3);
}
