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
