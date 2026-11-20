#![forbid(unsafe_code)]
#![cfg(feature = "plugin-tls")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_server::tls::ClientAuth;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

/// Expand `@CERT`, `@KEY`, `@CA` and `@OTHER` into fixture paths.
fn fixtures(input: &str) -> String {
    input
        .replace("@CERT", &format!("{FIXTURES}/server.pem"))
        .replace("@KEY", &format!("{FIXTURES}/server.key.pem"))
        .replace("@CA", &format!("{FIXTURES}/ca.pem"))
        .replace("@OTHER", &format!("{FIXTURES}/other-ca.pem"))
}

fn configure_block(body: &str) -> Result<Vec<pharos_corefile::BlockContext<Chain>>, String> {
    let text = format!(".:53 {{\n{}\n}}", fixtures(body));
    configure(
        &parse("Corefile", &text).map_err(|e| e.to_string())?,
        directives(),
    )
    .map_err(|e| e.to_string())
}

// CoreDNS v1.15.0 plugin/tls/tls_test.go TestTLS.
#[test]
fn setup_accepts_documented_syntax_and_rejects_the_rest() {
    let tmp = std::env::temp_dir().join(format!("pharos-tls-setup-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let keylog = format!(
        "tls @CERT @KEY @CA {{\nkeylog {}\n}}",
        tmp.join("tls.log").display()
    );
    for input in [
        "tls @CERT @KEY @CA",
        "tls @CERT @KEY",
        "tls @CERT @KEY @CA {\nclient_auth nocert\n}",
        "tls @CERT @KEY @CA {\nclient_auth request\n}",
        "tls @CERT @KEY @CA {\nclient_auth require\n}",
        "tls @CERT @KEY @CA {\nclient_auth verify_if_given\n}",
        "tls @CERT @KEY @CA {\nclient_auth require_and_verify\n}",
        &keylog,
    ] {
        configure_block(input).unwrap_or_else(|error| panic!("{input}: {error}"));
    }
    for (input, expected) in [
        ("tls @CERT @KEY @CA {\nunknown\n}", "unknown option"),
        ("tls @CERT @KEY @CA {\nclient_auth\n}", "Wrong argument"),
        (
            "tls @CERT @KEY @CA {\nclient_auth none bogus\n}",
            "Wrong argument",
        ),
        (
            "tls @CERT @KEY @CA {\nclient_auth bogus\n}",
            "unknown authentication type",
        ),
        ("tls @CERT", "Wrong argument"),
        ("tls @CERT @KEY @CA @CA", "Wrong argument"),
    ] {
        let error = configure_block(input).unwrap_err();
        assert!(error.contains(expected), "{input}: {error}");
    }
}

// CoreDNS v1.15.0 plugin/tls/tls_test.go TestTLSClientAuthentication.
#[test]
fn client_auth_keywords_map_to_policies() {
    for (option, expected) in [
        ("", ClientAuth::NoCert),
        ("{\nclient_auth nocert\n}", ClientAuth::NoCert),
        ("{\nclient_auth request\n}", ClientAuth::Request),
        ("{\nclient_auth require\n}", ClientAuth::Require),
        (
            "{\nclient_auth verify_if_given\n}",
            ClientAuth::VerifyIfGiven,
        ),
        (
            "{\nclient_auth require_and_verify\n}",
            ClientAuth::RequireAndVerify,
        ),
    ] {
        let blocks = configure_block(&format!("tls @CERT @KEY @CA {option}")).unwrap();
        let tls = blocks[0].config.tls.as_ref().unwrap();
        assert_eq!(tls.options.client_auth, expected, "{option}");
        assert!(tls.options.ca.is_some());
    }
}

// CoreDNS v1.15.0 plugin/tls/tls_test.go TestTLSKeyLog.
#[test]
fn keylog_requires_a_writable_path() {
    let error = configure_block("tls @CERT @KEY @CA {\nkeylog\n}").unwrap_err();
    assert!(error.contains("Wrong argument"), "{error}");
    let missing = std::env::temp_dir()
        .join("pharos-tls-missing")
        .join("tls.log");
    let error = configure_block(&format!(
        "tls @CERT @KEY @CA {{\nkeylog {}\n}}",
        missing.display()
    ))
    .unwrap_err();
    assert!(error.contains("unable to write TLS Key Log"), "{error}");
    let good = std::env::temp_dir().join(format!("pharos-tls-keylog-{}", std::process::id()));
    let blocks = configure_block(&format!(
        "tls @CERT @KEY @CA {{\nkeylog {}\n}}",
        good.display()
    ))
    .unwrap();
    assert!(good.exists());
    assert!(blocks[0].config.tls.is_some());
    std::fs::remove_file(good).unwrap();
}

#[test]
fn relative_paths_resolve_against_root() {
    let blocks = configure_block(&format!(
        "root {FIXTURES}\ntls server.pem server.key.pem ca.pem"
    ))
    .unwrap();
    let options = &blocks[0].config.tls.as_ref().unwrap().options;
    assert_eq!(
        options.cert,
        std::path::Path::new(FIXTURES)
            .canonicalize()
            .unwrap()
            .join("server.pem")
    );
}

#[test]
fn unreadable_certificates_fail_setup() {
    for input in [
        "tls missing.pem @KEY @CA",
        "tls @CERT missing.pem @CA",
        "tls @CERT @KEY missing.pem",
        "tls @CERT @CERT @CA",
    ] {
        assert!(configure_block(input).is_err(), "{input}");
    }
}

#[test]
fn acme_block_is_rejected_with_a_clear_error() {
    let error = configure_block("tls {\nacme dns.example.org\n}").unwrap_err();
    assert!(error.contains("ACME"), "{error}");
    let error = configure_block("tls").unwrap_err();
    assert!(error.contains("ACME"), "{error}");
}

fn servers(text: &str) -> Result<pharos_plugins::Servers, String> {
    let text = fixtures(text);
    let blocks = parse("Corefile", &text).unwrap();
    pharos_plugins::servers(configure::<Chain>(&blocks, directives()).unwrap())
        .map(|(servers, _)| servers)
        .map_err(|error| error.to_string())
}

#[test]
fn tls_server_block_key_listens_on_853_with_its_identity() {
    let servers = servers("tls://.:853 {\n tls @CERT @KEY\n whoami\n}").unwrap();
    let (key, server) = servers.iter().next().unwrap();
    assert_eq!(key.transport, pharos_server::Transport::Tls);
    assert_eq!(key.address.port(), 853);
    assert!(pharos_server::Handler::tls(server).is_some());
}

#[test]
fn encrypted_transports_without_a_tls_directive_are_rejected() {
    for key in [
        "tls://.:853",
        "https://.:443",
        "grpc://.:443",
        "quic://.:853",
        "https3://.:443",
    ] {
        let error = servers(&format!("{key} {{\n whoami\n}}"))
            .err()
            .expect("rejected")
            .to_string();
        assert!(
            error.contains("requires the tls Directive"),
            "{key}: {error}"
        );
    }
}

#[test]
fn dns_server_block_ignores_the_tls_directive() {
    let servers = servers(".:1053 {\n tls @CERT @KEY\n whoami\n}").unwrap();
    let (key, server) = servers.iter().next().unwrap();
    assert_eq!(key.transport, pharos_server::Transport::Dns);
    assert!(pharos_server::Handler::tls(server).is_none());
}

// CoreDNS v1.15.0 core/dnsserver/server_tls_test.go TestNewServerTLSRejectsConflictingSharedTLSConfig.
#[test]
fn blocks_sharing_a_listener_must_share_a_tls_identity() {
    let block = |zone: &str, tls: &str| format!("tls://{zone}:853 {{\n {tls}\n whoami\n}}\n");
    let same = block("a.example", "tls @CERT @KEY") + &block("b.example", "tls @CERT @KEY");
    assert_eq!(servers(&same).unwrap().len(), 1);
    for (first, second, reason) in [
        (
            "tls @CERT @KEY",
            "tls @CERT @KEY @CA {\n client_auth require\n}",
            "client authentication policies differ",
        ),
        (
            "tls @CERT @KEY @CA {\n client_auth require_and_verify\n}",
            "tls @CERT @KEY @OTHER {\n client_auth require_and_verify\n}",
            "client CA pools differ",
        ),
    ] {
        let error = servers(&(block("a.example", first) + &block("b.example", second)))
            .err()
            .expect("rejected")
            .to_string();
        assert!(
            error.contains("conflicting TLS configuration for shared listener"),
            "{error}"
        );
        assert!(error.contains(reason), "{error}");
        assert!(
            error.contains("\"a.example.\"") && error.contains("\"b.example.\""),
            "{error}"
        );
    }
}
