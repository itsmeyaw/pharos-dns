use super::*;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");
// `htpasswd -nbBC 4 u pw`
const HASH: &str = "$2y$04$rMNoGfh5s9sLzpV90fV9N.Q46UW8WIePlvnCWQkK2mshf8l00ODMu";

fn tls(extra: &str) -> String {
    format!(
        "tls_server_config:\n  cert_file: {FIXTURES}/server.pem\n  key_file: {FIXTURES}/server.key.pem\n{extra}"
    )
}

fn load_text(text: &str) -> io::Result<Security> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("web.yml");
    std::fs::write(&path, text).unwrap();
    load(&path)
}

fn accepts(text: &str) -> Security {
    load_text(text).unwrap_or_else(|error| panic!("{text}: {error}"))
}

fn rejects(text: &str) -> io::Error {
    match load_text(text) {
        Ok(_) => panic!("accepted: {text}"),
        Err(error) => error,
    }
}

// exporter-toolkit v0.20.0 web/tls_config_test.go TestYAMLFiles.
#[test]
fn empty_file_is_plain_http_without_credentials() {
    for text in ["", "# comment only\n", "tls_server_config:\n"] {
        let security = accepts(text);
        assert!(security.tls.is_none(), "{text}");
        assert!(security.basic_auth.is_none(), "{text}");
        assert!(security.headers.is_empty(), "{text}");
    }
}

#[test]
fn missing_file_junk_and_unknown_keys_are_errors() {
    assert_eq!(
        load(Path::new("/nonexistent/web.yml"))
            .err()
            .unwrap()
            .kind(),
        ErrorKind::NotFound
    );
    rejects("hWkNKCp3fvIx3jKnsaBI\nTuEjdwNS8A2vYdFbiKqr\n");
    rejects("tls_server_config:\n  cert_filse: server.crt\n");
    rejects("surprise: 1\n");
    rejects("basic_auth_users:\n  u: x\n  u: y\n");
}

#[test]
fn complete_identity_enables_https_with_http2_by_default() {
    let security = accepts(&tls(""));
    assert!(security.tls.is_some());
    assert!(security.http2);
    let security = accepts(&(tls("") + "http_server_config:\n  http2: false\n"));
    assert!(!security.http2);
}

#[test]
fn incomplete_or_unreadable_identity_is_an_error() {
    let key = format!("{FIXTURES}/server.key.pem");
    let cert = format!("{FIXTURES}/server.pem");
    for text in [
            // web_config_noAuth_certPath_empty.bad.yml
            format!("tls_server_config:\n  cert_file: \"\"\n  key_file: {key}\n"),
            format!("tls_server_config:\n  key_file: {key}\n"),
            format!("tls_server_config:\n  cert_file: {cert}\n  key_file: \"\"\n"),
            format!("tls_server_config:\n  cert_file: {cert}\n"),
            // web_config_noAuth_certPath_keyPath_empty.bad.yml
            "tls_server_config:\n  cert_file: \"\"\n  key_file: \"\"\n  client_auth_type: NoClientCert\n"
                .to_owned(),
            // *_invalid.bad.yml
            format!("tls_server_config:\n  cert_file: somefile\n  key_file: {key}\n"),
            format!("tls_server_config:\n  cert_file: {cert}\n  key_file: somefile\n"),
            "tls_server_config:\n  cert_file: somefile\n  key_file: somefile\n".to_owned(),
            // The key file holds no certificate.
            format!("tls_server_config:\n  cert_file: {key}\n  key_file: {key}\n"),
        ] {
            rejects(&text);
        }
}

#[test]
fn relative_paths_resolve_against_the_config_directory() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["server.pem", "server.key.pem"] {
        std::fs::copy(format!("{FIXTURES}/{name}"), dir.path().join(name)).unwrap();
    }
    let path = dir.path().join("web.yml");
    std::fs::write(
        &path,
        "tls_server_config:\n  cert_file: server.pem\n  key_file: server.key.pem\n",
    )
    .unwrap();
    assert!(load(&path).unwrap().tls.is_some());
}

#[test]
fn client_auth_policy_and_client_ca() {
    let ca = format!("{FIXTURES}/ca.pem");
    for policy in [
        "RequestClientCert",
        "RequireAnyClientCert",
        "RequireClientCert",
        "VerifyClientCertIfGiven",
        "NoClientCert",
    ] {
        accepts(&tls(&format!("  client_auth_type: {policy}\n")));
    }
    accepts(&tls(&format!(
        "  client_auth_type: RequireAndVerifyClientCert\n  client_ca_file: {ca}\n"
    )));
    // web_config_noAuth.bad.yml: a client CA needs a policy.
    rejects(&tls(&format!("  client_ca_file: {ca}\n")));
    rejects(&tls("  client_auth_type: Bogus\n"));
    // web_config_auth_clientCAs_invalid.bad.yml
    rejects(&tls(
        "  client_auth_type: RequireAndVerifyClientCert\n  client_ca_file: somefile\n",
    ));
}

#[test]
fn versions_ciphers_and_curves() {
    // web_config_noAuth_someCiphers.good.yml, web_config_noAuth_allCurves.good.yml
    accepts(&tls(
        "  cipher_suites:\n  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\n  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n  min_version: TLS12\n  max_version: TLS12\n",
    ));
    accepts(&tls(
        "  curve_preferences:\n    - CurveP256\n    - CurveP384\n    - CurveP521\n    - X25519\n",
    ));
    // TLS 1.0 and 1.1 minimums fall to TLS 1.2; the others are named in Go's tls package.
    accepts(&tls("  min_version: TLS10\n"));
    accepts(&tls(
        "  min_version: TLS13\n  curve_preferences:\n  - CurveP384\n",
    ));
    // web_config_noAuth_inventedCiphers.bad.yml, inventedCurves, wrongTLSVersion
    rejects(&tls(
        "  cipher_suites:\n  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA2048\n",
    ));
    rejects(&tls("  curve_preferences:\n    - CurveP257\n"));
    rejects(&tls("  min_version: TLS111\n"));
    rejects(&tls("  max_version: TLS11\n"));
    rejects(&tls("  min_version: TLS13\n  max_version: TLS12\n"));
    rejects(&tls("  curve_preferences:\n    - CurveP521\n"));
}

#[test]
fn http2_needs_an_aes_128_gcm_suite_on_tls12() {
    // web_config_noAuth_noHTTP2Cipher.bad.yml and web_config_noAuth_noHTTP2.good.yml
    let only_256 =
        "  cipher_suites:\n    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n  max_version: TLS12\n";
    rejects(&tls(only_256));
    accepts(&(tls(only_256) + "http_server_config:\n  http2: false\n"));
    accepts(&tls(
        "  cipher_suites:\n    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n  min_version: TLS13\n",
    ));
}

#[test]
fn headers_are_limited_to_the_known_set() {
    // web_config_headers.good.yml
    let security = accepts(
        "http_server_config:\n  headers:\n    X-Frame-Options: deny\n    Strict-Transport-Security: max-age=31536000; includeSubDomains\n    X-Content-Type-Options: nosniff\n    X-XSS-Protection: 1\n    Content-Security-Policy: \"default-src 'self' *.test.example.net\"\n",
    );
    assert_eq!(security.headers.len(), 5);
    rejects("http_server_config:\n  headers:\n    X-Content-Type-Options: sniff\n");
    rejects("http_server_config:\n  headers:\n    X-Frame-Options: foo\n");
    rejects("http_server_config:\n  headers:\n    Content-Type: foo\n");
}

#[test]
fn basic_auth_users_need_bcrypt_hashes() {
    let security = accepts(&format!("basic_auth_users:\n  u: {HASH}\n"));
    assert!(security.basic_auth.is_some());
    // web_config_auth_user_list_invalid.bad.yml
    rejects("basic_auth_users:\n  john: doe\n");
    // Credentials work without TLS (web_config_users_noTLS.good.yml).
    assert!(security.tls.is_none());
}

#[test]
fn features_pharos_does_not_implement_fail_instead_of_being_ignored() {
    // web_config_rate_limiter_nonblocking.yaml is a no-op; one second needs a limiter.
    accepts("rate_limit:\n  interval: 0\n  burst: 0\n");
    accepts("rate_limit:\n  interval: 0ns\n");
    accepts("rate_limit:\n  interval: \"0m\"\n");
    assert_eq!(
        rejects("rate_limit:\n  interval: \"1s\"\n  burst: 0\n").kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        rejects(&tls("  client_allowed_sans:\n    - one\n")).kind(),
        ErrorKind::Unsupported
    );
    assert_eq!(
        rejects("tls_server_config:\n  cert: |\n    x\n  key: |\n    y\n").kind(),
        ErrorKind::Unsupported
    );
}
