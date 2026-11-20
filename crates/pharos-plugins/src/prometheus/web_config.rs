//! The Prometheus exporter-toolkit web configuration file named by the `tls` option.
//!
//! Follows exporter-toolkit v0.20.0 `web/tls_config.go` and `web/handler.go`, which CoreDNS v1.15.0
//! uses through `web.Validate` and `web.Serve`.

use std::{
    collections::BTreeMap,
    fmt,
    io::{self, ErrorKind},
    marker::PhantomData,
    path::{Path, PathBuf},
    sync::Arc,
};

use pharos_server::{
    basic_auth::BasicAuth,
    http::Security,
    tls::{ClientAuth, Curve, Restrictions, ServerOptions, ServerTls, Version},
};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use serde_yaml_ng::Value;

// exporter-toolkit v0.20.0 web/handler.go extraHTTPHeaders: the headers a file may set, with the
// values allowed for each (none listed means any value).
const HEADERS: [(&str, &[&str]); 5] = [
    ("Strict-Transport-Security", &[]),
    ("X-Content-Type-Options", &["nosniff"]),
    ("X-Frame-Options", &["deny", "sameorigin"]),
    ("X-XSS-Protection", &[]),
    ("Content-Security-Policy", &[]),
];

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct File {
    tls_server_config: Option<Tls>,
    http_server_config: Option<Http>,
    rate_limit: Option<RateLimit>,
    #[serde(deserialize_with = "unique")]
    basic_auth_users: BTreeMap<String, String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Tls {
    cert: String,
    key: String,
    client_ca: String,
    cert_file: String,
    key_file: String,
    client_auth_type: String,
    client_ca_file: String,
    cipher_suites: Vec<String>,
    curve_preferences: Vec<String>,
    min_version: Option<String>,
    max_version: Option<String>,
    // exporter-toolkit v0.20.0 web/tls_config.go: parsed and ignored.
    #[serde(rename = "prefer_server_cipher_suites")]
    _prefer_server_cipher_suites: bool,
    client_allowed_sans: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
struct Http {
    http2: bool,
    #[serde(deserialize_with = "unique")]
    headers: BTreeMap<String, String>,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            http2: true,
            headers: BTreeMap::new(),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RateLimit {
    #[serde(rename = "burst")]
    _burst: Option<Value>,
    interval: Option<Value>,
}

// yaml.v2 UnmarshalStrict: a repeated key in a mapping is an error.
fn unique<'de, D: Deserializer<'de>, V: Deserialize<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, V>, D::Error> {
    struct Unique<V>(PhantomData<V>);
    impl<'de, V: Deserialize<'de>> Visitor<'de> for Unique<V> {
        type Value = BTreeMap<String, V>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a mapping")
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(BTreeMap::new())
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, V>()? {
                if out.contains_key(&key) {
                    return Err(de::Error::custom(format!("key {key:?} already set in map")));
                }
                out.insert(key, value);
            }
            Ok(out)
        }
    }
    deserializer.deserialize_any(Unique(PhantomData))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message.into())
}

/// Read, validate and apply the configuration file, like `web.Validate` followed by `web.Serve`.
pub(crate) fn load(path: &Path) -> io::Result<Security> {
    let text = std::fs::read_to_string(path)?;
    // exporter-toolkit v0.20.0 getConfig: yaml.UnmarshalStrict rejects unknown fields; an empty file is valid.
    let file = serde_yaml_ng::from_str::<Option<File>>(&text)
        .map_err(|error| invalid(format!("{}: {error}", path.display())))?
        .unwrap_or_default();
    let http = file.http_server_config.unwrap_or_default();
    let headers = headers(&http.headers)?;
    let basic_auth = if file.basic_auth_users.is_empty() {
        None
    } else {
        Some(Arc::new(BasicAuth::new(file.basic_auth_users)?))
    };
    if let Some(limit) = &file.rate_limit
        && limit
            .interval
            .as_ref()
            .is_some_and(|interval| !is_zero(interval))
    {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "rate_limit is not supported",
        ));
    }
    let tls = match file.tls_server_config {
        Some(tls) if enabled(&tls) => Some(server_tls(tls, &http, path)?),
        _ => None,
    };
    Ok(Security {
        tls,
        http2: http.http2,
        headers,
        basic_auth,
    })
}

fn is_zero(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.as_f64() == Some(0.0),
        Value::String(text) => matches!(text.as_str(), "0" | "0s"),
        Value::Null => true,
        _ => false,
    }
}

// exporter-toolkit v0.20.0 web/handler.go validateHeaderConfig.
fn headers(
    configured: &BTreeMap<String, String>,
) -> io::Result<Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>> {
    let mut headers = Vec::with_capacity(configured.len());
    for (name, value) in configured {
        let Some((_, allowed)) = HEADERS.iter().find(|(known, _)| known == name) else {
            return Err(invalid(format!(
                "HTTP header {name:?} can not be configured"
            )));
        };
        if !allowed.is_empty() && !allowed.contains(&value.as_str()) {
            return Err(invalid(format!(
                "invalid value for {name}. Expected one of: {allowed:?}, but got: {value:?}"
            )));
        }
        // RFC 9110 §5.5: a field value is visible characters, spaces and tabs.
        let header = (
            name.parse()
                .map_err(|error| invalid(format!("{name}: {error}")))?,
            value
                .parse()
                .map_err(|error| invalid(format!("{name}: {error}")))?,
        );
        headers.push(header);
    }
    Ok(headers)
}

// exporter-toolkit v0.20.0 web/tls_config.go TLSConfig.IsEnabled.
fn enabled(tls: &Tls) -> bool {
    [
        &tls.cert_file,
        &tls.cert,
        &tls.key_file,
        &tls.key,
        &tls.client_ca_file,
        &tls.client_ca,
        &tls.client_auth_type,
    ]
    .iter()
    .any(|value| !value.is_empty())
}

// exporter-toolkit v0.20.0 web/tls_config.go ConfigToTLSConfig.
fn server_tls(tls: Tls, http: &Http, config: &Path) -> io::Result<ServerTls> {
    if tls.cert_file.is_empty() && tls.cert.is_empty() {
        return Err(invalid("missing one of cert or cert_file"));
    }
    if tls.key_file.is_empty() && tls.key.is_empty() {
        return Err(invalid("missing one of key or key_file"));
    }
    if !tls.cert.is_empty() || !tls.key.is_empty() || !tls.client_ca.is_empty() {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "inline cert, key and client_ca are not supported; use cert_file, key_file and client_ca_file",
        ));
    }
    if tls.client_allowed_sans.is_some() {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "client_allowed_sans is not supported",
        ));
    }
    let client_auth = match tls.client_auth_type.as_str() {
        "RequestClientCert" => ClientAuth::Request,
        // Preserved for backwards compatibility by exporter-toolkit.
        "RequireAnyClientCert" | "RequireClientCert" => ClientAuth::Require,
        "VerifyClientCertIfGiven" => ClientAuth::VerifyIfGiven,
        "RequireAndVerifyClientCert" => ClientAuth::RequireAndVerify,
        "" | "NoClientCert" => ClientAuth::NoCert,
        other => return Err(invalid(format!("invalid ClientAuth: {other}"))),
    };
    if !tls.client_ca_file.is_empty() && client_auth == ClientAuth::NoCert {
        return Err(invalid(
            "client CA's have been configured without a Client Auth Policy",
        ));
    }
    let min_version = match parse_version(tls.min_version.as_deref(), 12)? {
        // RFC 9325 §3.1.1: Pharos starts at TLS 1.2, so an older minimum means TLS 1.2.
        13 => Version::Tls13,
        _ => Version::Tls12,
    };
    let max_version = match parse_version(tls.max_version.as_deref(), 13)? {
        13 => Version::Tls13,
        12 => Version::Tls12,
        _ => {
            return Err(io::Error::new(
                ErrorKind::Unsupported,
                "max_version below TLS12 is not supported",
            ));
        }
    };
    let curves = tls
        .curve_preferences
        .iter()
        .map(|name| match name.as_str() {
            "CurveP256" => Ok(Curve::P256),
            "CurveP384" => Ok(Curve::P384),
            "CurveP521" => Ok(Curve::P521),
            "X25519" => Ok(Curve::X25519),
            other => Err(invalid(format!("unknown curve: {other}"))),
        })
        .collect::<io::Result<Vec<_>>>()?;
    // RFC 9113 §9.2.2: HTTP/2 over TLS 1.2 needs an ECDHE AES-128-GCM suite, as Go's http2 server checks.
    if http.http2
        && !tls.cipher_suites.is_empty()
        && !matches!(tls.min_version.as_deref(), Some("TLS13"))
        && !tls.cipher_suites.iter().any(|name| {
            matches!(
                name.as_str(),
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" | "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            )
        })
    {
        return Err(invalid(
            "http2: TLSConfig.CipherSuites is missing an HTTP/2-required AES_128_GCM_SHA256 cipher (need at least one of TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 or TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)",
        ));
    }
    let dir = config.parent().unwrap_or(Path::new("."));
    let options = ServerOptions {
        cert: join_dir(dir, &tls.cert_file),
        key: join_dir(dir, &tls.key_file),
        ca: (!tls.client_ca_file.is_empty()).then(|| join_dir(dir, &tls.client_ca_file)),
        client_auth,
        keylog: None,
    };
    ServerTls::load_restricted(
        &options,
        &Restrictions {
            min_version,
            max_version,
            cipher_suites: tls.cipher_suites,
            curves,
        },
    )
}

// exporter-toolkit v0.20.0 web/tls_config.go tlsVersions: the names min_version and max_version accept.
fn parse_version(name: Option<&str>, default: u8) -> io::Result<u8> {
    match name {
        None => Ok(default),
        Some("TLS13") => Ok(13),
        Some("TLS12") => Ok(12),
        Some("TLS11") => Ok(11),
        Some("TLS10") => Ok(10),
        Some(other) => Err(invalid(format!("unknown TLS version: {other}"))),
    }
}

// exporter-toolkit v0.20.0 web/tls_config.go SetDirectory: relative paths are relative to the config file.
fn join_dir(dir: &Path, path: &str) -> PathBuf {
    if path.is_empty() || Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        dir.join(path)
    }
}

#[cfg(test)]
mod tests {
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
        let only_256 = "  cipher_suites:\n    - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n  max_version: TLS12\n";
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
}
