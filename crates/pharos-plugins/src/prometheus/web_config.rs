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
        // Go time.ParseDuration: a zero number with an optional unit.
        Value::String(text) => {
            let number = text.trim_end_matches(['n', 'u', 'µ', 'μ', 'm', 's', 'h']);
            number.parse::<f64>().is_ok_and(|number| number == 0.0)
        }
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
mod tests;
