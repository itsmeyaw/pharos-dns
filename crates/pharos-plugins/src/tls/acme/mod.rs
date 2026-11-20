//! ACME certificate management (RFC 8555) with the DNS-01 challenge for the `tls` Directive.

pub(crate) mod http;
mod runtime;
mod solver;

pub(crate) use runtime::link;
pub use solver::Solver;

use std::{
    io,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use pharos_corefile::{Cursor, Error};
use pharos_server::tls::{CertSlot, ServerTls};

/// The Let's Encrypt production directory, as in certmagic's `DefaultACME`.
const DEFAULT_CA: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// What a `tls { acme ... }` block configures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Options {
    /// Lowercase ASCII names without trailing dot; a `*.` prefix is a wildcard.
    pub domains: Vec<String>,
    pub email: Option<String>,
    pub ca: String,
    pub storage: PathBuf,
    pub ca_root: Option<PathBuf>,
    pub resolver: Option<String>,
}

impl Options {
    /// Equal keys mean equivalent configurations, whatever the order of `domains`.
    // CoreDNS v1.15.0 plugin/tls/acme.go acmeOptions.key: domains are compared sorted.
    fn key(&self) -> String {
        let mut domains = self.domains.clone();
        domains.sort_unstable();
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            domains.join("\0"),
            self.email.as_deref().unwrap_or_default(),
            self.ca,
            self.storage.display(),
            self.ca_root
                .as_deref()
                .map_or_else(String::new, |p| p.display().to_string()),
            self.resolver.as_deref().unwrap_or_default(),
        )
    }
}

/// One ACME configuration and the certificates it obtains.
#[derive(Debug)]
pub struct Entry {
    pub options: Options,
    pub(crate) key: String,
    pub(crate) slot: Arc<CertSlot>,
    server: ServerTls,
}

impl Entry {
    pub fn new(options: Options) -> io::Result<Self> {
        let key = options.key();
        let slot = CertSlot::new(&options.domains);
        let server = ServerTls::from_slot(&slot, &key)?;
        Ok(Self {
            options,
            key,
            slot,
            server,
        })
    }

    /// The identity encrypted Listeners of this entry present.
    pub fn server(&self) -> ServerTls {
        self.server.clone()
    }
}

// CoreDNS v1.15.0 plugin/tls/tls.go parseACMETLS: one line of options per `tls` block.
pub(crate) fn parse(cursor: &mut Cursor<'_>, root: Option<&Path>) -> Result<Entry, Error> {
    let mut options = Options {
        domains: Vec::new(),
        email: None,
        ca: DEFAULT_CA.to_owned(),
        // CoreDNS v1.15.0 plugin/tls/acme.go defaultACMEOptions: `.coredns/acme` below the Corefile root.
        storage: resolve(cursor, root, ".coredns/acme")?,
        ca_root: None,
        resolver: None,
    };
    let mut seen = Vec::new();
    while cursor.next_block() {
        let name = cursor.val().to_owned();
        let args = cursor.remaining_args();
        if seen.contains(&name) {
            return Err(cursor.error(format!("ACME option {name:?} can only be specified once")));
        }
        seen.push(name.clone());
        match name.as_str() {
            "acme" if args.is_empty() => return Err(cursor.arg_err()),
            "acme" => options.domains = args,
            "email" | "ca" | "storage" | "ca_root" | "resolver" => {
                let [value] = args.as_slice() else {
                    return Err(cursor.arg_err());
                };
                match name.as_str() {
                    "email" => options.email = Some(value.clone()),
                    "ca" => options.ca.clone_from(value),
                    "storage" => options.storage = resolve(cursor, root, value)?,
                    "ca_root" => options.ca_root = Some(resolve(cursor, root, value)?),
                    _ => options.resolver = Some(value.clone()),
                }
            }
            other => return Err(cursor.error(format!("unknown ACME option {other:?}"))),
        }
    }
    validate(&mut options).map_err(|message| cursor.error(message))?;
    Entry::new(options).map_err(|error| cursor.error(error.to_string()))
}

// CoreDNS v1.15.0 plugin/tls/tls.go resolveACMEPath: relative paths join `root`, then become absolute.
fn resolve(cursor: &Cursor<'_>, root: Option<&Path>, path: &str) -> Result<PathBuf, Error> {
    absolute(&crate::resolve_path(path.into(), root), cursor)
}

fn absolute(path: &Path, cursor: &Cursor<'_>) -> Result<PathBuf, Error> {
    std::path::absolute(path)
        .map_err(|error| cursor.error(format!("resolving ACME path {path:?}: {error}")))
}

// CoreDNS v1.15.0 plugin/tls/acme.go validateACMEOptions.
fn validate(options: &mut Options) -> Result<(), String> {
    if options.domains.is_empty() {
        return Err("ACME requires at least one domain".to_owned());
    }
    let mut domains: Vec<String> = Vec::with_capacity(options.domains.len());
    for domain in &options.domains {
        let normalized = normalize_domain(domain)?;
        if !domains.contains(&normalized) {
            domains.push(normalized);
        }
    }
    options.domains = domains;
    // RFC 8555 §6.1 requires HTTPS; CoreDNS also accepts `http` so private test CAs work.
    if options.ca.parse::<http::Url>().is_err() {
        return Err(format!("invalid ACME CA URL {:?}", options.ca));
    }
    if let Some(resolver) = &options.resolver {
        let (host, port) = resolver.rsplit_once(':').ok_or_else(|| {
            format!("invalid ACME resolver {resolver:?}: missing port in address")
        })?;
        if host.is_empty() {
            return Err(format!("invalid ACME resolver {resolver:?}: host is empty"));
        }
        if port.parse::<u16>().ok().filter(|port| *port != 0).is_none() {
            return Err(format!("invalid ACME resolver port {port:?}"));
        }
    }
    if let Some(path) = &options.ca_root {
        trusted_roots(path)?;
    }
    Ok(())
}

// CoreDNS v1.15.0 plugin/tls/acme.go loadACMETrustedRoots: the system roots plus the PEM bundle.
fn trusted_roots(path: &Path) -> Result<(), String> {
    std::fs::metadata(path).map_err(|error| format!("reading ACME CA root {path:?}: {error}"))?;
    pharos_server::tls::client_config_with_roots(Some(path))
        .map(drop)
        .map_err(|error| format!("ACME CA root {path:?} contains no certificates: {error}"))
}

// CoreDNS v1.15.0 plugin/tls/acme.go normalizeACMEDomain.
fn normalize_domain(domain: &str) -> Result<String, String> {
    let invalid = || format!("invalid ACME domain {domain:?}");
    let name = domain.trim_end_matches('.').to_ascii_lowercase();
    let host = name.strip_prefix("*.").unwrap_or(&name);
    // RFC 8555 §7.1.3: an identifier is a fully qualified domain name; IP identifiers are not supported.
    if host.is_empty() || host.contains('*') || host.parse::<IpAddr>().is_ok() {
        return Err(invalid());
    }
    // RFC 5890 §2.3.2.1: only A-labels (ASCII) are accepted; IDNA conversion is not performed.
    if !host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(invalid());
    }
    // RFC 1035 §2.3.4: labels are 1 to 63 octets and the name at most 255.
    if format!("{host}.").parse::<pharos_proto::Name>().is_err() {
        return Err(invalid());
    }
    Ok(name)
}
