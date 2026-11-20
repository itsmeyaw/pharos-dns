//! TLS configuration shared by every encrypted Transport and by Upstream clients.
//!
//! The module hides rustls and the aws-lc-rs provider behind two loaders:
//! [`ServerTls::load`] for Listeners and [`client_config`] for Upstreams.

use std::{
    fmt::{self, Write as _},
    fs::{File, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use arc_swap::ArcSwapOption;
use rustls::{
    DistinguishedName, NamedGroup, RootCertStore, ServerConfig, SignatureScheme,
    SupportedCipherSuite,
    client::danger::HandshakeSignatureValid,
    crypto::{
        CryptoProvider, WebPkiSupportedAlgorithms, aws_lc_rs, verify_tls12_signature,
        verify_tls13_signature,
    },
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject},
    server::{
        ClientHello, ResolvesServerCert, WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    sign::CertifiedKey,
    version::{TLS12, TLS13},
};

pub use quinn::crypto::rustls::QuicServerConfig;
pub use rustls::{ClientConfig, pki_types::ServerName};
pub use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream as ClientStream};

/// Whether and how a Listener asks its clients for a certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientAuth {
    /// Never ask for a client certificate.
    NoCert,
    /// Ask, but accept a missing or unverified certificate.
    Request,
    /// Require a certificate without verifying its chain.
    Require,
    /// Verify a certificate only when the client sends one.
    VerifyIfGiven,
    /// Require a certificate that chains to the client CA pool.
    RequireAndVerify,
}

/// Files that define a Listener's TLS identity and client policy.
#[derive(Clone, Debug)]
pub struct ServerOptions {
    pub cert: PathBuf,
    pub key: PathBuf,
    /// CA bundle for client certificates; the system roots when absent.
    pub ca: Option<PathBuf>,
    pub client_auth: ClientAuth,
    /// Append NSS key log lines here so tools can decrypt captured traffic.
    pub keylog: Option<PathBuf>,
}

/// A TLS protocol version Pharos can negotiate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Version {
    Tls12,
    Tls13,
}

/// A key exchange group a Listener may be limited to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Curve {
    P256,
    P384,
    /// Known, but rustls with aws-lc-rs cannot offer it.
    P521,
    X25519,
}

/// What a Listener negotiates beyond its identity; the default allows everything Pharos supports.
#[derive(Clone, Debug)]
pub struct Restrictions {
    pub min_version: Version,
    pub max_version: Version,
    /// IANA names of the TLS 1.2 cipher suites to offer; none offers every suite. TLS 1.3 names are
    /// accepted but ignored, because TLS 1.3 suites are not configurable (RFC 8446 §9.1).
    pub cipher_suites: Vec<String>,
    /// Key exchange groups to offer in order of preference; none offers every group.
    pub curves: Vec<Curve>,
}

impl Default for Restrictions {
    fn default() -> Self {
        Self {
            min_version: Version::Tls12,
            max_version: Version::Tls13,
            cipher_suites: Vec::new(),
            curves: Vec::new(),
        }
    }
}

/// A loaded server identity. Cloning shares the same rustls configuration.
#[derive(Clone)]
pub struct ServerTls {
    config: Arc<ServerConfig>,
    quic_tls: Arc<ServerConfig>,
    quic: Arc<QuicServerConfig>,
    policy: Arc<Policy>,
}

/// The settings CoreDNS compares before two Server Blocks may share a Listener.
#[derive(Eq, PartialEq)]
struct Policy {
    client_auth: ClientAuth,
    client_cas: Option<Vec<Vec<u8>>>,
    chain: Vec<Vec<u8>>,
    // The identity of a swappable certificate slot, which has no fixed chain to compare.
    slot: Option<String>,
}

impl fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerTls")
            .field("client_auth", &self.policy.client_auth)
            .finish_non_exhaustive()
    }
}

impl ServerTls {
    /// Read the certificate, key and client CA files; any unreadable or inconsistent file fails.
    pub fn load(options: &ServerOptions) -> io::Result<Self> {
        Self::load_restricted(options, &Restrictions::default())
    }

    /// [`ServerTls::load`] that also limits protocol versions, TLS 1.2 cipher suites and key exchange groups.
    pub fn load_restricted(
        options: &ServerOptions,
        restrictions: &Restrictions,
    ) -> io::Result<Self> {
        let provider = restricted_provider(restrictions)?;
        let versions = versions(restrictions, &provider)?;
        let chain = read_chain(&options.cert).map_err(load_error)?;
        let key = PrivateKeyDer::from_pem_file(&options.key)
            .map_err(|error| load_error(io::Error::other(error)))?;
        // CoreDNS v1.15.0 plugin/pkg/tls/tls.go NewTLSConfigFromArgs: one CA pool serves every client-verifying mode.
        let roots = match (&options.ca, options.client_auth) {
            (Some(path), _) => Some(read_roots(path)?),
            (None, ClientAuth::VerifyIfGiven | ClientAuth::RequireAndVerify) => {
                Some(system_roots()?)
            }
            (None, _) => None,
        };
        let algorithms = provider.signature_verification_algorithms;
        let verifier: Arc<dyn ClientCertVerifier> = match options.client_auth {
            ClientAuth::NoCert => WebPkiClientVerifier::no_client_auth(),
            ClientAuth::Request | ClientAuth::Require => Arc::new(UnverifiedClientCert {
                mandatory: options.client_auth == ClientAuth::Require,
                hints: roots
                    .as_ref()
                    .map(RootCertStore::subjects)
                    .unwrap_or_default(),
                algorithms,
            }),
            ClientAuth::VerifyIfGiven | ClientAuth::RequireAndVerify => {
                let roots = Arc::new(roots.clone().expect("verifying modes load roots"));
                let verifier = WebPkiClientVerifier::builder_with_provider(roots, provider.clone());
                let verifier = if options.client_auth == ClientAuth::VerifyIfGiven {
                    verifier.allow_unauthenticated()
                } else {
                    verifier
                };
                verifier.build().map_err(invalid)?
            }
        };
        let der_chain = chain.iter().map(|cert| cert.as_ref().to_vec()).collect();
        let key_log: Option<Arc<KeyLogFile>> = match &options.keylog {
            Some(path) => Some(Arc::new(KeyLogFile::open(path)?)),
            None => None,
        };
        let build =
            |versions: &[&'static rustls::SupportedProtocolVersion]| -> io::Result<ServerConfig> {
                let mut config = ServerConfig::builder_with_provider(Arc::clone(&provider))
                    .with_protocol_versions(versions)
                    .map_err(invalid)?
                    .with_client_cert_verifier(Arc::clone(&verifier))
                    .with_single_cert(chain.clone(), key.clone_key())
                    .map_err(|error| load_error(invalid(error)))?;
                // RFC 8446 §4.6.1: stateless tickets let reconnecting clients resume without server state.
                config.ticketer = aws_lc_rs::Ticketer::new().map_err(invalid)?;
                if let Some(log) = &key_log {
                    config.key_log = log.clone();
                }
                Ok(config)
            };
        // RFC 7858 §3.2: DoT uses TLS; RFC 9325 §3.1.1 forbids versions below TLS 1.2.
        let config = build(&versions)?;
        // RFC 9001 §4.2: QUIC requires TLS 1.3; RFC 9250 §4.1.1: DoQ negotiates ALPN "doq".
        let mut quic = build(&[&TLS13])?;
        quic.alpn_protocols = vec![b"doq".to_vec()];
        let quic_tls = Arc::new(quic);
        let quic = QuicServerConfig::try_from(Arc::clone(&quic_tls)).map_err(invalid)?;
        let mut client_cas = roots.map(|roots| {
            roots
                .roots
                .iter()
                .map(|anchor| {
                    let mut identity = anchor.subject.to_vec();
                    identity.extend_from_slice(&anchor.subject_public_key_info);
                    // RFC 5280 §4.2.1.10: name constraints change which chains a CA pool accepts.
                    if let Some(constraints) = &anchor.name_constraints {
                        identity.extend_from_slice(constraints);
                    }
                    identity
                })
                .collect::<Vec<_>>()
        });
        if let Some(cas) = &mut client_cas {
            cas.sort_unstable();
            cas.dedup();
        }
        Ok(Self {
            config: Arc::new(config),
            quic_tls,
            quic: Arc::new(quic),
            policy: Arc::new(Policy {
                client_auth: options.client_auth,
                client_cas,
                chain: der_chain,
                slot: None,
            }),
        })
    }

    /// An identity whose certificates `slot` supplies and may replace while Listeners serve.
    /// `identity` names the slot's configuration: Server Blocks may share a Listener only when it is equal.
    pub fn from_slot(slot: &Arc<CertSlot>, identity: &str) -> io::Result<Self> {
        let provider = provider();
        let build =
            |versions: &[&'static rustls::SupportedProtocolVersion]| -> io::Result<ServerConfig> {
                let mut config = ServerConfig::builder_with_provider(Arc::clone(&provider))
                    .with_protocol_versions(versions)
                    .map_err(invalid)?
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::clone(slot) as Arc<dyn ResolvesServerCert>);
                // RFC 8446 §4.6.1: stateless tickets let reconnecting clients resume without server state.
                config.ticketer = aws_lc_rs::Ticketer::new().map_err(invalid)?;
                Ok(config)
            };
        // RFC 7858 §3.2: DoT uses TLS; RFC 9325 §3.1.1 forbids versions below TLS 1.2.
        let config = build(&[&TLS13, &TLS12])?;
        // RFC 9001 §4.2: QUIC requires TLS 1.3; RFC 9250 §4.1.1: DoQ negotiates ALPN "doq".
        let mut quic = build(&[&TLS13])?;
        quic.alpn_protocols = vec![b"doq".to_vec()];
        // Every derived config (`with_alpn`, `with_quic_alpn`) clones one of these, so all keep the slot's resolver.
        let quic_tls = Arc::new(quic);
        let quic = QuicServerConfig::try_from(Arc::clone(&quic_tls)).map_err(invalid)?;
        Ok(Self {
            config: Arc::new(config),
            quic_tls,
            quic: Arc::new(quic),
            policy: Arc::new(Policy {
                client_auth: ClientAuth::NoCert,
                client_cas: None,
                chain: Vec::new(),
                slot: Some(identity.to_owned()),
            }),
        })
    }

    /// The TLS 1.3 identity with ALPN `doq` for QUIC connections.
    #[must_use]
    pub fn quic(&self) -> Arc<QuicServerConfig> {
        Arc::clone(&self.quic)
    }

    #[must_use]
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(Arc::clone(&self.config))
    }

    /// The same identity advertising `protocols` through ALPN, in server preference order.
    // RFC 7301 §3.1: the server selects an application protocol from the client's list.
    #[must_use]
    pub fn with_alpn(&self, protocols: &[&[u8]]) -> Self {
        let mut config = (*self.config).clone();
        config.alpn_protocols = protocols.iter().map(|protocol| protocol.to_vec()).collect();
        Self {
            config: Arc::new(config),
            quic_tls: Arc::clone(&self.quic_tls),
            quic: Arc::clone(&self.quic),
            policy: Arc::clone(&self.policy),
        }
    }

    /// The same identity advertising `protocols` through ALPN on QUIC connections.
    // RFC 9114 §3.1: HTTP/3 over QUIC is selected by ALPN "h3" instead of DoQ's "doq".
    pub fn with_quic_alpn(&self, protocols: &[&[u8]]) -> io::Result<Self> {
        let mut config = (*self.quic_tls).clone();
        config.alpn_protocols = protocols.iter().map(|protocol| protocol.to_vec()).collect();
        let quic_tls = Arc::new(config);
        let quic = QuicServerConfig::try_from(Arc::clone(&quic_tls)).map_err(invalid)?;
        Ok(Self {
            config: Arc::clone(&self.config),
            quic_tls,
            quic: Arc::new(quic),
            policy: Arc::clone(&self.policy),
        })
    }

    /// Why this identity cannot share a Listener with `other`, if it cannot.
    // CoreDNS v1.15.0 core/dnsserver/tlsconfig.go compatibleTLSConfig: same wording and order.
    #[must_use]
    pub fn conflict(&self, other: &Self) -> Option<&'static str> {
        let (a, b) = (&*self.policy, &*other.policy);
        if a.client_auth != b.client_auth {
            Some("client authentication policies differ")
        } else if a.client_cas != b.client_cas {
            Some("client CA pools differ")
        } else if a.chain != b.chain || a.slot != b.slot {
            Some("server certificates differ")
        } else {
            None
        }
    }
}

/// Certificates for a fixed set of names that can be replaced while handshakes are served.
///
/// A name that has no certificate yet fails its handshakes until [`CertSlot::load`] supplies one.
#[derive(Debug)]
pub struct CertSlot {
    slots: Vec<(String, ArcSwapOption<CertifiedKey>)>,
}

impl CertSlot {
    /// One empty slot per name, lowercase and without a trailing dot; `*.` prefixes match one label.
    /// A ClientHello without a server name gets the first name's certificate.
    #[must_use]
    pub fn new(names: &[String]) -> Arc<Self> {
        Arc::new(Self {
            slots: names
                .iter()
                .map(|name| (name.clone(), ArcSwapOption::empty()))
                .collect(),
        })
    }

    /// Replace `name`'s certificate with the PEM chain and private key in these files.
    pub fn load(&self, name: &str, cert: &Path, key: &Path) -> io::Result<()> {
        let (_, slot) = self
            .slots
            .iter()
            .find(|(candidate, _)| candidate == name)
            .ok_or_else(|| invalid(format!("{name} is not managed by this slot")))?;
        let chain = read_chain(cert).map_err(load_error)?;
        let key = PrivateKeyDer::from_pem_file(key)
            .map_err(|error| load_error(io::Error::other(error)))?;
        let signing = aws_lc_rs::sign::any_supported_type(&key)
            .map_err(|error| load_error(invalid(error)))?;
        let certified = CertifiedKey::new(chain, signing);
        // RFC 8555 §7.4: the issued certificate certifies the key the CSR carried.
        certified
            .keys_match()
            .map_err(|error| load_error(invalid(error)))?;
        slot.store(Some(Arc::new(certified)));
        Ok(())
    }

    /// Whether `name` has a certificate to serve.
    #[must_use]
    pub fn ready(&self, name: &str) -> bool {
        self.slots
            .iter()
            .any(|(candidate, slot)| candidate == name && slot.load().is_some())
    }
}

impl ResolvesServerCert for CertSlot {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let slot = match hello.server_name() {
            Some(server_name) => {
                let server_name = server_name.trim_end_matches('.');
                self.slots
                    .iter()
                    .find(|(name, _)| matches_name(name, server_name))
            }
            None => self.slots.first(),
        };
        slot.and_then(|(_, certificate)| certificate.load_full())
    }
}

// RFC 6125 §6.4.3: a wildcard stands for exactly one leftmost label; DNS names compare case-insensitively (RFC 4343 §3).
fn matches_name(pattern: &str, server_name: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => server_name
            .split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest.eq_ignore_ascii_case(suffix)),
        None => pattern.eq_ignore_ascii_case(server_name),
    }
}

/// Where an Upstream client finds trust anchors and its own identity.
#[derive(Clone, Debug, Default)]
pub struct ClientOptions {
    /// CA bundle that verifies the server; the system roots when absent.
    pub ca: Option<PathBuf>,
    /// Certificate chain and private key presented to servers that ask.
    pub identity: Option<(PathBuf, PathBuf)>,
}

/// Build a client configuration that verifies servers and offers TLS 1.2 or later.
pub fn client_config(options: &ClientOptions) -> io::Result<Arc<ClientConfig>> {
    let roots = match &options.ca {
        Some(path) => read_roots(path)?,
        None => system_roots()?,
    };
    // RFC 9325 §3.1.1: TLS 1.2 is the oldest version in use.
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13, &TLS12])
        .map_err(invalid)?
        .with_root_certificates(roots);
    let config = match &options.identity {
        None => builder.with_no_client_auth(),
        Some((cert, key)) => {
            let chain = read_chain(cert).map_err(load_error)?;
            let key = PrivateKeyDer::from_pem_file(key)
                .map_err(|error| load_error(io::Error::other(error)))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|error| load_error(invalid(error)))?
        }
    };
    Ok(Arc::new(config))
}

/// A client configuration that trusts the system roots and every certificate in `extra`.
// certmagic v0.25 ACMEIssuer.TrustedRoots: the system pool plus the extra bundle; an unreadable system pool is not fatal.
pub fn client_config_with_roots(extra: Option<&Path>) -> io::Result<Arc<ClientConfig>> {
    let mut roots = system_roots().unwrap_or_else(|_| RootCertStore::empty());
    if let Some(path) = extra {
        roots.roots.extend(read_roots(path)?.roots);
    }
    if roots.is_empty() {
        return Err(invalid("no trusted root certificates"));
    }
    // RFC 9325 §3.1.1: TLS 1.2 is the oldest version in use.
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS13, &TLS12])
        .map_err(invalid)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(aws_lc_rs::default_provider())
}

// RFC 8446 §9.1: TLS 1.3 suites are always on; the restricted names narrow only TLS 1.2 (RFC 5246 §7.4.1.2).
fn restricted_provider(restrictions: &Restrictions) -> io::Result<Arc<CryptoProvider>> {
    const TLS13_NAMES: [&str; 3] = [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ];
    const GO_ONLY_NAMES: [&str; 4] = [
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    ];
    let mut provider = aws_lc_rs::default_provider();
    if !restrictions.cipher_suites.is_empty() {
        let offered = |name: &str| {
            provider.cipher_suites.iter().any(|suite| {
                matches!(suite, SupportedCipherSuite::Tls12(_))
                    && suite.suite().as_str() == Some(name)
            })
        };
        for name in &restrictions.cipher_suites {
            if TLS13_NAMES.contains(&name.as_str()) || offered(name) {
                continue;
            }
            // Go's crypto/tls lists these as secure, but rustls has no CBC suites.
            if GO_ONLY_NAMES.contains(&name.as_str()) {
                crate::logging::log(
                    "WARN",
                    "tls",
                    &format!("cipher suite {name} is not supported and will not be offered"),
                );
                continue;
            }
            return Err(invalid(format!("unknown cipher: {name}")));
        }
        provider.cipher_suites.retain(|suite| match suite {
            SupportedCipherSuite::Tls13(_) => true,
            SupportedCipherSuite::Tls12(_) => suite.suite().as_str().is_some_and(|name| {
                restrictions
                    .cipher_suites
                    .iter()
                    .any(|wanted| wanted == name)
            }),
        });
    }
    if !restrictions.curves.is_empty() {
        let mut groups = Vec::new();
        for curve in &restrictions.curves {
            let wanted = match curve {
                Curve::P256 => NamedGroup::secp256r1,
                Curve::P384 => NamedGroup::secp384r1,
                Curve::X25519 => NamedGroup::X25519,
                Curve::P521 => {
                    crate::logging::log(
                        "WARN",
                        "tls",
                        "curve CurveP521 is not supported and will not be offered",
                    );
                    continue;
                }
            };
            if let Some(group) = aws_lc_rs::ALL_KX_GROUPS
                .iter()
                .find(|group| group.name() == wanted)
            {
                groups.push(*group);
            }
        }
        if groups.is_empty() {
            return Err(invalid("no supported key exchange group configured"));
        }
        provider.kx_groups = groups;
    }
    Ok(Arc::new(provider))
}

// RFC 8446 §4.2.1: the versions between the configured bounds that still have a cipher suite.
fn versions(
    restrictions: &Restrictions,
    provider: &CryptoProvider,
) -> io::Result<Vec<&'static rustls::SupportedProtocolVersion>> {
    if restrictions.min_version > restrictions.max_version {
        return Err(invalid("minimum TLS version is above the maximum"));
    }
    let has = |tls13: bool| {
        provider
            .cipher_suites
            .iter()
            .any(|suite| matches!(suite, SupportedCipherSuite::Tls13(_)) == tls13)
    };
    let mut versions = Vec::new();
    if restrictions.max_version >= Version::Tls13 && has(true) {
        versions.push(&TLS13);
    }
    if restrictions.min_version <= Version::Tls12 && has(false) {
        versions.push(&TLS12);
    }
    if versions.is_empty() {
        return Err(invalid("no TLS version has a cipher suite to offer"));
    }
    Ok(versions)
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error)
}

// CoreDNS v1.15.0 plugin/pkg/tls/tls.go NewTLSConfig: "could not load TLS cert: %s".
fn load_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("could not load TLS cert: {error}"))
}

fn read_chain(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let chain = CertificateDer::pem_file_iter(path)
        .map_err(io::Error::other)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)?;
    if chain.is_empty() {
        return Err(invalid(format!(
            "no certificate found in {}",
            path.display()
        )));
    }
    Ok(chain)
}

// CoreDNS v1.15.0 plugin/pkg/tls/tls.go loadRoots: unreadable or empty CA files are errors.
fn read_roots(path: &Path) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|error| io::Error::other(format!("error reading {}: {error}", path.display())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io::Error::other(format!("error reading {}: {error}", path.display())))?;
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(invalid(format!(
            "could not read root certs: no certificates in {}",
            path.display()
        )));
    }
    Ok(roots)
}

fn system_roots() -> io::Result<RootCertStore> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(loaded.certs);
    if roots.is_empty() {
        let detail = loaded
            .errors
            .first()
            .map_or_else(|| "none found".to_owned(), ToString::to_string);
        return Err(io::Error::other(format!(
            "could not load system root certificates: {detail}"
        )));
    }
    Ok(roots)
}

/// Asks for a client certificate and accepts whatever chain it carries, like Go's
/// `RequestClientCert` and `RequireAnyClientCert`; the handshake signature is still checked.
#[derive(Debug)]
struct UnverifiedClientCert {
    mandatory: bool,
    hints: Vec<DistinguishedName>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for UnverifiedClientCert {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Appends secrets in the NSS Key Log Format; Wireshark reads it.
#[derive(Debug)]
struct KeyLogFile(Mutex<File>);

impl KeyLogFile {
    fn open(path: &Path) -> io::Result<Self> {
        let absolute = std::path::absolute(path)?;
        // CoreDNS v1.15.0 plugin/tls/tls.go: the log is created 0600 and appended to.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&absolute)
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("unable to write TLS Key Log to {:?}: {error}", absolute),
                )
            })?;
        crate::logging::log(
            "WARN",
            "tls",
            &format!("Writing TLS Key Log to {absolute:?}"),
        );
        Ok(Self(Mutex::new(file)))
    }
}

impl rustls::KeyLog for KeyLogFile {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        // NSS Key Log Format: "<label> <hex client random> <hex secret>".
        let mut line =
            String::with_capacity(label.len() + 2 * (client_random.len() + secret.len()) + 3);
        line.push_str(label);
        line.push(' ');
        for byte in client_random {
            let _ = write!(line, "{byte:02x}");
        }
        line.push(' ');
        for byte in secret {
            let _ = write!(line, "{byte:02x}");
        }
        line.push('\n');
        if let Ok(mut file) = self.0.lock() {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::matches_name;

    // CoreDNS v1.15.0 plugin/tls/acme_test.go TestACMEEntryManagedNames.
    #[test]
    fn names_match_exactly_or_through_one_wildcard_label() {
        for (pattern, name, expected) in [
            ("dns.example", "DNS.EXAMPLE", true),
            ("*.wild.example", "one.wild.example", true),
            ("*.wild.example", "two.one.wild.example", false),
            ("*.wild.example", "wild.example", false),
            ("*.wild.example", ".wild.example", false),
            ("dns.example", "other.example", false),
        ] {
            assert_eq!(matches_name(pattern, name), expected, "{pattern} {name}");
        }
    }
}
