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

use rustls::{
    ClientConfig, DistinguishedName, RootCertStore, ServerConfig, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    crypto::{
        CryptoProvider, WebPkiSupportedAlgorithms, aws_lc_rs, verify_tls12_signature,
        verify_tls13_signature,
    },
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject},
    server::{
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
    version::{TLS12, TLS13},
};

pub use tokio_rustls::{TlsAcceptor, TlsConnector};

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

/// A loaded server identity. Cloning shares the same rustls configuration.
#[derive(Clone)]
pub struct ServerTls {
    config: Arc<ServerConfig>,
    policy: Arc<Policy>,
}

/// The settings CoreDNS compares before two Server Blocks may share a Listener.
#[derive(Eq, PartialEq)]
struct Policy {
    client_auth: ClientAuth,
    client_cas: Option<Vec<Vec<u8>>>,
    chain: Vec<Vec<u8>>,
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
        let provider = provider();
        // RFC 7858 §3.2: DoT uses TLS; RFC 9325 §3.1.1 forbids versions below TLS 1.2.
        let builder = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&TLS13, &TLS12])
            .map_err(invalid)?;
        let chain = read_chain(&options.cert).map_err(load_error)?;
        let key = PrivateKeyDer::from_pem_file(&options.key)
            .map_err(|error| load_error(io::Error::other(error)))?;
        // RFC 5280 §4.2.1.3: CA files and the client verifier agree on one pool.
        let roots = match (&options.ca, options.client_auth) {
            (Some(path), _) => Some(read_roots(path)?),
            (None, ClientAuth::VerifyIfGiven | ClientAuth::RequireAndVerify) => {
                Some(system_roots()?)
            }
            (None, _) => None,
        };
        let algorithms = provider.signature_verification_algorithms;
        let builder = match options.client_auth {
            ClientAuth::NoCert => builder.with_no_client_auth(),
            ClientAuth::Request | ClientAuth::Require => {
                builder.with_client_cert_verifier(Arc::new(UnverifiedClientCert {
                    mandatory: options.client_auth == ClientAuth::Require,
                    hints: roots
                        .as_ref()
                        .map(RootCertStore::subjects)
                        .unwrap_or_default(),
                    algorithms,
                }))
            }
            ClientAuth::VerifyIfGiven | ClientAuth::RequireAndVerify => {
                let roots = Arc::new(roots.clone().expect("verifying modes load roots"));
                let verifier = WebPkiClientVerifier::builder_with_provider(roots, provider);
                let verifier = if options.client_auth == ClientAuth::VerifyIfGiven {
                    verifier.allow_unauthenticated()
                } else {
                    verifier
                };
                builder.with_client_cert_verifier(verifier.build().map_err(invalid)?)
            }
        };
        let der_chain = chain.iter().map(|cert| cert.as_ref().to_vec()).collect();
        let mut config = builder
            .with_single_cert(chain, key)
            .map_err(|error| load_error(invalid(error)))?;
        // RFC 8446 §4.6.1: stateless tickets let reconnecting clients resume without server state.
        config.ticketer = aws_lc_rs::Ticketer::new().map_err(invalid)?;
        if let Some(path) = &options.keylog {
            config.key_log = Arc::new(KeyLogFile::open(path)?);
        }
        let mut client_cas = roots.map(|roots| {
            roots
                .roots
                .iter()
                .map(|anchor| {
                    let mut identity = anchor.subject.to_vec();
                    identity.extend_from_slice(&anchor.subject_public_key_info);
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
            policy: Arc::new(Policy {
                client_auth: options.client_auth,
                client_cas,
                chain: der_chain,
            }),
        })
    }

    #[must_use]
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(Arc::clone(&self.config))
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
        } else if a.chain != b.chain {
            Some("server certificates differ")
        } else {
            None
        }
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

fn provider() -> Arc<CryptoProvider> {
    Arc::new(aws_lc_rs::default_provider())
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
            .write(true)
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
