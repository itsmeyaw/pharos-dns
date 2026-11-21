//! dnstap Directive: logs Queries and Responses as dnstap messages.

pub mod msg;
pub(crate) mod setup;

use pharos_server::{Context, Next, Outcome, Plugin};

/// Where a sink connects or listens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Endpoint {
    /// A Unix domain socket path.
    Unix(String),
    /// A TCP `host:port`.
    Tcp(String),
    /// A TLS-over-TCP `host:port`.
    Tls(String),
}

/// Whether a `dnstap` Directive dials a sink or accepts sinks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Pharos connects out to a collector.
    Dial,
    /// Collectors connect in (`dnstap listen ...`).
    Listen,
}

/// The `tls CERT KEY [CA]` files of a `listen` Directive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsFiles {
    pub cert: String,
    pub key: String,
    pub ca: Option<String>,
}

/// One parsed `dnstap` Directive. Plain data: parsing starts no IO.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub role: Role,
    pub endpoint: Endpoint,
    /// `full`: include the raw DNS message in each dnstap message.
    pub full: bool,
    /// Write buffer in MiB units per TCP connection.
    pub write_buffer: u32,
    /// Queue size in units of 10,000 messages.
    pub queue: u32,
    pub identity: Vec<u8>,
    pub version: Vec<u8>,
    /// The `extra` format, empty when unset.
    pub extra: String,
    pub skip_verify: bool,
    /// Set only for a `tls://` listener with a `tls` block line.
    pub tls: Option<TlsFiles>,
}

/// The `dnstap` Directives of one Server Block.
#[derive(Debug)]
pub struct Dnstap {
    configs: Vec<Config>,
}

impl Dnstap {
    /// The parsed Directives in Corefile order.
    #[must_use]
    pub fn configs(&self) -> &[Config] {
        &self.configs
    }
}

impl Plugin for Dnstap {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        next.run(cx).await
    }
}
