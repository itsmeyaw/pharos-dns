//! SkyDNS service discovery from etcd v3.

pub mod msg;
pub(crate) mod setup;
mod ttl;

use std::sync::Arc;

use pharos_proto::Name;
use pharos_server::{Context, Next, Outcome, Plugin, tls::ClientConfig};

/// CoreDNS v1.15.0 plugin/etcd/setup.go `etcdParse`: the `path` when none is given.
pub const DEFAULT_PATH: &str = "skydns";

/// CoreDNS v1.15.0 plugin/etcd/setup.go `defaultEndpoint`.
pub const DEFAULT_ENDPOINT: &str = "http://localhost:2379";

/// CoreDNS v1.15.0 plugin/etcd/etcd.go `defaultLeaseMinTTL`.
pub const DEFAULT_MIN_LEASE_TTL: u32 = 30;

/// CoreDNS v1.15.0 plugin/etcd/etcd.go `defaultLeaseMaxTTL`.
pub const DEFAULT_MAX_LEASE_TTL: u32 = 86400;

/// One etcd client endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    /// The endpoint as written in the Corefile.
    pub text: String,
    /// Host name or IP address, without the brackets of an IPv6 address.
    pub host: String,
    pub port: u16,
    /// Whether the connection uses TLS: `https://` always, `http://` never, and a bare
    /// `host:port` when the Directive has `tls`. With `tls` unset, TLS verifies against the system roots.
    pub tls: bool,
}

/// The `credentials` of the Directive.
#[derive(Clone, Eq, PartialEq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// One `etcd` Directive, as parsed. Parsing makes no connection to etcd.
#[derive(Clone, Debug)]
pub struct Config {
    /// Zones the Plugin is authoritative for.
    pub zones: Vec<Name>,
    /// Zones whose Queries pass to the next Plugin when nothing is found; empty without `fallthrough`.
    pub fallthrough: Vec<Name>,
    /// The `path` as written; the key prefix is `/` + this (CoreDNS `msg.Path`).
    pub path_prefix: String,
    pub endpoints: Vec<Endpoint>,
    /// The client configuration of `tls`, with ALPN `h2`, for endpoints that use TLS. Without it
    /// an endpoint that needs TLS verifies against the system roots.
    pub tls: Option<Arc<ClientConfig>>,
    pub credentials: Option<Credentials>,
    /// Lower bound of a lease TTL used as a record TTL; `0` means [`DEFAULT_MIN_LEASE_TTL`].
    pub min_lease_ttl: u32,
    /// Upper bound of a lease TTL used as a record TTL; `0` means [`DEFAULT_MAX_LEASE_TTL`].
    pub max_lease_ttl: u32,
    /// Disables the legacy zone-root lookup when `apex.dns` records are absent.
    pub no_apex_fallback: bool,
}

/// The `etcd` Plugin.
#[derive(Debug)]
pub struct Etcd {
    config: Config,
}

impl Etcd {
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// CoreDNS v1.15.0 plugin/etcd/etcd.go OnShutdown: closes the etcd client, which does not exist yet.
    pub(crate) fn stop(&self) {}
}

impl Plugin for Etcd {
    // shortcut: every Query passes to the next Plugin until the etcd backend lands.
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        next.run(cx).await
    }
}
