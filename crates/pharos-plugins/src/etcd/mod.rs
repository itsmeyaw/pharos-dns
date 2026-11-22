//! SkyDNS service discovery from etcd v3.

mod backend;
pub mod client;
pub mod msg;
pub(crate) mod setup;
mod ttl;
pub mod view;

#[cfg(test)]
#[path = "../../tests/support/etcd_stub.rs"]
mod etcd_stub;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use pharos_proto::{MessageBuilder, Name, Rcode, Section};
use pharos_server::{Context, Next, Outcome, Plugin, Protocol, tls::ClientConfig};

use backend::{Answer, Failure, Rr};

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
    view: view::View,
}

impl Etcd {
    #[must_use]
    pub fn new(config: Config) -> Self {
        let view = view::View::new(&config);
        Self { config, view }
    }

    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The etcd keys the Plugin serves from, read through a bounded cache.
    #[must_use]
    pub fn view(&self) -> &view::View {
        &self.view
    }

    /// CoreDNS v1.15.0 plugin/etcd/etcd.go OnShutdown: closes the etcd client.
    pub(crate) fn stop(&self) {
        self.view.stop();
    }
}

impl Plugin for Etcd {
    // CoreDNS v1.15.0 plugin/etcd/handler.go ServeDNS.
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let query = cx.query;
        let Some(question) = query.questions().next() else {
            return next.run(cx).await;
        };
        let name = question.name.to_name();
        // CoreDNS v1.15.0 plugin/normalize.go Zones.Matches: the longest zone holding the name.
        let Some(zone) = self
            .config
            .zones
            .iter()
            .filter(|zone| name.is_subdomain_of(zone))
            .max_by_key(|zone| zone.label_count())
        else {
            return next.run(cx).await;
        };
        let lookup = backend::Lookup {
            etcd: self,
            cx,
            zone,
            zone_key: zone.canonical(),
        };
        let q = backend::Query::new(name, question.qtype);
        let result = lookup.answer(&q).await;
        let soa = lookup.soa();
        let (rcode, answer) = match result {
            // CoreDNS v1.15.0 plugin/etcd/handler.go: a name error falls through where configured.
            Err(Failure::NameError) if self.falls_through(&q.owner) => return next.run(cx).await,
            // CoreDNS v1.15.0 plugin/backend_lookup.go BackendError: NXDOMAIN, SERVFAIL or NODATA, each with the SOA.
            Err(Failure::NameError) => (Rcode::NXDOMAIN, None),
            Err(Failure::Other) => (Rcode::SERVFAIL, None),
            Ok(answer) if answer.records.is_empty() => (Rcode::NOERROR, None),
            Ok(answer) => (Rcode::NOERROR, Some(answer)),
        };
        respond(cx, rcode, answer.as_ref(), soa.as_ref())
    }
}

impl Etcd {
    /// CoreDNS v1.15.0 plugin/pkg/fall Through: whether `fallthrough` covers the name.
    fn falls_through(&self, name: &Name) -> bool {
        self.config
            .fallthrough
            .iter()
            .any(|zone| name.is_subdomain_of(zone))
    }
}

/// Write the Response: `answer` when there is one, else the SOA in Authority.
fn respond(
    cx: &mut Context<'_, '_>,
    rcode: Rcode,
    answer: Option<&Answer>,
    soa: Option<&Rr>,
) -> Outcome {
    let query = cx.query;
    let Some(question) = query.questions().next() else {
        return Outcome::Unanswered(Rcode::SERVFAIL);
    };
    let max = cx.max_response_size.max(512);
    if cx.response.capacity() < max {
        if cx.protocol == Protocol::Tcp {
            cx.response.reserve(max.saturating_sub(cx.response.len()));
        } else {
            return Outcome::Error(pharos_server::Error::ResponseBufferTooSmall);
        }
    }
    // RFC 1035 §4.1.1: QR, AA, and the opcode, RD and CD of the Query; CoreDNS marks every Response authoritative.
    let mut flags = 0x8400 | (query.flags() & 0x7910) | rcode.0;
    if answer.is_some_and(|answer| answer.truncated) {
        flags |= 0x0200;
    }
    let result = (|| {
        let mut builder = MessageBuilder::new(cx.response, max, query.id(), flags)?;
        builder.question(question.name, question.qtype, question.qclass)?;
        if let Some(answer) = answer {
            for record in &answer.records {
                record.write(&mut builder, Section::Answer)?;
            }
            for record in &answer.extra {
                record.write(&mut builder, Section::Additional)?;
            }
        } else if let Some(soa) = soa {
            // RFC 2308 §3: a negative Response carries the zone SOA.
            soa.write(&mut builder, Section::Authority)?;
        }
        let _ = builder.finish();
        Ok(())
    })();
    match result {
        Ok(()) => Outcome::Response,
        Err(error) => Outcome::Error(pharos_server::Error::Build(error)),
    }
}
