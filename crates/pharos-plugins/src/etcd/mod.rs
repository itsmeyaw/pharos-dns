//! SkyDNS service discovery from etcd v3.

mod backend;
pub mod client;
mod direct;
pub mod msg;
mod scratch;
pub(crate) mod setup;
mod ttl;
pub mod view;

#[cfg(test)]
#[path = "../../tests/support/etcd_stub.rs"]
mod etcd_stub;

#[cfg(test)]
mod tests;

use std::{fmt::Write, sync::Arc};

use pharos_proto::{BuildError, MessageBuilder, Name, NameRef, Rcode, Section};
use pharos_server::{Context, Next, Outcome, Plugin, Protocol, tls::ClientConfig};

use backend::Failure;

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
    /// `config.zones` lowercased, in the form of an etcd key.
    zone_keys: Vec<String>,
    view: view::View,
}

impl Etcd {
    #[must_use]
    pub fn new(config: Config) -> Self {
        let view = view::View::new(&config);
        let zone_keys = config.zones.iter().map(Name::canonical).collect();
        Self {
            config,
            zone_keys,
            view,
        }
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
        let (name, qtype) = (question.name, question.qtype);
        let Some((zone, zone_key)) = self.zone_of(name) else {
            return next.run(cx).await;
        };
        let mut key = scratch::lease();
        // RFC 4343 §3.1: names are looked up in lowercase, which the presentation form of a lowercased name is.
        let _ = write!(key, "{name}");
        key.make_ascii_lowercase();
        let lookup = backend::Lookup {
            etcd: self,
            cx,
            zone,
            zone_key,
        };
        let first = match lookup.first(&key, qtype).await {
            Ok(first) => first,
            // CoreDNS v1.15.0 plugin/etcd/handler.go: a name error falls through where configured.
            Err(Failure::NameError) if self.falls_through(name) => return next.run(cx).await,
            // CoreDNS v1.15.0 plugin/backend_lookup.go BackendError: NXDOMAIN or SERVFAIL, each with the SOA.
            Err(failure) => {
                let rcode = match failure {
                    Failure::NameError => Rcode::NXDOMAIN,
                    Failure::Other => Rcode::SERVFAIL,
                };
                return respond(cx, rcode, false, |builder| {
                    direct::soa(builder, zone, Section::Authority).map(drop)
                });
            }
        };
        if direct::handles(qtype, first.as_ref()) {
            return respond(cx, Rcode::NOERROR, false, |builder| {
                let written = direct::answers(builder, name, zone, qtype, first.as_ref())?;
                // RFC 2308 §3: a negative Response carries the zone SOA.
                if written == 0 {
                    direct::soa(builder, zone, Section::Authority)?;
                }
                Ok(())
            });
        }
        drop(key);
        let lookup = backend::Lookup {
            etcd: self,
            cx,
            zone,
            zone_key,
        };
        let q = backend::Query::new(name.to_name(), qtype);
        let (rcode, answer) = match lookup.answer(&q, first).await {
            Err(Failure::NameError) if self.falls_through(name) => return next.run(cx).await,
            Err(Failure::NameError) => (Rcode::NXDOMAIN, None),
            Err(Failure::Other) => (Rcode::SERVFAIL, None),
            Ok(answer) if answer.records.is_empty() => (Rcode::NOERROR, None),
            Ok(answer) => (Rcode::NOERROR, Some(answer)),
        };
        respond(
            cx,
            rcode,
            answer.as_ref().is_some_and(|answer| answer.truncated),
            |builder| {
                if let Some(answer) = &answer {
                    for record in &answer.records {
                        record.write(builder, Section::Answer)?;
                    }
                    for record in &answer.extra {
                        record.write(builder, Section::Additional)?;
                    }
                } else {
                    direct::soa(builder, zone, Section::Authority)?;
                }
                Ok(())
            },
        )
    }
}

impl Etcd {
    /// CoreDNS v1.15.0 plugin/normalize.go Zones.Matches: the longest zone holding the name, with its key.
    fn zone_of(&self, name: NameRef<'_>) -> Option<(&Name, &str)> {
        let zones = &self.config.zones;
        let mut best: Option<usize> = None;
        for (index, zone) in zones.iter().enumerate() {
            // `max_by_key` keeps the last of the longest zones.
            if is_under(name, zone)
                && best.is_none_or(|best| zone.label_count() >= zones[best].label_count())
            {
                best = Some(index);
            }
        }
        best.map(|index| (&zones[index], self.zone_keys[index].as_str()))
    }

    /// CoreDNS v1.15.0 plugin/pkg/fall Through: whether `fallthrough` covers the name.
    fn falls_through(&self, name: NameRef<'_>) -> bool {
        self.config
            .fallthrough
            .iter()
            .any(|zone| is_under(name, zone))
    }
}

/// RFC 1034 §3.1: whether `name` is at or below `zone`, comparing labels without case.
fn is_under(name: NameRef<'_>, zone: &Name) -> bool {
    let zone = zone.as_name_ref();
    let (have, want) = (name.labels().count(), zone.labels().count());
    have >= want
        && name
            .labels()
            .skip(have - want)
            .zip(zone.labels())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

/// Write the Response with `rcode`, the records `fill` adds and TC when `truncated`.
fn respond(
    cx: &mut Context<'_, '_>,
    rcode: Rcode,
    truncated: bool,
    fill: impl FnOnce(&mut MessageBuilder<'_>) -> Result<(), BuildError>,
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
    if truncated {
        flags |= 0x0200;
    }
    let result = (|| {
        let mut builder = MessageBuilder::new(cx.response, max, query.id(), flags)?;
        builder.question(question.name, question.qtype, question.qclass)?;
        fill(&mut builder)?;
        let _ = builder.finish();
        Ok(())
    })();
    match result {
        Ok(()) => Outcome::Response,
        Err(error) => Outcome::Error(pharos_server::Error::Build(error)),
    }
}
