//! Serve A, AAAA and SRV records for services registered with Nomad.

mod client;
mod escape;
mod registration;
mod response;
pub(crate) mod setup;
#[cfg(test)]
mod stub;

use pharos_proto::{Class, Name, NameRef, Opcode};
use pharos_server::{Context, Next, Outcome, Plugin, Protocol};

use client::{Client, Options};
use response::Reply;

/// CoreDNS v1.15.0 plugin/nomad/nomad.go `defaultTTL`: seconds a Response record lives unless `ttl` says otherwise.
const DEFAULT_TTL: u32 = 30;
const DEFAULT_ADDRESS: &str = "http://127.0.0.1:4646";

/// CoreDNS v1.15.0 plugin/nomad/setup.go `parse`: the values one `nomad` Directive configures.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Settings {
    pub(crate) zone: String,
    pub(crate) ttl: u32,
    pub(crate) filter: String,
    pub(crate) token: Option<String>,
    pub(crate) addresses: Vec<String>,
}

// The token stays out of Debug output.
impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("zone", &self.zone)
            .field("ttl", &self.ttl)
            .field("filter", &self.filter)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("addresses", &self.addresses)
            .finish()
    }
}

/// One `nomad` Directive.
#[derive(Debug)]
pub struct Nomad {
    ttl: u32,
    filter: String,
    /// The lower-cased wire name of the zone and its label count.
    zone: Vec<u8>,
    zone_labels: usize,
    /// The wire name `hostmaster.<zone>`.
    mailbox: Vec<u8>,
    client: Client,
}

impl Nomad {
    pub(crate) fn new(
        settings: Settings,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, String> {
        // CoreDNS v1.15.0 plugin/nomad/nomad.go processQName: `dns.Fqdn(zone)`.
        let mut zone = settings.zone;
        if !zone.ends_with('.') {
            zone.push('.');
        }
        let zone: Name = zone
            .parse()
            .map_err(|error| format!("invalid zone: {error}"))?;
        let mut mailbox = b"\x0ahostmaster".to_vec();
        mailbox.extend_from_slice(zone.as_wire());
        // RFC 1035 §2.3.4: the SOA mailbox, `hostmaster.<zone>`, is a name of at most 255 octets.
        NameRef::parse(&mailbox, 0).map_err(|error| format!("invalid zone: {error}"))?;
        let mut addresses = settings.addresses;
        if addresses.is_empty() {
            addresses.push(
                env("NOMAD_ADDR")
                    .filter(|address| !address.is_empty())
                    .unwrap_or_else(|| DEFAULT_ADDRESS.to_owned()),
            );
        }
        let https = addresses
            .iter()
            .any(|address| address.starts_with("https://"));
        let options = Options::from_env(env, settings.token, https)?;
        Ok(Self {
            ttl: settings.ttl,
            filter: settings.filter,
            zone: zone.as_wire().to_ascii_lowercase(),
            zone_labels: zone.label_count(),
            mailbox,
            client: Client::new(&addresses, options)?,
        })
    }

    /// The service and namespace labels of a lower-cased Query name inside the zone.
    // CoreDNS v1.15.0 plugin/nomad/nomad.go processQName and extractNamespaceAndService: `<service>.<namespace>.<zone>`, further labels ignored.
    fn split<'w>(&self, wire: &'w [u8]) -> Option<(&'w [u8], &'w [u8])> {
        let mut starts = [0_usize; 128];
        let (mut count, mut at) = (0, 0);
        while wire[at] != 0 {
            starts[count] = at;
            count += 1;
            at += 1 + usize::from(wire[at]);
        }
        starts[count] = at;
        // CoreDNS dnsutil.TrimZone: a name no longer than the zone is out of it; here the zone must also be the name's suffix.
        let base = count
            .checked_sub(self.zone_labels)
            .filter(|base| *base >= 2)?;
        if wire[starts[base]..] != self.zone[..] {
            return None;
        }
        let label = |index: usize| {
            &wire[starts[index] + 1..starts[index] + 1 + usize::from(wire[starts[index]])]
        };
        Some((label(0), label(1)))
    }
}

impl Plugin for Nomad {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        // RFC 1035 §6.2: Nomad data is IN-class; QCLASS=ANY matches it.
        if question.qclass != Class::IN && question.qclass != Class::ANY {
            return next.run(cx).await;
        }
        // RFC 4343 §3: names compare case-insensitively; CoreDNS lower-cases the Query name.
        let mut wire = [0_u8; 255];
        let mut len = 0;
        for label in question.name.labels() {
            wire[len] = label.len() as u8;
            len += 1;
            for byte in label {
                wire[len] = byte.to_ascii_lowercase();
                len += 1;
            }
        }
        len += 1;
        let wire = &wire[..len];
        let Some((service, namespace)) = self.split(wire) else {
            return next.run(cx).await;
        };
        let max = cx.max_response_size.max(512);
        if cx.response.capacity() < max {
            if cx.protocol == Protocol::Tcp {
                cx.response.reserve(max.saturating_sub(cx.response.len()));
            } else {
                return Outcome::Error(pharos_server::Error::ResponseBufferTooSmall);
            }
        }
        let registrations = match self
            .client
            .registrations(service, namespace, &self.filter)
            .await
        {
            Ok(registrations) => Some(registrations),
            Err(error) => {
                // CoreDNS v1.15.0 plugin/nomad/nomad.go ServeDNS: a failed lookup is logged and answered empty.
                pharos_server::logging::log_bounded(
                    "WARN",
                    "nomad",
                    format_args!("service lookup failed: {error}"),
                );
                None
            }
        };
        // RFC 1035 §4.1.1: Responses set QR and copy the opcode and RD; CoreDNS sets AA.
        let mut flags = 0x8400 | (cx.query.flags() & 0x7800);
        if cx.query.opcode() == Opcode::QUERY {
            flags |= cx.query.flags() & 0x0110;
        }
        let reply = Reply {
            id: cx.query.id(),
            flags,
            max_size: max,
            question,
            owner: wire,
            ttl: self.ttl,
            mailbox: &self.mailbox,
        };
        response::build(cx.response, &reply, registrations.as_deref())
            .map_or_else(Outcome::Error, |()| Outcome::Response)
    }
}

#[cfg(test)]
mod tests;
