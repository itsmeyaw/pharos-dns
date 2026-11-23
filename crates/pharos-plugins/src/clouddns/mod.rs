//! Authoritative Zones served from Google Cloud DNS managed zones.

mod api;
mod auth;
mod http;
mod records;
pub(crate) mod setup;
#[cfg(test)]
mod stub;
#[cfg(test)]
mod tests;
mod update;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use pharos_proto::{Class, Name, Rcode};
use pharos_server::{Context, Error, Next, Outcome, Plugin};
use tokio::task::JoinHandle;

use crate::zone::{ZoneHolder, contains};

/// One hosted zone of a DNS name: where it lives in Cloud DNS and its current Zone.
#[derive(Debug)]
struct Hosted {
    project: String,
    zone: String,
    current: ZoneHolder,
}

/// A DNS name and the hosted zones that back it, in Corefile order.
#[derive(Debug)]
struct DnsName {
    apex: Name,
    hosted: Vec<Hosted>,
}

/// One `clouddns` line: CoreDNS builds one handler per line, so each keeps its own names, credentials and refresh.
#[derive(Debug)]
struct Instance {
    names: Vec<DnsName>,
    fallthrough: Vec<Name>,
    refresh: Duration,
    credentials: Option<PathBuf>,
    endpoint: String,
    api: Mutex<Option<api::Api>>,
}

#[derive(Debug)]
struct Shared {
    instances: Vec<Arc<Instance>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

/// Serves Zones loaded from Google Cloud DNS.
#[derive(Debug)]
pub struct CloudDns {
    shared: Arc<Shared>,
}

/// What one `clouddns` line made of a Query.
enum Step {
    Done(Outcome),
    /// The line did not answer; the next line, or the next Plugin, may.
    Pass,
}

/// Stands in for the next Plugin while a hosted zone is consulted: `Zone::lookup` only runs it to fall through.
struct Pass;

impl Next for Pass {
    fn run(self, _cx: &mut Context<'_, '_>) -> impl Future<Output = Outcome> + Send {
        std::future::ready(Outcome::Error(Error::NoNextPlugin))
    }
}

// CoreDNS v1.15.0 plugin/clouddns/clouddns.go ServeDNS: a hosted zone's result is final when it has an Answer or
// is NODATA. NXDOMAIN, a delegation (no AA) and a failed lookup have neither, so the next hosted zone is tried.
fn is_final(outcome: &Outcome, response: &[u8]) -> bool {
    match outcome {
        Outcome::Unanswered(rcode) => *rcode != Rcode::SERVFAIL,
        // RFC 1035 §4.1.1: header octets 2-3 carry AA and RCODE, octets 6-7 ANCOUNT.
        Outcome::Response => match response.get(..8) {
            Some(header) if header[6] == 0 && header[7] == 0 => {
                let rcode = u16::from(header[3] & 0x0f);
                rcode != Rcode::NXDOMAIN.0 && !(rcode == Rcode::NOERROR.0 && header[2] & 0x04 == 0)
            }
            _ => true,
        },
        _ => true,
    }
}

impl Instance {
    // CoreDNS v1.15.0 plugin/clouddns/clouddns.go ServeDNS: the longest configured name containing QNAME.
    fn matching(&self, name: &[u8]) -> Option<&DnsName> {
        self.names
            .iter()
            .filter(|candidate| contains(name, &candidate.apex))
            .max_by_key(|candidate| candidate.apex.label_count())
    }

    async fn serve(&self, cx: &mut Context<'_, '_>, name: &[u8], dns_name: &DnsName) -> Step {
        let last = dns_name.hosted.len() - 1;
        for (index, hosted) in dns_name.hosted.iter().enumerate() {
            // CoreDNS v1.15.0 plugin/clouddns/clouddns.go ServeDNS: only the last hosted zone's result can fall through.
            let fallthrough: &[Name] = if index == last {
                &self.fallthrough
            } else {
                &[]
            };
            let snapshot = hosted.current.load();
            let outcome = match snapshot.as_ref() {
                // Zone::lookup rewrites the whole Response, so a hosted zone's result never leaks into the next.
                Some(zone) => zone.lookup(cx, Pass, fallthrough).await,
                // CoreDNS v1.15.0 plugin/clouddns/clouddns.go ServeDNS: a hosted zone with no data is a failed lookup.
                None => Outcome::Unanswered(Rcode::SERVFAIL),
            };
            drop(snapshot);
            if matches!(outcome, Outcome::Error(Error::NoNextPlugin)) {
                return Step::Pass;
            }
            if is_final(&outcome, cx.response) {
                return Step::Done(outcome);
            }
            // CoreDNS v1.15.0 plugin/clouddns/clouddns.go ServeDNS: the last result stands unless `fallthrough`
            // covers QNAME; `Zone::lookup` handles NXDOMAIN, this covers SERVFAIL and delegations.
            if index == last {
                return if self.fallthrough.iter().any(|apex| contains(name, apex)) {
                    Step::Pass
                } else {
                    Step::Done(outcome)
                };
            }
        }
        Step::Pass
    }
}

impl Plugin for CloudDns {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        // RFC 1035 §3.7.1: the Zones answer class IN only.
        if question.qclass != Class::IN && question.qclass != Class::ANY {
            return next.run(cx).await;
        }
        let mut wire = [0u8; 255];
        let mut len = 0;
        for label in question.name.labels() {
            wire[len] = label.len() as u8;
            len += 1;
            wire[len..len + label.len()].copy_from_slice(label);
            len += label.len();
        }
        let name = &wire[..len + 1];
        for instance in &self.shared.instances {
            let Some(dns_name) = instance.matching(name) else {
                continue;
            };
            if let Step::Done(outcome) = instance.serve(cx, name, dns_name).await {
                return outcome;
            }
        }
        next.run(cx).await
    }
}
