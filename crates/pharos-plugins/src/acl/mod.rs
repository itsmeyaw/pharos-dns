//! Source-address access control.

pub(crate) mod setup;

use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Opcode, Section, Type};
use pharos_server::{Context, Next, Outcome, Plugin, Protocol};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug)]
pub struct Acl {
    rules: Vec<Rule>,
    metrics: Vec<(SocketAddr, pharos_server::metrics::AclMetrics)>,
    view_metrics: Vec<(SocketAddr, String, pharos_server::metrics::AclMetrics)>,
}

#[derive(Debug)]
struct Rule {
    domains: Vec<Name>,
    policies: Vec<Policy>,
    metrics: Vec<(SocketAddr, Vec<pharos_server::metrics::AclMetrics>)>,
    view_metrics: Vec<(SocketAddr, String, Vec<pharos_server::metrics::AclMetrics>)>,
}

#[derive(Debug)]
struct Policy {
    action: Action,
    types: Vec<Type>,
    networks: Vec<(IpAddr, u8, Option<u32>)>,
}

#[derive(Clone, Copy, Debug)]
enum Action {
    Allow,
    Block,
    Filter,
    Drop,
}

impl Acl {
    pub(crate) fn parse(cursor: &mut Cursor<'_>, domains: &[&str]) -> Result<Self, Error> {
        let mut rules = Vec::new();
        while cursor.next() {
            let args = cursor.remaining_args();
            let args = args.iter().map(String::as_str).collect::<Vec<_>>();
            let domains = origins_from_args_or_server_block(&args, domains)
                .iter()
                .filter_map(|domain| domain.parse().ok())
                .collect();
            let mut policies = Vec::new();
            while cursor.next_block() {
                let action = match cursor.val().to_ascii_lowercase().as_str() {
                    "allow" => Action::Allow,
                    "block" => Action::Block,
                    "filter" => Action::Filter,
                    "drop" => Action::Drop,
                    _ => return Err(cursor.error("invalid acl action")),
                };
                let args = cursor.remaining_args();
                let mut types = Vec::new();
                let mut networks = Vec::new();
                let mut seen_type = false;
                let mut seen_net = false;
                let mut all_networks = false;
                let mut index = 0;
                while index < args.len() {
                    let section = args[index].to_ascii_lowercase();
                    if section != "type" && section != "net" {
                        return Err(cursor.error("invalid acl section"));
                    }
                    index += 1;
                    let start = index;
                    while index < args.len()
                        && !args[index].eq_ignore_ascii_case("type")
                        && !args[index].eq_ignore_ascii_case("net")
                    {
                        index += 1;
                    }
                    if start == index {
                        return Err(cursor.error("empty acl section"));
                    }
                    if section == "type" {
                        seen_type = true;
                        for token in &args[start..index] {
                            if token == "*" {
                                types.push(Type::NONE);
                                break;
                            }
                            let typ = (0..=261)
                                .chain([32768, 32769, 65535])
                                .map(Type)
                                .find(|typ| typ.to_string() == *token && !token.starts_with("TYPE"))
                                .ok_or_else(|| cursor.error("invalid acl query type"))?;
                            types.push(typ);
                        }
                    } else {
                        seen_net = true;
                        for token in &args[start..index] {
                            if token == "*" {
                                networks.clear();
                                all_networks = true;
                                break;
                            }
                            // RFC 4632 §3.1: Parse CIDR; default to full address width.
                            let (ip, prefix) = token
                                .split_once('/')
                                .map_or((token.as_str(), None), |(ip, prefix)| (ip, Some(prefix)));
                            // RFC 4007 §11: Parse a numeric zone ID for scoped IPv6 prefixes.
                            let (ip, scope) = if let Some((ip, scope)) = ip.rsplit_once('%') {
                                let scope = scope
                                    .parse::<u32>()
                                    .ok()
                                    .filter(|scope| *scope != 0)
                                    .ok_or_else(|| cursor.error("invalid acl scope"))?;
                                (ip, Some(scope))
                            } else {
                                (ip, None)
                            };
                            // RFC 4291 §2.2: Parse conventional IPv6 address text.
                            let ip: IpAddr = ip
                                .parse()
                                .map_err(|_| cursor.error("invalid acl network"))?;
                            if scope.is_some() && !requires_scope(ip) {
                                return Err(cursor.error("scope requires link-local IPv6 network"));
                            }
                            let max = if ip.is_ipv4() { 32 } else { 128 };
                            let prefix = prefix
                                .map(|p| p.parse::<u8>())
                                .transpose()
                                .map_err(|_| cursor.error("invalid acl prefix"))?
                                .unwrap_or(max);
                            if prefix > max {
                                return Err(cursor.error("invalid acl prefix"));
                            }
                            if !all_networks {
                                networks.push((ip, prefix, scope));
                            }
                        }
                    }
                }
                if !seen_type {
                    types.push(Type::NONE);
                }
                if !seen_net {
                    networks.clear();
                }
                policies.push(Policy {
                    action,
                    types,
                    networks,
                });
            }
            rules.push(Rule {
                domains,
                policies,
                metrics: Vec::new(),
                view_metrics: Vec::new(),
            });
        }
        Ok(Self {
            rules,
            metrics: Vec::new(),
            view_metrics: Vec::new(),
        })
    }

    pub(crate) fn set_metrics(
        &mut self,
        registry: &pharos_server::metrics::Registry,
        listeners: &[pharos_server::ListenerKey],
        views: &[String],
    ) {
        for listener in listeners {
            let address = listener.address;
            let server = if address.ip().is_unspecified() {
                format!("dns://:{}", address.port())
            } else {
                format!("dns://{address}")
            };
            self.metrics.push((address, registry.acl(&server, "", "")));
            for rule in &mut self.rules {
                let metrics = rule
                    .domains
                    .iter()
                    .map(|domain| registry.acl(&server, &domain.canonical(), ""))
                    .collect();
                rule.metrics.push((address, metrics));
            }
            for view in views {
                self.view_metrics
                    .push((address, view.clone(), registry.acl(&server, "", view)));
                for rule in &mut self.rules {
                    let metrics = rule
                        .domains
                        .iter()
                        .map(|domain| registry.acl(&server, &domain.canonical(), view))
                        .collect();
                    rule.view_metrics.push((address, view.clone(), metrics));
                }
            }
        }
    }
}

impl Plugin for Acl {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        let labels = question.name.labels().count();
        let ip = match cx.client.ip() {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
            ip => ip,
        };
        let client_scope = match cx.client {
            SocketAddr::V6(address) => address.scope_id(),
            SocketAddr::V4(_) => 0,
        };
        for rule in &self.rules {
            // RFC 4343 §3: DNS name comparisons ignore ASCII letter case.
            let matched_domain = rule
                .domains
                .iter()
                .enumerate()
                .filter(|(_, domain)| {
                    let count = domain.label_count();
                    labels >= count
                        && question
                            .name
                            .labels()
                            .skip(labels - count)
                            .zip(NameRef::parse(domain.as_wire(), 0).unwrap().labels())
                            .all(|(left, right)| left.eq_ignore_ascii_case(right))
                })
                .max_by_key(|(_, domain)| domain.label_count())
                .map(|(index, _)| index);
            let Some(domain_index) = matched_domain else {
                continue;
            };
            let metrics = if rule.view_metrics.is_empty() || cx.metadata.metric_view().is_empty() {
                rule.metrics.iter().find_map(|(address, metrics)| {
                    (*address == cx.local).then(|| &metrics[domain_index])
                })
            } else {
                rule.view_metrics
                    .iter()
                    .find_map(|(address, view, metrics)| {
                        (*address == cx.local && view == cx.metadata.metric_view())
                            .then(|| &metrics[domain_index])
                    })
            };
            let action = rule
                .policies
                .iter()
                // RFC 5936 §5: ACL rules can restrict AXFR to configured client address ranges.
                .find(|policy| {
                    (policy.types.contains(&Type::NONE) || policy.types.contains(&question.qtype))
                        && (policy.networks.is_empty()
                            || policy.networks.iter().any(|&(network, prefix, scope)| {
                                // RFC 4007 §§11–12: Allow must not match scoped clients without a zone.
                                network_matches(
                                    network,
                                    prefix,
                                    scope,
                                    ip,
                                    client_scope,
                                    !matches!(policy.action, Action::Allow),
                                )
                            }))
                })
                .map(|policy| policy.action);
            match action {
                Some(Action::Allow) => break,
                Some(Action::Drop) => {
                    if let Some(metrics) = metrics {
                        metrics.increment(3);
                    }
                    return Outcome::Drop;
                }
                Some(Action::Block | Action::Filter) => {
                    let blocked = matches!(action, Some(Action::Block));
                    if let Some(metrics) = metrics {
                        metrics.increment(if blocked { 1 } else { 2 });
                    }
                    let result = (|| {
                        let max = cx.max_response_size.max(512);
                        if cx.response.capacity() < max {
                            if cx.protocol == Protocol::Tcp {
                                cx.response.reserve(max.saturating_sub(cx.response.len()));
                            } else {
                                return Err(pharos_server::Error::ResponseBufferTooSmall);
                            }
                        }
                        // RFC 1035 §4.1.1: set QR and copy opcode, RD and CD for QUERY.
                        let mut flags =
                            0x8000 | (cx.query.flags() & 0x7800) | if blocked { 5 } else { 0 };
                        // RFC 4035 §3.2.2: Copy the query's CD bit into the response.
                        if cx.query.opcode() == Opcode::QUERY {
                            flags |= cx.query.flags() & 0x0110;
                        }
                        let mut builder =
                            MessageBuilder::new(cx.response, max, cx.query.id(), flags)
                                .map_err(pharos_server::Error::Build)?;
                        builder
                            // RFC 1035 §4.1.2: Copy QNAME, QTYPE, and QCLASS.
                            .question(question.name, question.qtype, question.qclass)
                            .map_err(pharos_server::Error::Build)?;
                        // RFC 8914 §4: EDE 15 and 17 indicate Blocked and Filtered respectively.
                        let ede = [0, 15, 0, 2, 0, if blocked { 15 } else { 17 }];
                        if let Some(opt) = cx.query.opt() {
                            // RFC 6891 §7: Do not include OPT when the Query had none.
                            // RFC 3225 §3: Copy the Query's DO bit into the Response OPT.
                            builder
                                .record(
                                    Section::Additional,
                                    NameRef::parse(&[0], 0).unwrap(),
                                    Type::OPT,
                                    Class(4096),
                                    if opt.dnssec_ok() { 0x8000 } else { 0 },
                                    &ede,
                                )
                                .map_err(pharos_server::Error::Build)?;
                        }
                        let _ = builder.finish();
                        Ok(())
                    })();
                    return match result {
                        Ok(()) => Outcome::Response,
                        Err(error) => Outcome::Error(error),
                    };
                }
                None => {}
            }
        }
        let metrics = if self.view_metrics.is_empty() || cx.metadata.metric_view().is_empty() {
            self.metrics
                .iter()
                .find_map(|(address, metrics)| (*address == cx.local).then_some(metrics))
        } else {
            self.view_metrics
                .iter()
                .find_map(|(address, view, metrics)| {
                    (*address == cx.local && view == cx.metadata.metric_view()).then_some(metrics)
                })
        };
        if let Some(metrics) = metrics {
            metrics.increment(0);
        }
        next.run(cx).await
    }
}

// RFC 4007 §§11–12: Link/site-local unicast and interface/link-local multicast need zone IDs.
fn requires_scope(ip: IpAddr) -> bool {
    let IpAddr::V6(ip) = ip else {
        return false;
    };
    let octets = ip.octets();
    (octets[0] == 0xfe && matches!(octets[1] & 0xc0, 0x80 | 0xc0))
        || (octets[0] == 0xff && matches!(octets[1] & 0x0f, 1 | 2))
}

// RFC 4007 §§11–12: Match scoped IPv6 addresses only with their configured zone ID.
fn network_matches(
    network: IpAddr,
    prefix: u8,
    scope: Option<u32>,
    client: IpAddr,
    client_scope: u32,
    restrictive: bool,
) -> bool {
    if !crate::ipnet::contains(network, prefix, client) {
        return false;
    }
    if requires_scope(client) {
        // RFC 4007 §§11–12: Unscoped restrictive rules must not fail open across interfaces.
        scope.map_or(restrictive, |scope| scope == client_scope)
    } else {
        scope.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::network_matches;
    use std::net::IpAddr;

    #[test]
    fn scoped_ipv6_acl_handles_link_site_and_multicast_scopes() {
        for address in ["fe80::1", "fec0::1", "ff01::1", "ff02::1"] {
            let client: IpAddr = address.parse().unwrap();
            assert!(!network_matches(client, 128, None, client, 2, false));
            assert!(network_matches(client, 128, None, client, 2, true));
            assert!(network_matches(client, 128, Some(2), client, 2, false));
            assert!(!network_matches(client, 128, Some(3), client, 2, true));
        }
    }
}
