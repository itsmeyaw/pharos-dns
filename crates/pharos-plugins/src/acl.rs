//! Source-address access control.

use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::{Class, MessageBuilder, Name, NameRef, Opcode, Section, Type};
use pharos_server::{Context, Next, Outcome, Plugin, Protocol};
use std::net::IpAddr;

#[derive(Debug)]
pub struct Acl {
    rules: Vec<Rule>,
}

#[derive(Debug)]
struct Rule {
    domains: Vec<Name>,
    policies: Vec<Policy>,
}

#[derive(Debug)]
struct Policy {
    action: Action,
    types: Vec<Type>,
    networks: Vec<(IpAddr, u8)>,
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
                                break;
                            }
                            let (ip, prefix) = token
                                .split_once('/')
                                .map_or((token.as_str(), None), |(ip, prefix)| (ip, Some(prefix)));
                            let ip: IpAddr = ip
                                .parse()
                                .map_err(|_| cursor.error("invalid acl network"))?;
                            let max = if ip.is_ipv4() { 32 } else { 128 };
                            let prefix = prefix
                                .map(|p| p.parse::<u8>())
                                .transpose()
                                .map_err(|_| cursor.error("invalid acl prefix"))?
                                .unwrap_or(max);
                            if prefix > max {
                                return Err(cursor.error("invalid acl prefix"));
                            }
                            networks.push((ip, prefix));
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
            rules.push(Rule { domains, policies });
        }
        Ok(Self { rules })
    }
}

impl Plugin for Acl {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_>, next: N) -> Outcome {
        let Some(question) = cx.query.questions().next() else {
            return next.run(cx).await;
        };
        let labels = question.name.labels().count();
        let ip = match cx.client.ip() {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
            ip => ip,
        };
        for rule in &self.rules {
            // RFC 4343 §3: DNS name comparisons ignore ASCII letter case.
            let matches_domain = rule.domains.iter().any(|domain| {
                let count = domain.label_count();
                labels >= count
                    && question
                        .name
                        .labels()
                        .skip(labels - count)
                        .zip(NameRef::parse(domain.as_wire(), 0).unwrap().labels())
                        .all(|(left, right)| left.eq_ignore_ascii_case(right))
            });
            if !matches_domain {
                continue;
            }
            let action = rule
                .policies
                .iter()
                .find(|policy| {
                    (policy.types.contains(&Type::NONE) || policy.types.contains(&question.qtype))
                        && (policy.networks.is_empty()
                            || policy
                                .networks
                                .iter()
                                .any(|&(network, prefix)| contains(network, prefix, ip)))
                })
                .map(|policy| policy.action);
            match action {
                Some(Action::Allow) => break,
                Some(Action::Drop) => return Outcome::Drop,
                Some(Action::Block | Action::Filter) => {
                    let blocked = matches!(action, Some(Action::Block));
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
                        if cx.query.opcode() == Opcode::QUERY {
                            flags |= cx.query.flags() & 0x0110;
                        }
                        let mut builder =
                            MessageBuilder::new(cx.response, max, cx.query.id(), flags)
                                .map_err(pharos_server::Error::Build)?;
                        builder
                            .question(question.name, question.qtype, question.qclass)
                            .map_err(pharos_server::Error::Build)?;
                        // RFC 8914 §4: EDE 15 and 17 indicate Blocked and Filtered respectively.
                        let ede = [0, 15, 0, 2, 0, if blocked { 15 } else { 17 }];
                        builder
                            .record(
                                Section::Additional,
                                NameRef::parse(&[0], 0).unwrap(),
                                Type::OPT,
                                Class(4096),
                                0x8000,
                                &ede,
                            )
                            .map_err(pharos_server::Error::Build)?;
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
        next.run(cx).await
    }
}

fn contains(network: IpAddr, prefix: u8, client: IpAddr) -> bool {
    match (network, client) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
            u32::from(net) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
            u128::from(net) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}
