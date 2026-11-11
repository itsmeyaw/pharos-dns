//! Source-address access control.

use pharos_corefile::{Cursor, Error, origins_from_args_or_server_block};
use pharos_proto::{Name, Type};
use pharos_server::{Context, Next, Outcome, Plugin};
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

#[derive(Debug)]
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
    async fn serve<N: Next + Send>(&self, _cx: &mut Context<'_>, _next: N) -> Outcome {
        Outcome::Error(pharos_server::Error::NotImplemented)
    }
}
