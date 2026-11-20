use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{Arc, atomic::AtomicU32},
};

use pharos_corefile::{BlockContext, Cursor, Error, Fallthrough, normalize_domain};
use pharos_proto::Name;
use pharos_server::{
    grpc,
    tls::{ClientOptions, ServerName, client_config},
};

use super::{
    Grpc, MAX_UPSTREAMS, Policy, Upstream,
    client::{Client, Pool, Target, Tls},
};

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    block: &mut BlockContext<crate::Chain>,
) -> Result<(), Error> {
    // CoreDNS v1.15.0 plugin/grpc/setup.go parseGRPC: the Directive runs once per Server Block (`once` in build.rs).
    let root = crate::root_path(&block.config);
    block.config.grpc = Some(parse(cursor, root)?);
    Ok(())
}

fn domain(cursor: &Cursor<'_>, name: &str) -> Result<Name, Error> {
    name.parse()
        .map_err(|_| cursor.error(format!("invalid Domain {name}")))
}

fn one_arg<'a>(cursor: &Cursor<'_>, args: &'a [String]) -> Result<&'a str, Error> {
    match args {
        [arg] => Ok(arg),
        _ => Err(cursor.arg_err()),
    }
}

// CoreDNS v1.15.0 plugin/grpc/setup.go parseStanza and parseBlock.
pub(super) fn parse(cursor: &mut Cursor<'_>, root: Option<&Path>) -> Result<Grpc, Error> {
    if !cursor.next() {
        return Err(cursor.arg_err());
    }
    let args = cursor.remaining_args();
    if args.len() < 2 {
        return Err(cursor.arg_err());
    }
    // RFC 1034 §3.1: Configured complete domain names use absolute presentation form.
    let from = normalize_domain(&args[0])
        .into_iter()
        .next()
        .ok_or_else(|| cursor.error(format!("unable to normalize '{}'", args[0])))?;
    let targets = targets(&args[1..]).map_err(|error| cursor.error(error))?;

    let mut except = Vec::new();
    let mut policy = Policy::Random;
    let mut fallthrough = Fallthrough::default();
    let mut tls = false;
    let mut tls_client = None;
    let mut tls_servername = None;
    while cursor.next_block() {
        let option = cursor.val().to_owned();
        let args = cursor.remaining_args();
        match option.as_str() {
            "except" => {
                if args.is_empty() {
                    return Err(cursor.arg_err());
                }
                for name in &args {
                    except.extend(normalize_domain(name));
                }
            }
            "tls" => {
                // CoreDNS v1.15.0 plugin/grpc/setup.go parseBlock: at most CERT KEY CA.
                if args.len() > 3 {
                    return Err(cursor.arg_err());
                }
                tls = true;
                tls_client = crate::tls_client_from_args(&args, root)
                    .map_err(|error| cursor.error(error.to_string()))?;
            }
            "tls_servername" => tls_servername = Some(one_arg(cursor, &args)?.to_owned()),
            "policy" => {
                policy = match one_arg(cursor, &args)? {
                    "random" => Policy::Random,
                    "round_robin" => Policy::RoundRobin,
                    "sequential" => Policy::Sequential,
                    other => return Err(cursor.error(format!("unknown policy '{other}'"))),
                };
            }
            "fallthrough" => {
                let args = args.iter().map(String::as_str).collect::<Vec<_>>();
                fallthrough.set_domains_from_args(&args);
            }
            other => return Err(cursor.error(format!("unknown property '{other}'"))),
        }
    }

    // CoreDNS v1.15.0 plugin/grpc/setup.go setup: more than 15 Upstreams is an error.
    if targets.len() > MAX_UPSTREAMS {
        return Err(cursor.error(format!(
            "more than {MAX_UPSTREAMS} TOs configured: {}",
            targets.len()
        )));
    }
    // CoreDNS v1.15.0 plugin/grpc/setup.go parseStanza: `tls_servername` alone turns TLS on with the system roots.
    let config = if tls || tls_servername.is_some() {
        let config = match tls_client {
            Some(config) => config,
            None => client_config(&ClientOptions::default())
                .map_err(|error| cursor.error(error.to_string()))?,
        };
        // RFC 7301 §3.1: gRPC runs on HTTP/2, so only `h2` is offered.
        let mut config = (*config).clone();
        config.alpn_protocols = grpc::ALPN
            .iter()
            .map(|protocol| protocol.to_vec())
            .collect();
        Some(Arc::new(config))
    } else {
        None
    };
    let mut upstreams = Vec::with_capacity(targets.len());
    for Resolved { to, mut target } in targets {
        let host = match &target {
            Target::Tcp(address) => address.ip().to_string(),
            Target::Host { host, .. } => strip_zone(host).to_owned(),
            Target::Unix(_) | Target::Invalid(_) => "localhost".to_owned(),
        };
        // RFC 6125 §6.4.1: verify the name the Corefile gives, else the Upstream's address.
        let mut tls = None;
        if let Some(config) = &config {
            let name = tls_servername.clone().unwrap_or(host);
            match ServerName::try_from(name.clone()) {
                Ok(server_name) => {
                    tls = Some(Tls {
                        config: Arc::clone(config),
                        server_name,
                    });
                }
                // CoreDNS v1.15.0 plugin/grpc/proxy.go newProxy: a name that cannot be verified fails at dial, not setup.
                Err(_) if tls_servername.is_none() => {
                    target = Target::Invalid(format!("invalid TLS server name {name}"));
                }
                Err(_) => return Err(cursor.error(format!("invalid TLS server name {name}"))),
            }
        }
        // grpc-go takes the `:authority` from the credentials' server name, else the target.
        let authority = tls_servername.clone().unwrap_or_else(|| match &target {
            Target::Tcp(address) => address.to_string(),
            // RFC 6874 §2: a zone in a URI host is written after `%25`.
            Target::Host { host, port } => join_host_port(&host.replace('%', "%25"), *port),
            Target::Unix(_) | Target::Invalid(_) => "localhost".to_owned(),
        });
        let client = Client::new(target, tls, &authority)
            .map_err(|error| cursor.error(error.to_string()))?;
        upstreams.push(Upstream {
            to,
            client,
            metrics: None,
        });
    }
    Ok(Grpc {
        from: domain(cursor, &from)?,
        ignored: except
            .iter()
            .map(|name| domain(cursor, name))
            .collect::<Result<_, _>>()?,
        upstreams,
        policy,
        robin: AtomicU32::new(0),
        fallthrough: fallthrough
            .domains
            .iter()
            .map(|name| domain(cursor, name))
            .collect::<Result<_, _>>()?,
        pool: Pool::default(),
    })
}

/// One TO as CoreDNS parses it: the text its metrics label and `grpc.NewClient` receive, and where Pharos dials.
struct Resolved {
    to: String,
    target: Target,
}

/// CoreDNS v1.15.0 plugin/pkg/parse/transport.go Transport: a recognised scheme prefix and the rest.
fn transport(entry: &str) -> (Option<&'static str>, &str) {
    for scheme in ["tls", "dns", "quic", "grpc", "https3", "https", "unix"] {
        if let Some(rest) = entry
            .strip_prefix(scheme)
            .and_then(|rest| rest.strip_prefix("://"))
        {
            return (Some(scheme), rest);
        }
    }
    (None, entry)
}

/// CoreDNS v1.15.0 plugin/pkg/parse/host.go stripZone: drop the last `%` and what follows.
fn strip_zone(host: &str) -> &str {
    host.rsplit_once('%').map_or(host, |(host, _)| host)
}

/// Go net.SplitHostPort: `None` where Go returns an error.
fn split_host_port(value: &str) -> Option<(&str, &str)> {
    let colon = value.rfind(':')?;
    let (host, open, close) = if value.starts_with('[') {
        let end = value.find(']')?;
        // Go net.SplitHostPort: the first `]` must sit just before the last `:`.
        if end + 1 != colon {
            return None;
        }
        (&value[1..end], 1, end + 1)
    } else {
        let host = &value[..colon];
        if host.contains(':') {
            return None;
        }
        (host, 0, 0)
    };
    if value[open..].contains('[') || value[close..].contains(']') {
        return None;
    }
    Some((host, &value[colon + 1..]))
}

/// Go net.JoinHostPort.
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Go net.ParseIP, which has no zone.
fn is_ip(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

/// Where `host` and `port` lead when grpc-go dials them; what grpc-go cannot dial fails at the first call.
fn dial(host: &str, port: &str) -> Target {
    let Ok(port) = port.parse::<u16>() else {
        // shortcut: grpc-go also dials a service name such as `domain`; only numeric ports are, so a name fails at dial.
        return Target::Invalid(format!("invalid port {port:?}"));
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Target::Tcp(SocketAddr::new(ip, port));
    }
    // Go net: an IPv6 zone names an interface that is looked up when dialling, so it is kept for getaddrinfo.
    let zoned = host
        .split_once('%')
        .is_some_and(|(ip, _)| ip.parse::<Ipv6Addr>().is_ok());
    if host.contains(':') && !zoned {
        return Target::Invalid(format!("invalid target address {host}:{port}"));
    }
    Target::Host {
        host: host.to_owned(),
        port,
    }
}

// CoreDNS v1.15.0 plugin/pkg/parse/host.go tryFile: miekg/dns ClientConfigFromFile takes the second field of each `nameserver` line, on port 53, with the zone dropped.
fn file(host: &str) -> Result<Vec<Resolved>, String> {
    let text = std::fs::read_to_string(host)
        .map_err(|error| format!("not an IP address or file {host:?}: {error}"))?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some("nameserver")).then(|| words.next())?
        })
        .map(|server| {
            let server = strip_zone(server);
            Resolved {
                to: join_host_port(server, 53),
                target: dial(server, "53"),
            }
        })
        .collect())
}

// CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: each TO is `[SCHEME://]IP`, `[SCHEME://]IP:PORT`, `unix://PATH` or a resolv.conf-style file.
fn targets(to: &[String]) -> Result<Vec<Resolved>, String> {
    let mut targets = Vec::new();
    for entry in to {
        let (scheme, host) = transport(entry);
        if host.is_empty() {
            return Err(format!("invalid address: {entry:?}"));
        }
        if scheme == Some("unix") {
            targets.push(Resolved {
                to: format!("unix://{host}"),
                target: Target::Unix(host.into()),
            });
            continue;
        }
        let Some((address, port)) = split_host_port(host) else {
            let host = host.trim_matches(['[', ']']);
            if !is_ip(strip_zone(host)) {
                targets.extend(file(host)?);
                continue;
            }
            // CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: each scheme has its own default port.
            let port = match scheme {
                None | Some("dns") => 53,
                Some("tls" | "quic") => 853,
                _ => 443,
            };
            let joined = join_host_port(host, port);
            targets.push(match scheme {
                None | Some("dns") => Resolved {
                    to: joined,
                    target: dial(host, "53"),
                },
                // CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: `https3` has no case, so its address is empty.
                Some("https3") => Resolved {
                    to: String::new(),
                    target: Target::Invalid("empty target".into()),
                },
                // grpc-go has no resolver for these schemes, so the call fails at dial.
                Some(scheme) => Resolved {
                    target: Target::Invalid(format!("unsupported scheme {scheme}")),
                    to: format!("{scheme}://{joined}"),
                },
            });
            continue;
        };
        if !is_ip(strip_zone(address)) {
            targets.extend(file(host)?);
            continue;
        }
        // CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: an address with a port is kept as written.
        targets.push(Resolved {
            to: entry.clone(),
            target: match scheme {
                None => dial(address, port),
                // grpc-go reads `SCHEME://ADDRESS:PORT` as a target with an authority and no endpoint.
                Some(scheme) => Target::Invalid(format!("unsupported scheme {scheme}")),
            },
        });
    }
    if targets.is_empty() {
        return Err("no nameservers found".into());
    }
    Ok(targets)
}

#[cfg(test)]
mod tests;
