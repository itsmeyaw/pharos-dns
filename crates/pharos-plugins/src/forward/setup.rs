use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use pharos_corefile::{Cursor, Error, normalize_domain};
use pharos_server::tls::ClientConfig;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Policy {
    Random,
    RoundRobin,
    Sequential,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Target {
    Address(SocketAddr),
    /// A DNS-over-TLS or, with `quic`, DNS-over-QUIC Upstream; the name the certificate must match, else its IP address.
    Tls {
        address: SocketAddr,
        server_name: Option<String>,
        quic: bool,
    },
    /// A DNS-over-HTTPS Upstream; the name the certificate must match, else its IP address.
    Https {
        address: SocketAddr,
        server_name: Option<String>,
    },
    Invalid(String),
}

#[derive(Debug)]
pub(super) struct Config {
    pub from: String,
    pub upstreams: Vec<Target>,
    pub except: Vec<String>,
    pub force_tcp: bool,
    pub prefer_udp: bool,
    pub expire: Duration,
    pub max_age: Duration,
    pub max_idle_conns: usize,
    pub read_timeout: Duration,
    pub max_fails: u32,
    pub max_connect_attempts: Option<u32>,
    pub policy: Policy,
    pub health_interval: Duration,
    pub health_recursion_desired: bool,
    pub health_domain: String,
    pub max_concurrent: usize,
    pub next: Vec<u16>,
    pub next_on_nodata: bool,
    pub allow_special: bool,
    pub failover: Vec<u16>,
    pub failfast_all_unhealthy_upstreams: bool,
    pub source_address: Option<IpAddr>,
    pub resolver: Vec<SocketAddr>,
    pub doh_method: String,
    pub tls_servername: Option<String>,
    /// Built from the `tls` option's arguments; absent when it had none, which keeps the system roots.
    pub tls_client: Option<Arc<ClientConfig>>,
}

/// Parse one Directive, advancing from before its `forward` token.
pub(super) fn parse(cursor: &mut Cursor<'_>, root: Option<&Path>) -> Result<Config, Error> {
    if !cursor.next() || cursor.val() != "forward" {
        return Err(cursor.error("expected forward Directive"));
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
    let mut config = Config {
        from,
        upstreams: Vec::new(),
        except: Vec::new(),
        force_tcp: false,
        prefer_udp: false,
        expire: Duration::from_secs(10),
        max_age: Duration::ZERO,
        max_idle_conns: 0,
        read_timeout: Duration::from_secs(2),
        max_fails: 2,
        max_connect_attempts: None,
        policy: Policy::Random,
        health_interval: Duration::from_millis(500),
        health_recursion_desired: true,
        health_domain: ".".into(),
        max_concurrent: 0,
        next: Vec::new(),
        next_on_nodata: false,
        allow_special: false,
        failover: Vec::new(),
        failfast_all_unhealthy_upstreams: false,
        source_address: None,
        resolver: Vec::new(),
        doh_method: "POST".into(),
        tls_servername: None,
        tls_client: None,
    };

    while cursor.next_block() {
        let option = cursor.val().to_owned();
        let args = cursor.remaining_args();
        match option.as_str() {
            "tls" => {
                // CoreDNS v1.15.0 plugin/forward/setup.go parseBlock: at most CERT KEY CA.
                if args.len() > 3 {
                    return Err(cursor.arg_err());
                }
                // CoreDNS v1.15.0 plugin/pkg/tls/tls.go NewTLSConfigFromArgs: no arguments keeps the system CAs.
                config.tls_client = crate::tls_client_from_args(&args, root)
                    .map_err(|error| cursor.error(error.to_string()))?;
            }
            "tls_servername" => config.tls_servername = Some(one_arg(cursor, &args)?.to_owned()),
            "except" => {
                if args.is_empty() {
                    return Err(cursor.arg_err());
                }
                for name in &args {
                    config.except.extend(normalize_domain(name));
                }
            }
            "force_tcp"
            | "prefer_udp"
            | "next_on_nodata"
            | "allow_special"
            | "failfast_all_unhealthy_upstreams" => {
                if !args.is_empty() {
                    return Err(cursor.arg_err());
                }
                match option.as_str() {
                    "force_tcp" => config.force_tcp = true,
                    "prefer_udp" => config.prefer_udp = true,
                    "next_on_nodata" => config.next_on_nodata = true,
                    // RFC 6761 §§6.1–6.2: special reverse and test names require explicit upstream opt-in.
                    "allow_special" => config.allow_special = true,
                    _ => config.failfast_all_unhealthy_upstreams = true,
                }
            }
            "max_fails" | "max_connect_attempts" => {
                let argument = one_arg(cursor, &args)?;
                if argument.starts_with('+') {
                    return Err(cursor.error(format!("invalid {option}")));
                }
                let value = argument
                    .parse::<u32>()
                    .map_err(|_| cursor.error(format!("invalid {option}")))?;
                if option == "max_fails" {
                    config.max_fails = value;
                } else {
                    config.max_connect_attempts = Some(value);
                }
            }
            "max_concurrent" | "max_idle_conns" => {
                let value = one_arg(cursor, &args)?
                    .parse::<i64>()
                    .map_err(|_| cursor.error(format!("invalid {option}")))?;
                let value = usize::try_from(value)
                    .map_err(|_| cursor.error(format!("invalid {option}")))?;
                if option == "max_concurrent" {
                    config.max_concurrent = value;
                } else {
                    config.max_idle_conns = value;
                }
            }
            "expire" | "max_age" | "read_timeout" => {
                let value = duration(one_arg(cursor, &args)?)
                    .ok_or_else(|| cursor.error(format!("invalid {option} duration")))?;
                match option.as_str() {
                    "expire" => config.expire = value,
                    "max_age" => config.max_age = value,
                    _ if value.is_zero() => {
                        return Err(cursor.error("read_timeout must be positive"));
                    }
                    _ => config.read_timeout = value,
                }
            }
            "health_check" => {
                if args.is_empty() {
                    return Err(cursor.arg_err());
                }
                config.health_interval = duration(&args[0])
                    .ok_or_else(|| cursor.error("invalid health_check duration"))?;
                config.health_domain = ".".into();
                let mut i = 1;
                while i < args.len() {
                    match args[i].as_str() {
                        "no_rec" => config.health_recursion_desired = false,
                        "domain" => {
                            i += 1;
                            let value = args.get(i).ok_or_else(|| cursor.arg_err())?;
                            config.health_domain = normalize_domain(value)
                                .into_iter()
                                .next()
                                .ok_or_else(|| cursor.error("invalid health_check domain"))?;
                        }
                        _ => {
                            return Err(
                                cursor.error(format!("unknown health_check option {}", args[i]))
                            );
                        }
                    }
                    i += 1;
                }
            }
            "policy" => {
                config.policy = match one_arg(cursor, &args)? {
                    "random" => Policy::Random,
                    "round_robin" => Policy::RoundRobin,
                    "sequential" => Policy::Sequential,
                    _ => return Err(cursor.error("unknown policy")),
                };
            }
            "next" | "failover" => {
                if args.is_empty() {
                    return Err(cursor.arg_err());
                }
                for name in &args {
                    let code =
                        rcode(name).ok_or_else(|| cursor.error(format!("invalid RCODE {name}")))?;
                    if option == "failover" {
                        if code == 0 {
                            return Err(cursor.error("NOERROR cannot be used in failover"));
                        }
                        config.failover.push(code);
                    } else {
                        config.next.push(code);
                    }
                }
            }
            "source_address" => {
                config.source_address = Some(
                    one_arg(cursor, &args)?
                        .parse()
                        .map_err(|_| cursor.error("invalid source_address IP"))?,
                );
            }
            "resolver" => {
                if args.is_empty() {
                    return Err(cursor.arg_err());
                }
                config.resolver = args
                    .iter()
                    .map(|arg| {
                        socket_address(arg, 53)
                            .ok_or_else(|| cursor.error("resolver must be a numeric IP address"))
                    })
                    .collect::<Result<_, _>>()?;
            }
            "doh_method" => {
                let value = one_arg(cursor, &args)?;
                if value != "GET" && value != "POST" {
                    return Err(cursor.error("doh_method must be GET or POST"));
                }
                config.doh_method = value.into();
            }
            _ => return Err(cursor.error(format!("unknown forward property {option}"))),
        }
    }

    if !config.max_age.is_zero() && config.max_age < config.expire {
        return Err(cursor.error("max_age must not be less than expire"));
    }
    let mut entries = 0;
    for to in &args[1..] {
        let (scheme, address) = to.split_once("://").unwrap_or(("dns", to));
        if !matches!(scheme, "dns" | "tls" | "quic" | "https") {
            return Err(cursor.error(format!("{scheme} Upstreams are not supported")));
        }
        let quic = scheme == "quic";
        let (tls, https) = (quic || scheme == "tls", scheme == "https");
        // CoreDNS v1.15.0 plugin/forward/setup.go: an HTTPS Upstream always uses the /dns-query path.
        if https && address.contains('/') {
            return Err(cursor.error(format!(
                "paths are not allowed in HTTPS upstream addresses (the /dns-query path is used by default): {to}"
            )));
        }
        // RFC 7858 §3.1: DoT uses TCP port 853; RFC 9250 §4.1.1: DoQ uses UDP port 853; RFC 8484 §3: DoH uses the https port 443; unless the Upstream names another.
        let default_port = match scheme {
            "tls" | "quic" => 853,
            "https" => 443,
            _ => 53,
        };
        let (unscoped, zone) = split_zone(address);
        // CoreDNS v1.15.0 plugin/forward/setup.go: the zone of a `tls://`, `quic://` or `https://` Upstream is its TLS server name.
        let target = |address| {
            let server_name = zone.as_ref().map(|zone| zone.to_ascii_lowercase());
            if tls {
                Target::Tls {
                    address,
                    server_name,
                    quic,
                }
            } else if https {
                Target::Https {
                    address,
                    server_name,
                }
            } else {
                Target::Address(address)
            }
        };
        if let Some(address) = socket_address(&unscoped, default_port) {
            entries += 1;
            let target = target(address);
            if !config.upstreams.contains(&target) {
                config.upstreams.push(target);
            }
        } else if std::path::Path::new(address).exists() || address.contains('/') {
            let file = std::fs::read_to_string(address)
                .map_err(|error| cursor.error(format!("cannot read {address}: {error}")))?;
            let mut has_nameservers = false;
            for line in file.lines() {
                let mut words = line.split_whitespace();
                if words.next() == Some("nameserver")
                    && let Some(ip) = words.next()
                {
                    let ip = ip.rsplit_once('%').map_or(ip, |(host, _)| host);
                    has_nameservers = true;
                    let target = ip.parse::<IpAddr>().map_or_else(
                        |_| {
                            Target::Invalid(if ip.contains(':') {
                                format!("[{ip}]:{default_port}")
                            } else {
                                format!("{ip}:{default_port}")
                            })
                        },
                        |ip| target(SocketAddr::new(ip, default_port)),
                    );
                    if !config.upstreams.contains(&target) {
                        config.upstreams.push(target);
                    }
                }
            }
            entries += usize::from(has_nameservers);
        } else {
            let (host, port) = match unscoped.rsplit_once(':') {
                Some((host, port)) if !host.contains(':') => {
                    let port = port
                        .parse::<u16>()
                        .map_err(|_| cursor.error("invalid Upstream port"))?;
                    (host, port)
                }
                _ => (unscoped.as_str(), default_port),
            };
            let ips = super::resolve::resolve(host, &config.resolver)
                .map_err(|error| cursor.error(format!("failed to resolve {host}: {error}")))?;
            entries += 1;
            for ip in ips {
                let target = target(SocketAddr::new(ip, port));
                if !config.upstreams.contains(&target) {
                    config.upstreams.push(target);
                }
            }
        }
    }
    if let Some(forward_name) = &config.tls_servername {
        for target in &config.upstreams {
            if let Target::Tls {
                address,
                server_name: Some(server_name),
                quic,
            } = target
            {
                let scheme = if *quic { "quic" } else { "tls" };
                return Err(cursor.error(format!(
                    "both forward ('{forward_name}') and proxy level ('{server_name}') TLS servernames are set for upstream proxy '{scheme}://{address}'"
                )));
            }
            if let Target::Https {
                address,
                server_name: Some(server_name),
            } = target
            {
                return Err(cursor.error(format!(
                    "both forward ('{forward_name}') and proxy level ('{server_name}') TLS servernames are set for upstream proxy 'https://{address}'"
                )));
            }
        }
    }
    if config.upstreams.is_empty() {
        return Err(cursor.error("no valid Upstream addresses found"));
    }
    if entries > 15 {
        return Err(cursor.error("more than 15 Upstream entries configured"));
    }
    Ok(config)
}

// CoreDNS v1.15.0 plugin/forward/setup.go splitZone: `HOST%ZONE[:PORT]` yields the host with its port and the zone.
fn split_zone(value: &str) -> (String, Option<String>) {
    let Some(percent) = value.rfind('%') else {
        return (value.to_owned(), None);
    };
    let mut host = value[..percent].to_owned();
    let mut zone = &value[percent + 1..];
    if host.starts_with('[') {
        host.push(']');
    }
    if let Some(colon) = zone.rfind(':') {
        host.push_str(&zone[colon..]);
        zone = &zone[..colon];
    }
    (host, Some(zone.trim_end_matches(']').to_owned()))
}

fn one_arg<'a>(cursor: &Cursor<'_>, args: &'a [String]) -> Result<&'a str, Error> {
    if args.len() == 1 {
        Ok(&args[0])
    } else {
        Err(cursor.arg_err())
    }
}

// RFC 1035 §4.2.1: DNS uses server port 53 by default; RFC 7858 §3.1 uses 853 for DoT.
fn socket_address(value: &str, default_port: u16) -> Option<SocketAddr> {
    value.parse::<SocketAddr>().ok().or_else(|| {
        value
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, default_port))
    })
}

fn rcode(value: &str) -> Option<u16> {
    Some(match value.to_ascii_uppercase().as_str() {
        "NOERROR" => 0,
        "FORMERR" => 1,
        "SERVFAIL" => 2,
        "NXDOMAIN" => 3,
        "NOTIMP" | "NOTIMPL" => 4,
        "REFUSED" => 5,
        "YXDOMAIN" => 6,
        "YXRRSET" => 7,
        "NXRRSET" => 8,
        "NOTAUTH" => 9,
        "NOTZONE" => 10,
        "DSOTYPENI" => 11,
        "BADSIG" => 16,
        "BADKEY" => 17,
        "BADTIME" => 18,
        "BADMODE" => 19,
        "BADNAME" => 20,
        "BADALG" => 21,
        "BADTRUNC" => 22,
        "BADCOOKIE" => 23,
        _ => return None,
    })
}

// Parse Go duration syntax, truncating fractional nanoseconds as time.ParseDuration does.
fn duration(value: &str) -> Option<Duration> {
    let value = value.strip_prefix('+').unwrap_or(value);
    let negative = value.starts_with('-');
    let value = value.strip_prefix('-').unwrap_or(value);
    if value == "0" {
        return Some(Duration::ZERO);
    }
    if value.is_empty() {
        return None;
    }
    let mut rest = value;
    let mut total = 0u128;
    while !rest.is_empty() {
        let number_end = rest
            .find(|ch: char| !ch.is_ascii_digit() && ch != '.')
            .unwrap_or(rest.len());
        let number = &rest[..number_end];
        rest = &rest[number_end..];
        let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
        if (whole.is_empty() && fraction.is_empty())
            || !whole.bytes().all(|b| b.is_ascii_digit())
            || !fraction.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        let unit_end = rest
            .find(|ch: char| ch.is_ascii_digit() || ch == '.')
            .unwrap_or(rest.len());
        let unit = match &rest[..unit_end] {
            "ns" => 1u128,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => return None,
        };
        rest = &rest[unit_end..];
        let integer = if whole.is_empty() {
            0
        } else {
            whole.parse::<u128>().ok()?
        };
        let digits = &fraction[..fraction.len().min(18)];
        let fractional = if digits.is_empty() {
            0
        } else {
            digits.parse::<u128>().ok()? * unit / 10u128.pow(digits.len() as u32)
        };
        total = total.checked_add(integer.checked_mul(unit)?.checked_add(fractional)?)?;
        if total > i64::MAX as u128 {
            return None;
        }
    }
    if negative && total != 0 {
        return None;
    }
    Some(Duration::from_nanos(total as u64))
}

pub(crate) fn setup(
    cursor: &mut pharos_corefile::Cursor<'_>,
    block: &mut pharos_corefile::BlockContext<crate::Chain>,
) -> Result<(), pharos_corefile::Error> {
    use crate::forward;

    // CoreDNS v1.15.0 plugin/forward/setup.go setup: the Directive configures the Server Block's forward Plugin; a relative path joins `root`.
    let root = crate::root_path(&block.config);
    block.config.forward = Some(forward::Forward::parse(cursor, root)?);
    Ok(())
}

#[cfg(test)]
mod tests;
