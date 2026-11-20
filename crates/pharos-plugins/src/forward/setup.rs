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

    let root = crate::root_path(&block.config);
    block.config.forward = Some(forward::Forward::parse(cursor, root)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_corefile::{Cursor, lex};
    use std::time::Duration;

    fn parse_text(text: &str) -> Result<Config, pharos_corefile::Error> {
        let tokens = lex("Corefile", text);
        parse(&mut Cursor::new("Corefile", &tokens), None)
    }

    const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

    fn tls(address: &str, server_name: Option<&str>) -> Target {
        Target::Tls {
            address: address.parse().unwrap(),
            server_name: server_name.map(str::to_owned),
            quic: false,
        }
    }

    fn quic(address: &str, server_name: Option<&str>) -> Target {
        Target::Tls {
            address: address.parse().unwrap(),
            server_name: server_name.map(str::to_owned),
            quic: true,
        }
    }

    #[test]
    fn defaults_and_numeric_upstreams() {
        let config = parse_text("forward Example.ORG 127.0.0.1 dns://[::1]:5353").unwrap();
        assert_eq!(config.from, "example.org.");
        assert_eq!(
            config.upstreams,
            [
                Target::Address("127.0.0.1:53".parse().unwrap()),
                Target::Address("[::1]:5353".parse().unwrap())
            ]
        );
        assert_eq!(config.max_fails, 2);
        assert_eq!(config.expire, Duration::from_secs(10));
        assert_eq!(config.health_interval, Duration::from_millis(500));
        assert!(config.health_recursion_desired);
        assert_eq!(config.health_domain, ".");
        assert_eq!(config.policy, Policy::Random);
        assert_eq!(config.max_connect_attempts, None);
    }

    #[test]
    fn parses_options_and_preserves_zero_attempts() {
        let config = parse_text("forward . 192.0.2.1 {\nexcept example.org 10.0.0.0/8\nforce_tcp\nprefer_udp\nexpire 1m2.5s\nmax_age 90s\nmax_idle_conns 4\nread_timeout 3s\nmax_fails 0\nmax_connect_attempts 0\npolicy round_robin\nhealth_check 250ms no_rec domain Example.org\nmax_concurrent 10\nnext NXDOMAIN servfail\nnext_on_nodata\nallow_special\nfailover REFUSED\nfailfast_all_unhealthy_upstreams\nsource_address 192.0.2.9\n}").unwrap();
        assert_eq!(config.except, ["example.org.", "10.in-addr.arpa."]);
        assert!(config.force_tcp && config.prefer_udp);
        assert_eq!(config.expire, Duration::from_millis(62500));
        assert_eq!(config.max_age, Duration::from_secs(90));
        assert_eq!(config.max_idle_conns, 4);
        assert_eq!(config.read_timeout, Duration::from_secs(3));
        assert_eq!(config.max_fails, 0);
        assert_eq!(config.max_connect_attempts, Some(0));
        assert_eq!(config.policy, Policy::RoundRobin);
        assert_eq!(config.health_interval, Duration::from_millis(250));
        assert!(!config.health_recursion_desired);
        assert_eq!(config.health_domain, "example.org.");
        assert_eq!(config.max_concurrent, 10);
        assert_eq!(config.next, [3, 2]);
        assert!(config.next_on_nodata && config.failfast_all_unhealthy_upstreams);
        assert!(config.allow_special);
        assert_eq!(config.failover, [5]);
        assert_eq!(config.source_address, Some("192.0.2.9".parse().unwrap()));
    }

    #[test]
    fn rejects_invalid_options_and_encrypted_transports() {
        for text in [
            "forward .",
            "forward . invalid..domain",
            "forward . grpc://1.1.1.1",
            "forward . unix:///run/dns.sock",
            "forward . 1.1.1.1 {\nunknown x\n}",
            "forward . 1.1.1.1 {\nforce_tcp x\n}",
            "forward . 1.1.1.1 {\nallow_special x\n}",
            "forward . 1.1.1.1 {\nhealth_check -1s\n}",
            "forward . 1.1.1.1 {\nhealth_check 1s domain a..b\n}",
            "forward . 1.1.1.1 {\nhealth_check 1s nonsense\n}",
            "forward . 1.1.1.1 {\nmax_fails -1\n}",
            "forward . 1.1.1.1 {\nmax_fails +1\n}",
            "forward . 1.1.1.1 {\nmax_connect_attempts +1\n}",
            "forward . 1.1.1.1 {\nmax_concurrent -1\n}",
            "forward . 1.1.1.1 {\nfailover NOERROR\n}",
            "forward . 1.1.1.1 {\nnext INVALID\n}",
            "forward . 1.1.1.1 {\nexpire 10s\nmax_age 9s\n}",
            "forward . 1.1.1.1 {\nread_timeout 0\n}",
        ] {
            assert!(parse_text(text).is_err(), "accepted {text}");
        }
        assert!(
            parse_text("forward . grpc://1.1.1.1")
                .unwrap_err()
                .to_string()
                .contains("grpc Upstreams are not supported")
        );
    }

    // CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: `quic://` defaults to port 853.
    #[test]
    fn quic_upstreams_default_to_port_853() {
        let config = parse_text(
            "forward . quic://9.9.9.9 quic://[2620:fe::fe]:8853 quic://[::1] quic://127.0.0.1%Example.net:854",
        )
        .unwrap();
        assert_eq!(
            config.upstreams,
            [
                quic("9.9.9.9:853", None),
                quic("[2620:fe::fe]:8853", None),
                quic("[::1]:853", None),
                quic("127.0.0.1:854", Some("example.net")),
            ]
        );
    }

    // CoreDNS v1.15.0 plugin/forward/setup.go: `tls_servername` covers `quic://` and conflicts with its zone.
    #[test]
    fn tls_servername_applies_to_quic_upstreams() {
        let config = parse_text(
            "forward . quic://127.0.0.1 tls://127.0.0.2 {\ntls_servername dns.example\n}",
        )
        .unwrap();
        assert_eq!(
            config.upstreams,
            [quic("127.0.0.1:853", None), tls("127.0.0.2:853", None)]
        );
        assert_eq!(
            parse_text("forward . quic://127.0.0.3%Other {\ntls_servername dns.example\n}")
                .unwrap_err()
                .to_string(),
            "Corefile:3: both forward ('dns.example') and proxy level ('other') TLS servernames are set for upstream proxy 'quic://127.0.0.3:853'"
        );
    }

    #[test]
    fn dns_tls_and_quic_upstreams_at_one_address_stay_distinct() {
        let config =
            parse_text("forward . tls://127.0.0.1 quic://127.0.0.1 quic://127.0.0.1").unwrap();
        assert_eq!(
            config.upstreams,
            [tls("127.0.0.1:853", None), quic("127.0.0.1:853", None)]
        );
    }

    // CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: `tls://` defaults to port 853.
    #[test]
    fn tls_upstreams_default_to_port_853() {
        let config =
            parse_text("forward . tls://9.9.9.9 tls://[2620:fe::fe]:8853 tls://[::1]").unwrap();
        assert_eq!(
            config.upstreams,
            [
                tls("9.9.9.9:853", None),
                tls("[2620:fe::fe]:8853", None),
                tls("[::1]:853", None),
            ]
        );
    }

    // CoreDNS v1.15.0 plugin/forward/setup_test.go TestSplitZone, TestSetupTLS.
    #[test]
    fn tls_endpoint_zone_sets_the_server_name() {
        let config = parse_text(
            "forward . tls://127.0.0.1%Example.net:854 tls://127.0.0.2%example.net tls://[fe80::1%example.com] tls://[2400:3200::1%dns.alidns.com]:853",
        )
        .unwrap();
        assert_eq!(
            config.upstreams,
            [
                tls("127.0.0.1:854", Some("example.net")),
                tls("127.0.0.2:853", Some("example.net")),
                tls("[fe80::1]:853", Some("example.com")),
                tls("[2400:3200::1]:853", Some("dns.alidns.com")),
            ]
        );
    }

    // CoreDNS v1.15.0 plugin/forward/setup_test.go TestSetupTLS.
    #[test]
    fn tls_servername_applies_to_every_tls_upstream_only() {
        let config = parse_text(
            "forward . tls://127.0.0.1 127.0.0.2 tls://127.0.0.3%Other {\ntls_servername dns.example\n}",
        );
        assert_eq!(
            config.unwrap_err().to_string(),
            "Corefile:3: both forward ('dns.example') and proxy level ('other') TLS servernames are set for upstream proxy 'tls://127.0.0.3:853'"
        );
        let config =
            parse_text("forward . tls://127.0.0.1 127.0.0.2 {\ntls_servername dns.example\n}")
                .unwrap();
        assert_eq!(
            config.upstreams,
            [
                tls("127.0.0.1:853", None),
                Target::Address("127.0.0.2:53".parse().unwrap()),
            ]
        );
        assert_eq!(config.tls_servername.as_deref(), Some("dns.example"));
    }

    fn https(address: &str, server_name: Option<&str>) -> Target {
        Target::Https {
            address: address.parse().unwrap(),
            server_name: server_name.map(str::to_owned),
        }
    }

    // CoreDNS v1.15.0 plugin/forward/setup_test.go TestSetupForward: `https://` defaults to port 443.
    #[test]
    fn https_upstreams_default_to_port_443_and_take_a_zone_as_server_name() {
        let config = parse_text(
            "forward . https://127.0.0.1 https://127.0.0.1%example.net:8443 https://[::1%example.net]:443 https://127.0.0.1",
        )
        .unwrap();
        assert_eq!(
            config.upstreams,
            [
                https("127.0.0.1:443", None),
                https("127.0.0.1:8443", Some("example.net")),
                https("[::1]:443", Some("example.net")),
            ]
        );
        assert_eq!(config.doh_method, "POST");
    }

    // CoreDNS v1.15.0 plugin/forward/setup_test.go TestSetupForward: paths are not allowed in HTTPS Upstreams.
    #[test]
    fn https_upstreams_reject_paths() {
        for text in [
            "forward . https://1.1.1.1/",
            "forward . https://1.1.1.1/dns-query",
            "forward . https://1.1.1.1:443/x",
        ] {
            let error = parse_text(text).unwrap_err().to_string();
            assert!(
                error.contains("paths are not allowed in HTTPS upstream addresses"),
                "{text}: {error}"
            );
        }
    }

    // CoreDNS v1.15.0 plugin/forward/setup.go: a proxy-level server name conflicts with `tls_servername` for HTTPS too.
    #[test]
    fn tls_servername_conflicts_with_an_https_zone() {
        let error =
            parse_text("forward . https://127.0.0.1%Other {\ntls_servername dns.example\n}")
                .unwrap_err()
                .to_string();
        assert_eq!(
            error,
            "Corefile:3: both forward ('dns.example') and proxy level ('other') TLS servernames are set for upstream proxy 'https://127.0.0.1:443'"
        );
        assert!(
            parse_text(
                "forward . https://127.0.0.1 {\ntls_servername dns.example\ndoh_method GET\n}"
            )
            .is_ok()
        );
    }

    #[test]
    fn dns_zone_is_a_scope_not_a_server_name() {
        let config =
            parse_text("forward . 127.0.0.1%eth0 dns://127.0.0.1%eth1 {\ntls_servername dns\n}")
                .unwrap();
        assert_eq!(
            config.upstreams,
            [Target::Address("127.0.0.1:53".parse().unwrap())]
        );
    }

    // CoreDNS v1.15.0 plugin/forward/resolve.go dedupKey: transport and server name keep upstreams distinct.
    #[test]
    fn dns_and_tls_upstreams_at_one_address_stay_distinct() {
        let config = parse_text("forward . 127.0.0.1:853 tls://127.0.0.1 tls://127.0.0.1 tls://127.0.0.1%A tls://127.0.0.1%a tls://127.0.0.1%b").unwrap();
        assert_eq!(
            config.upstreams,
            [
                Target::Address("127.0.0.1:853".parse().unwrap()),
                tls("127.0.0.1:853", None),
                tls("127.0.0.1:853", Some("a")),
                tls("127.0.0.1:853", Some("b")),
            ]
        );
    }

    // CoreDNS v1.15.0 plugin/forward/setup_test.go TestSetupTLS: the options are accepted without a TLS upstream.
    #[test]
    fn tls_options_are_accepted_for_plain_upstreams() {
        assert!(parse_text("forward . 127.0.0.1 {\ntls\ntls_servername dns\n}").is_ok());
        assert!(parse_text("forward . tls://127.0.0.1%example.net {\ntls\n}").is_ok());
    }

    // CoreDNS v1.15.0 plugin/pkg/tls/tls.go NewTLSConfigFromArgs: zero to three arguments.
    #[test]
    fn tls_option_takes_ca_or_cert_key_and_optional_ca() {
        let ca = format!("{FIXTURES}/ca.pem");
        let cert = format!("{FIXTURES}/client.pem");
        let key = format!("{FIXTURES}/client.key.pem");
        assert!(
            parse_text("forward . tls://127.0.0.1 {\ntls\n}")
                .unwrap()
                .tls_client
                .is_none()
        );
        for line in [
            format!("tls {ca}"),
            format!("tls {cert} {key}"),
            format!("tls {cert} {key} {ca}"),
        ] {
            let config = parse_text(&format!("forward . tls://127.0.0.1 {{\n{line}\n}}"))
                .unwrap_or_else(|error| panic!("{line}: {error}"));
            assert!(config.tls_client.is_some(), "{line}");
        }
    }

    #[test]
    fn tls_option_rejects_bad_arguments_and_files() {
        let ca = format!("{FIXTURES}/ca.pem");
        let key = format!("{FIXTURES}/client.key.pem");
        let missing = format!("{FIXTURES}/missing.pem");
        for line in [
            format!("tls {ca} {ca} {ca} {ca}"),
            format!("tls {missing}"),
            format!("tls {ca} {key} {ca}"),
            format!("tls {ca} {missing}"),
            format!("tls {key}"),
        ] {
            assert!(
                parse_text(&format!("forward . 127.0.0.1 {{\n{line}\n}}")).is_err(),
                "accepted {line}"
            );
        }
    }

    // CoreDNS v1.15.0 plugin/forward/setup.go parseBlock: relative `tls` paths join the `root`.
    #[test]
    fn tls_option_paths_resolve_against_root() {
        let tokens = lex("Corefile", "forward . tls://127.0.0.1 {\ntls ca.pem\n}");
        let root = std::path::Path::new(FIXTURES);
        let config = parse(&mut Cursor::new("Corefile", &tokens), Some(root)).unwrap();
        assert!(config.tls_client.is_some());
        assert!(parse_text("forward . tls://127.0.0.1 {\ntls ca.pem\n}").is_err());
    }

    #[test]
    fn duration_units_and_bounds() {
        assert_eq!(duration("1h2m3.5s"), Some(Duration::from_millis(3_723_500)));
        assert_eq!(duration("0"), Some(Duration::ZERO));
        assert_eq!(duration("1us"), Some(Duration::from_micros(1)));
        assert_eq!(duration("1µs"), Some(Duration::from_micros(1)));
        assert_eq!(duration("-0.0s"), Some(Duration::ZERO));
        for bad in ["-1s", "1", "NaNs", "1s2", "999999999999999999999h"] {
            assert_eq!(duration(bad), None, "{bad}");
        }
    }

    #[test]
    fn coredns_rcodes_and_bracketed_ipv6() {
        let config = parse_text("forward . [::1] {\nnext notimpl DSOTYPENI\n}").unwrap();
        assert_eq!(
            config.upstreams,
            [Target::Address("[::1]:53".parse().unwrap())]
        );
        assert_eq!(config.next, [4, 11]);
        assert!(parse_text("forward . 1.1.1.1 {\nnext BADVERS\n}").is_err());
    }

    #[test]
    fn successive_directives_share_cursor() {
        let tokens = lex(
            "Corefile",
            "forward . 192.0.2.1 {\npolicy sequential\n}\nforward example.org 192.0.2.2",
        );
        let mut cursor = Cursor::new("Corefile", &tokens);
        assert_eq!(parse(&mut cursor, None).unwrap().policy, Policy::Sequential);
        assert_eq!(parse(&mut cursor, None).unwrap().from, "example.org.");
    }

    #[test]
    fn reads_resolv_conf_and_deduplicates() {
        let path = std::env::temp_dir().join(format!("pharos-forward-{}.conf", std::process::id()));
        std::fs::write(
            &path,
            "# comment\nnameserver 192.0.2.1\nnameserver ::1\nnameserver 192.0.2.1\n",
        )
        .unwrap();
        let config = parse_text(&format!("forward . {} 192.0.2.1", path.display())).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(
            config.upstreams,
            [
                Target::Address("192.0.2.1:53".parse().unwrap()),
                Target::Address("[::1]:53".parse().unwrap())
            ]
        );
    }

    #[test]
    fn upstream_limit_counts_nonempty_entries_not_expanded_addresses() {
        let path =
            std::env::temp_dir().join(format!("pharos-forward-many-{}.conf", std::process::id()));
        let nameservers = (1..=16)
            .map(|i| format!("nameserver 192.0.2.{i}\n"))
            .collect::<String>();
        std::fs::write(&path, nameservers).unwrap();
        let config = parse_text(&format!("forward . {}", path.display())).unwrap();
        assert_eq!(config.upstreams.len(), 16);
        std::fs::write(&path, "# empty\n").unwrap();
        let empty_files = vec![path.to_string_lossy().to_string(); 16].join(" ");
        assert!(parse_text(&format!("forward . {empty_files} 192.0.2.1")).is_ok());
        let addresses = (1..=16)
            .map(|i| format!("192.0.2.{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(parse_text(&format!("forward . {addresses}")).is_err());
        let fifteen = (1..=15)
            .map(|i| format!("192.0.2.{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(parse_text(&format!("forward . {fifteen}")).is_ok());
        std::fs::write(&path, "nameserver 192.0.2.20\n").unwrap();
        assert!(parse_text(&format!("forward . {} {fifteen}", path.display())).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn scoped_and_invalid_resolv_conf_nameservers_follow_coredns() {
        let path =
            std::env::temp_dir().join(format!("pharos-forward-scoped-{}.conf", std::process::id()));
        std::fs::write(&path, "nameserver fe80::1%eth0\nnameserver #\nnameserver\n").unwrap();
        let config = parse_text(&format!("forward . {}", path.display())).unwrap();
        assert_eq!(
            config.upstreams,
            [
                Target::Address("[fe80::1]:53".parse().unwrap()),
                Target::Invalid("#:53".into())
            ]
        );
        let config = parse_text("forward . [fe80::1%eth0]:5300").unwrap();
        assert_eq!(
            config.upstreams,
            [Target::Address("[fe80::1]:5300".parse().unwrap())]
        );
        let config = parse_text("forward . 127.0.0.1%eth0:5300").unwrap();
        assert_eq!(
            config.upstreams,
            [Target::Address("127.0.0.1:5300".parse().unwrap())]
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn hostname_upstream_uses_configured_resolver_at_setup() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let resolver = std::thread::spawn(move || {
            let mut wire = [0; 512];
            for expected_type in [1, 28] {
                let (len, peer) = socket.recv_from(&mut wire).unwrap();
                let query = pharos_proto::Message::parse(&wire[..len]).unwrap();
                let question = query.questions().next().unwrap();
                assert_eq!(question.name.to_string(), "upstream.example.");
                assert_eq!(question.qtype.0, expected_type);
                assert!(query.rd());
                wire[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
                let mut response = wire[..len].to_vec();
                if expected_type == 1 {
                    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
                    response.extend_from_slice(&[
                        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 42,
                    ]);
                }
                socket.send_to(&response, peer).unwrap();
            }
        });
        let config = parse_text(&format!(
            "forward . upstream.example:5300 {{\n resolver {address}\n}}"
        ))
        .unwrap();
        assert_eq!(
            config.upstreams,
            [Target::Address("127.0.0.42:5300".parse().unwrap())]
        );
        resolver.join().unwrap();
    }
}
