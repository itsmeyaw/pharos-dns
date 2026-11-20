use std::{
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicU32},
};

use pharos_corefile::{BlockContext, Cursor, Error, Fallthrough, normalize_domain};
use pharos_proto::Name;
use pharos_server::{
    grpc,
    tls::{ClientConfig, ClientOptions, ServerName, client_config},
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
                tls_client =
                    client_for(&args, root).map_err(|error| cursor.error(error.to_string()))?;
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

// CoreDNS v1.15.0 plugin/pkg/tls/tls.go NewTLSConfigFromArgs: `CA`, `CERT KEY` or `CERT KEY CA`, and no arguments for the system roots.
fn client_for(args: &[String], root: Option<&Path>) -> io::Result<Option<Arc<ClientConfig>>> {
    // CoreDNS v1.15.0 plugin/grpc/setup.go parseBlock: a relative path is joined to `root`.
    let path = |index: usize| -> PathBuf { crate::resolve_path(args[index].clone().into(), root) };
    let options = match args.len() {
        0 => return Ok(None),
        1 => ClientOptions {
            ca: Some(path(0)),
            identity: None,
        },
        2 | 3 => ClientOptions {
            ca: (args.len() == 3).then(|| path(2)),
            identity: Some((path(0), path(1))),
        },
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    client_config(&options).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_corefile::lex;

    fn parse_text(text: &str) -> Result<Grpc, Error> {
        let tokens = lex("Corefile", text);
        parse(&mut Cursor::new("Corefile", &tokens), None)
    }

    fn name(text: &str) -> Name {
        text.parse().unwrap()
    }

    fn labels(grpc: &Grpc) -> Vec<&str> {
        grpc.upstreams.iter().map(|u| u.to.as_str()).collect()
    }

    // CoreDNS v1.15.0 plugin/grpc/setup_test.go TestSetup.
    #[test]
    fn setup_accepts_and_rejects_what_coredns_does() {
        for input in [
            "grpc . 127.0.0.1",
            "grpc . 127.0.0.1 {\nexcept miek.nl\n}\n",
            "grpc . 127.0.0.1:53",
            "grpc . 127.0.0.1:8080",
            "grpc . [::1]:53",
            "grpc . [2003::1]:53",
            "grpc . unix:///var/run/g.sock",
        ] {
            let grpc = parse_text(input).unwrap_or_else(|error| panic!("{input}: {error}"));
            assert_eq!(grpc.from, name("."), "{input}");
        }
        for (input, expected) in [
            ("grpc . a27.0.0.1", "not an IP"),
            ("grpc . 127.0.0.1 {\nblaatl\n}\n", "unknown property"),
            (
                "grpc xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 127.0.0.1",
                "unable to normalize 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
            ),
        ] {
            let error = parse_text(input).unwrap_err().to_string();
            assert!(error.contains(expected), "{input}: {error}");
        }
    }

    fn targets_of(grpc: &Grpc) -> Vec<&Target> {
        grpc.upstreams.iter().map(|u| &u.client.target).collect()
    }

    fn tcp(text: &str) -> Target {
        Target::Tcp(text.parse().unwrap())
    }

    fn host(host: &str, port: u16) -> Target {
        Target::Host {
            host: host.into(),
            port,
        }
    }

    // CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: an address without a port gets 53 and keeps its zone.
    #[test]
    fn addresses_default_to_port_53_and_keep_their_text() {
        let grpc = parse_text(
            "grpc . 127.0.0.1 [::1] 127.0.0.2:8080 fe80::1%eth0 [fe80::1%eth0] [fe80::2%2]:853 [0:0:0:0:0:0:0:1]:53 dns://10.0.0.1",
        )
        .unwrap();
        assert_eq!(
            labels(&grpc),
            [
                "127.0.0.1:53",
                "[::1]:53",
                "127.0.0.2:8080",
                "[fe80::1%eth0]:53",
                "[fe80::1%eth0]:53",
                "[fe80::2%2]:853",
                "[0:0:0:0:0:0:0:1]:53",
                "10.0.0.1:53",
            ]
        );
        assert_eq!(
            targets_of(&grpc),
            [
                &tcp("127.0.0.1:53"),
                &tcp("[::1]:53"),
                &tcp("127.0.0.2:8080"),
                &host("fe80::1%eth0", 53),
                &host("fe80::1%eth0", 53),
                &host("fe80::2%2", 853),
                &tcp("[::1]:53"),
                &tcp("10.0.0.1:53"),
            ]
        );
    }

    // CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: a scheme other than dns:// and unix:// passes setup and fails at dial.
    #[test]
    fn other_schemes_and_bad_ports_are_accepted_and_fail_at_dial() {
        let grpc = parse_text(
            "grpc . tls://127.0.0.1 grpc://127.0.0.1:8080 https://[::1] quic://10.0.0.1:853 https3://10.0.0.1 dns://127.0.0.1:53 127.0.0.1:99999 127.0.0.1:",
        )
        .unwrap();
        assert_eq!(
            labels(&grpc),
            [
                "tls://127.0.0.1:853",
                "grpc://127.0.0.1:8080",
                "https://[::1]:443",
                "quic://10.0.0.1:853",
                "",
                "dns://127.0.0.1:53",
                "127.0.0.1:99999",
                "127.0.0.1:",
            ]
        );
        assert!(
            targets_of(&grpc)
                .iter()
                .all(|target| matches!(target, Target::Invalid(_)))
        );
    }

    // CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: a port is not checked, so port 0 is accepted.
    #[test]
    fn port_zero_is_accepted() {
        let grpc = parse_text("grpc . 127.0.0.1:0").unwrap();
        assert_eq!(targets_of(&grpc), [&tcp("127.0.0.1:0")]);
    }

    #[test]
    fn except_names_are_normalized() {
        let grpc =
            parse_text("grpc . 127.0.0.1 {\nexcept Miek.nl example.org.\nexcept a.b\n}").unwrap();
        assert_eq!(
            grpc.ignored,
            [name("miek.nl."), name("example.org."), name("a.b.")]
        );
        assert!(parse_text("grpc . 127.0.0.1 {\nexcept\n}").is_err());
    }

    // CoreDNS v1.15.0 plugin/grpc/setup_test.go TestSetupTLS.
    #[test]
    fn tls_options_are_accepted() {
        for input in [
            "grpc . 127.0.0.1 {\ntls_servername dns\n}",
            "grpc . 127.0.0.1 {\ntls\n}",
            "grpc . 127.0.0.1",
        ] {
            parse_text(input).unwrap_or_else(|error| panic!("{input}: {error}"));
        }
        for input in [
            "grpc . 127.0.0.1 {\ntls a b c d\n}",
            "grpc . 127.0.0.1 {\ntls_servername\n}",
            "grpc . 127.0.0.1 {\ntls_servername a b\n}",
            "grpc . 127.0.0.1 {\ntls /nonexistent/ca.pem\n}",
        ] {
            assert!(parse_text(input).is_err(), "accepted {input}");
        }
    }

    // CoreDNS v1.15.0 plugin/grpc/setup_test.go TestSetupResolvconf.
    #[test]
    fn resolv_conf_nameservers_become_upstreams() {
        let dir = std::env::temp_dir().join(format!("pharos-grpc-resolv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("resolv.conf");
        std::fs::write(
            &file,
            "# comment\nsearch example.org\nnameserver 10.10.255.252\nnameserver 10.10.255.253\nnameserver fe80::1%eth0\nnameserver dns.example.org\nnameserver 10.0.0.1:5\n",
        )
        .unwrap();
        let grpc = parse_text(&format!("grpc . {}", file.display())).unwrap();
        // CoreDNS v1.15.0 plugin/pkg/parse/host.go tryFile: the zone is dropped, and any other name is kept for the dial.
        assert_eq!(
            labels(&grpc),
            [
                "10.10.255.252:53",
                "10.10.255.253:53",
                "[fe80::1]:53",
                "dns.example.org:53",
                "[10.0.0.1:5]:53"
            ]
        );
        let targets = targets_of(&grpc);
        assert_eq!(targets[2], &tcp("[fe80::1]:53"));
        assert_eq!(targets[3], &host("dns.example.org", 53));
        assert!(matches!(targets[4], Target::Invalid(_)));
        std::fs::write(&file, "search example.org\n").unwrap();
        assert!(
            parse_text(&format!("grpc . {}", file.display()))
                .unwrap_err()
                .to_string()
                .contains("no nameservers found")
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    // CoreDNS v1.15.0 plugin/grpc/setup_test.go TestSetupFallthrough.
    #[test]
    fn fallthrough_zones() {
        let zones = |input: &str| parse_text(input).unwrap().fallthrough;
        assert_eq!(zones("grpc . 127.0.0.1 {\nfallthrough\n}"), [name(".")]);
        assert_eq!(
            zones("grpc . 127.0.0.1 {\nfallthrough example.org\n}"),
            [name("example.org.")]
        );
        assert_eq!(
            zones("grpc . 127.0.0.1 {\nfallthrough example.org example.com\n}"),
            [name("example.org."), name("example.com.")]
        );
        assert!(zones("grpc . 127.0.0.1").is_empty());
    }

    // CoreDNS v1.15.0 plugin/grpc/setup_policy_test.go TestSetupPolicy.
    #[test]
    fn policy_names() {
        for (policy, expected) in [
            ("random", Policy::Random),
            ("round_robin", Policy::RoundRobin),
            ("sequential", Policy::Sequential),
        ] {
            let grpc = parse_text(&format!("grpc . 127.0.0.1 {{\npolicy {policy}\n}}")).unwrap();
            assert_eq!(grpc.policy, expected);
        }
        assert_eq!(
            parse_text("grpc . 127.0.0.1").unwrap().policy,
            Policy::Random
        );
        assert!(
            parse_text("grpc . 127.0.0.1 {\npolicy random2\n}\n")
                .unwrap_err()
                .to_string()
                .contains("unknown policy")
        );
    }

    // CoreDNS v1.15.0 plugin/grpc/setup.go setup: at most 15 TOs.
    #[test]
    fn at_most_fifteen_upstreams() {
        let hosts = |count: usize| {
            (1..=count)
                .map(|i| format!("127.0.0.{i}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        assert!(parse_text(&format!("grpc . {}", hosts(15))).is_ok());
        assert!(
            parse_text(&format!("grpc . {}", hosts(16)))
                .unwrap_err()
                .to_string()
                .contains("more than 15 TOs configured: 16")
        );
    }

    #[test]
    fn missing_arguments_and_unusable_addresses_fail() {
        for input in [
            "grpc",
            "grpc .",
            "grpc . unix://",
            "grpc . tls://",
            "grpc . localhost",
            "grpc . example.com:53",
            "grpc . 127.0.0.1 localhost",
        ] {
            assert!(parse_text(input).is_err(), "accepted {input}");
        }
    }

    // Go net.SplitHostPort.
    #[test]
    fn host_and_port_split_as_go_does() {
        for (input, expected) in [
            ("127.0.0.1:53", Some(("127.0.0.1", "53"))),
            ("[::1]:53", Some(("::1", "53"))),
            ("[fe80::1%eth0]:", Some(("fe80::1%eth0", ""))),
            ("127.0.0.1", None),
            ("::1", None),
            ("[::1]", None),
            ("[::1]x:53", None),
            ("[::1:53", None),
            ("a[b:53", None),
            ("a]b:53", None),
        ] {
            assert_eq!(split_host_port(input), expected, "{input}");
        }
    }
}
