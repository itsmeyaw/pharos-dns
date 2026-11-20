use std::{
    io,
    net::{IpAddr, SocketAddr},
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
    client::{Client, Target, Tls},
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
    for target in targets {
        let (to, host) = match &target {
            Target::Tcp(address) => (address.to_string(), address.ip().to_string()),
            Target::Unix(path) => (format!("unix://{}", path.display()), "localhost".to_owned()),
        };
        let tls = config
            .as_ref()
            .map(|config| {
                // RFC 6125 §6.4.1: verify the name the Corefile gives, else the Upstream's address.
                let name = tls_servername.clone().unwrap_or(host);
                ServerName::try_from(name.clone())
                    .map(|server_name| Tls {
                        config: Arc::clone(config),
                        server_name,
                    })
                    .map_err(|_| cursor.error(format!("invalid TLS server name {name}")))
            })
            .transpose()?;
        // grpc-go takes the `:authority` from the credentials' server name, else the target.
        let authority = tls_servername.clone().unwrap_or_else(|| match &target {
            Target::Tcp(address) => address.to_string(),
            Target::Unix(_) => "localhost".to_owned(),
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
    })
}

// CoreDNS v1.15.0 plugin/pkg/parse/host.go HostPortOrFile: each TO is `IP`, `IP:PORT`, `unix://PATH` or a resolv.conf-style file.
fn targets(to: &[String]) -> Result<Vec<Target>, String> {
    let mut targets = Vec::new();
    for entry in to {
        if let Some(path) = entry.strip_prefix("unix://") {
            if path.is_empty() {
                return Err(format!("invalid address: {entry:?}"));
            }
            targets.push(Target::Unix(path.into()));
        } else if let Some((scheme, _)) = entry.split_once("://") {
            // shortcut: other schemes reach grpc-go as an unusable target and only fail at the first Query; rejecting them at setup is clearer.
            return Err(format!("{scheme} Upstreams are not supported"));
        } else if let Some(address) = address(entry) {
            targets.push(Target::Tcp(address));
        } else {
            let file = std::fs::read_to_string(entry)
                .map_err(|error| format!("not an IP address or file {entry:?}: {error}"))?;
            // miekg/dns ClientConfigFromFile: the second field of each `nameserver` line, on port 53.
            for line in file.lines() {
                let mut words = line.split_whitespace();
                if words.next() == Some("nameserver")
                    && let Some(server) = words.next()
                {
                    let address = address(server)
                        .ok_or_else(|| format!("invalid nameserver {server:?} in {entry:?}"))?;
                    targets.push(Target::Tcp(address));
                }
            }
        }
    }
    if targets.is_empty() {
        return Err("no nameservers found".into());
    }
    Ok(targets)
}

// RFC 1035 §4.2.1: DNS uses server port 53 by default; like CoreDNS, an IPv6 zone is dropped.
fn address(value: &str) -> Option<SocketAddr> {
    value.parse::<SocketAddr>().ok().or_else(|| {
        let host = value.trim_matches(['[', ']']);
        let host = host.rsplit_once('%').map_or(host, |(host, _)| host);
        host.parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 53))
    })
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

    #[test]
    fn addresses_default_to_port_53_and_zones_are_dropped() {
        let grpc =
            parse_text("grpc . 127.0.0.1 [::1] 127.0.0.2:8080 [fe80::1%eth0] [::2]:853").unwrap();
        assert_eq!(
            labels(&grpc),
            [
                "127.0.0.1:53",
                "[::1]:53",
                "127.0.0.2:8080",
                "[fe80::1]:53",
                "[::2]:853"
            ]
        );
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
            "# comment\nsearch example.org\nnameserver 10.10.255.252\nnameserver 10.10.255.253\nnameserver fe80::1%eth0\n",
        )
        .unwrap();
        let grpc = parse_text(&format!("grpc . {}", file.display())).unwrap();
        assert_eq!(
            labels(&grpc),
            ["10.10.255.252:53", "10.10.255.253:53", "[fe80::1]:53"]
        );
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
    fn missing_arguments_and_unsupported_schemes_fail() {
        for input in [
            "grpc",
            "grpc .",
            "grpc . unix://",
            "grpc . tls://127.0.0.1",
            "grpc . grpc://127.0.0.1",
            "grpc . localhost",
        ] {
            assert!(parse_text(input).is_err(), "accepted {input}");
        }
    }
}
