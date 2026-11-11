//! Bind Directive setup and interface expansion.

use std::net::IpAddr;

use pharos_corefile::{Cursor, Error};

fn interfaces() -> Vec<(String, Option<IpAddr>)> {
    match nix::ifaddrs::getifaddrs() {
        Ok(addrs) => addrs
            .map(|entry| {
                let ip = entry.address.and_then(|address| {
                    address
                        .as_sockaddr_in()
                        .map(|ip| IpAddr::V4(ip.ip()))
                        .or_else(|| address.as_sockaddr_in6().map(|ip| IpAddr::V6(ip.ip())))
                });
                (entry.interface_name, ip)
            })
            .collect(),
        Err(error) => {
            pharos_server::logging::log(
                "WARNING",
                "bind",
                &format!("failed to get interfaces list, cannot bind by interface name: {error}"),
            );
            Vec::new()
        }
    }
}

fn expand(
    args: &[String],
    ifaces: &[(String, Option<IpAddr>)],
    cursor: &Cursor<'_>,
) -> Result<Vec<String>, Error> {
    let mut result = Vec::new();
    for arg in args {
        let matches: Vec<_> = ifaces.iter().filter(|(name, _)| name == arg).collect();
        if matches.is_empty() {
            arg.parse::<IpAddr>().map_err(|_| {
                cursor.error(format!("not a valid IP address or interface name: {arg}"))
            })?;
            result.push(arg.clone());
        } else {
            for (_, ip) in matches {
                if let Some(ip) = ip {
                    let mut address = ip.to_string();
                    if let IpAddr::V6(v6) = ip
                        && (v6.is_unicast_link_local()
                            || (v6.is_multicast() && v6.segments()[0] & 0xf == 2))
                    {
                        address.push('%');
                        address.push_str(arg);
                    }
                    result.push(address);
                }
            }
        }
    }
    Ok(result)
}

pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Vec<String>, Error> {
    let ifaces = interfaces();
    parse_with_interfaces(cursor, &ifaces)
}

fn parse_with_interfaces(
    cursor: &mut Cursor<'_>,
    ifaces: &[(String, Option<IpAddr>)],
) -> Result<Vec<String>, Error> {
    let mut all = Vec::new();
    while cursor.next() {
        let args = cursor.remaining_args();
        if args.is_empty() {
            return Err(cursor.error("at least one address or interface name is expected"));
        }
        let mut except = Vec::new();
        while cursor.next_block() {
            if cursor.val() != "except" {
                return Err(cursor.error(format!("invalid option {:?}", cursor.val())));
            }
            except = cursor.remaining_args();
            if except.is_empty() {
                return Err(cursor.error(
                    "at least one address or interface must be given to except subdirective",
                ));
            }
        }
        let ips = expand(&args, ifaces, cursor)?;
        let except = expand(&except, ifaces, cursor)?;
        all.extend(ips.into_iter().filter(|ip| !except.contains(ip)));
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_corefile::Token;

    #[test]
    fn interface_expansion_preserves_link_local_scope() {
        let tokens: Vec<Token> = vec![];
        let cursor = Cursor::new("Corefile", &tokens);
        let ifaces = vec![
            ("test0".into(), Some("127.0.0.1".parse().unwrap())),
            ("test0".into(), Some("::1".parse().unwrap())),
            ("test0".into(), Some("fe80::1".parse().unwrap())),
            ("test0".into(), Some("ff02::1".parse().unwrap())),
            ("test0".into(), Some("ff05::1".parse().unwrap())),
        ];
        assert_eq!(
            expand(&["test0".into()], &ifaces, &cursor).unwrap(),
            [
                "127.0.0.1",
                "::1",
                "fe80::1%test0",
                "ff02::1%test0",
                "ff05::1"
            ]
        );
        assert!(expand(&["missing".into()], &ifaces, &cursor).is_err());
    }

    // CoreDNS plugin/bind/setup_test.go cases, with deterministic interface addresses.
    #[test]
    fn interface_setup_expands_and_excludes_addresses() {
        let ifaces = vec![
            ("lo".into(), Some("127.0.0.1".parse().unwrap())),
            ("lo".into(), Some("::1".parse().unwrap())),
        ];
        for (directive, expected) in [
            ("bind 1.2.3.4 lo", vec!["1.2.3.4", "127.0.0.1", "::1"]),
            ("bind lo {\n except 127.0.0.1\n}", vec!["::1"]),
            ("bind lo {\n except lo\n}", vec![]),
        ] {
            let blocks =
                pharos_corefile::parse("Corefile", &format!(".:53 {{\n{directive}\n}}")).unwrap();
            let mut cursor = Cursor::new("Corefile", &blocks[0].directives["bind"]);
            assert_eq!(
                parse_with_interfaces(&mut cursor, &ifaces).unwrap(),
                expected
            );
        }
    }
}
