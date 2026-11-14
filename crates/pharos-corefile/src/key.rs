use std::net::IpAddr;

/// A normalized Server Block Key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ServerBlockKey {
    /// Transport selected by the key.
    pub transport: String,
    /// Fully qualified, lowercased Domain.
    pub domain: String,
    /// Decimal port, or an empty string for the Unix transport's default.
    pub port: String,
}

/// Normalize one Server Block Key, expanding CIDRs into reverse Domains.
pub fn normalize_key(key: &str) -> Result<Vec<ServerBlockKey>, String> {
    let (transport, host) = ["dns", "tls", "quic", "grpc", "https", "https3", "unix"]
        .into_iter()
        .find_map(|transport| {
            key.strip_prefix(&format!("{transport}://"))
                .map(|host| (transport, host))
        })
        .unwrap_or(("dns", key));

    if host.is_empty() || host.ends_with(':') {
        return Err(format!("expecting data after last colon: {host:?}"));
    }
    let (host, port) = host
        .rsplit_once(':')
        .and_then(|(host, port)| {
            port.parse::<i64>()
                .ok()
                .map(|port| (host, port.to_string()))
        })
        .unwrap_or((host, String::new()));
    if !valid_domain(host) {
        return Err(format!("invalid Domain: {host}"));
    }

    let domains = match parse_cidr(host) {
        Some((ip, prefix)) => reverse_domains(ip, prefix),
        None => vec![fqdn(host)],
    };
    // RFC 1035 §4.2.2: DNS messages sent over TCP use server port 53.
    let port = if port.is_empty() {
        match transport {
            "dns" => "53",
            "tls" | "quic" => "853",
            "grpc" | "https" | "https3" => "443",
            _ => "",
        }
        .to_owned()
    } else {
        port
    };
    domains
        .into_iter()
        .map(|domain| {
            if !valid_domain(&domain) {
                return Err(format!("invalid Domain: {domain}"));
            }
            Ok(ServerBlockKey {
                transport: transport.to_owned(),
                domain: domain.chars().map(go_lowercase).collect(),
                port: port.clone(),
            })
        })
        .collect()
}

fn go_lowercase(c: char) -> char {
    // RFC 4343 §3: DNS name matching folds ASCII A–Z only.
    c.to_ascii_lowercase()
}

fn fqdn(name: &str) -> String {
    let is_fqdn = name.strip_suffix('.').is_some_and(|prefix| {
        if !prefix.ends_with('\\') {
            return true;
        }
        // Match miekg/dns's byte-index calculation, including its Unicode edge case.
        let last_non_escape = prefix.char_indices().rfind(|(_, c)| *c != '\\');
        let distance = last_non_escape.map_or(prefix.len() + 1, |(index, _)| prefix.len() - index);
        !distance.is_multiple_of(2)
    });
    if is_fqdn {
        name.to_owned()
    } else {
        format!("{name}.")
    }
}

fn valid_domain(name: &str) -> bool {
    // RFC 1035 §5.1: reject a trailing escape before FQDN expansion can consume it.
    if name.is_empty() || name.ends_with('\\') {
        return false;
    }
    let qualified = fqdn(name);
    let bytes = qualified.as_bytes();
    let (mut i, mut label_len, mut name_len) = (0, 0, 0);
    let mut was_dot = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                let digits = bytes
                    .get(i + 1..i + 4)
                    .is_some_and(|digits| digits.iter().all(u8::is_ascii_digit));
                if digits {
                    // RFC 1035 §2.3.4: a decimal escape represents one wire octet.
                    label_len += 1;
                    i += 4;
                } else if i + 1 < bytes.len() {
                    label_len += 1;
                    i += 2;
                } else {
                    return false;
                }
                if label_len > 63 {
                    return false;
                }
                was_dot = false;
            }
            b'.' => {
                if (i == 0 && bytes.len() > 1) || was_dot {
                    return false;
                }
                name_len += 1 + label_len;
                // RFC 1035 §2.3.4: DNS names are limited to 255 wire octets.
                if name_len > 255 {
                    return false;
                }
                label_len = 0;
                was_dot = true;
                i += 1;
            }
            _ => {
                label_len += 1;
                if label_len > 63 {
                    return false;
                }
                was_dot = false;
                i += 1;
            }
        }
    }
    // RFC 1035 §5.1: an escaped dot is label data, not the terminating root label.
    was_dot
}

fn parse_cidr(host: &str) -> Option<(IpAddr, u32)> {
    let (address, prefix) = host.split_once('/')?;
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ip: IpAddr = address.parse().ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    (prefix <= bits).then_some((ip, prefix))
}

fn reverse_domains(ip: IpAddr, prefix: u32) -> Vec<String> {
    // RFC 1035 §3.5: IPv4 reverse names use reversed decimal octets under in-addr.arpa.
    // RFC 3596 §2.5: IPv6 reverse names use reversed hex nibbles under ip6.arpa.
    let (value, bits, step, suffix) = match ip {
        IpAddr::V4(ip) => (u128::from(u32::from(ip)), 32, 8, "in-addr.arpa."),
        IpAddr::V6(ip) => (u128::from(ip), 128, 4, "ip6.arpa."),
    };
    // RFC 4291 §2.3: CIDR prefixes identify the leftmost contiguous address bits.
    let rounded = prefix.div_ceil(step) * step;
    let network = if prefix == 0 {
        0
    } else {
        (value >> (bits - prefix)) << (bits - prefix)
    };
    let count = 1_u128 << (rounded - prefix);
    (0..count)
        .map(|index| {
            let value = if rounded == 0 {
                network
            } else {
                network | (index << (bits - rounded))
            };
            let mut domain = String::new();
            for label in (0..rounded / step).rev() {
                let digit = (value >> (bits - step * (label + 1))) & ((1 << step) - 1);
                if step == 8 {
                    domain.push_str(&format!("{digit}."));
                } else {
                    domain.push_str(&format!("{digit:x}."));
                }
            }
            domain.push_str(suffix);
            domain
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{ServerBlockKey, normalize_key};

    fn key(transport: &str, domain: &str, port: &str) -> ServerBlockKey {
        ServerBlockKey {
            transport: transport.into(),
            domain: domain.into(),
            port: port.into(),
        }
    }

    #[test]
    fn transport_and_port_defaults() {
        for (input, transport, port) in [
            (".", "dns", "53"),
            ("dns://Example.ORG", "dns", "53"),
            ("tls://Example.ORG.", "tls", "853"),
            ("quic://example.org", "quic", "853"),
            ("grpc://example.org", "grpc", "443"),
            ("https://example.org", "https", "443"),
            ("https3://example.org", "https3", "443"),
            ("unix://example.org", "unix", ""),
        ] {
            let domain = if input == "." { "." } else { "example.org." };
            assert_eq!(
                normalize_key(input).unwrap(),
                [key(transport, domain, port)],
                "{input}"
            );
        }
    }

    #[test]
    fn numeric_ports_are_canonicalized_without_range_validation() {
        for (input, domain, port) in [
            ("Example.Org:0053", "example.org.", "53"),
            ("example.org:+53", "example.org.", "53"),
            ("example.org:-1", "example.org.", "-1"),
            ("example.org:99999", "example.org.", "99999"),
            ("example.org:http", "example.org:http.", "53"),
            ("unknown://Example.org", "unknown://example.org.", "53"),
            ("2001:db8::1", "2001:db8:.", "1"),
        ] {
            assert_eq!(
                normalize_key(input).unwrap(),
                [key("dns", domain, port)],
                "{input}"
            );
        }
    }

    #[test]
    fn expands_ipv4_networks_on_octet_boundaries() {
        assert_eq!(
            normalize_key("10.0.0.0/8:53").unwrap(),
            [key("dns", "10.in-addr.arpa.", "53")]
        );
        assert_eq!(
            normalize_key("tls://192.168.1.1/23:0054").unwrap(),
            [
                key("tls", "0.168.192.in-addr.arpa.", "54"),
                key("tls", "1.168.192.in-addr.arpa.", "54"),
            ]
        );
        let expanded = normalize_key("10.9.3.0/18").unwrap();
        assert_eq!(expanded.len(), 64);
        assert_eq!(expanded[0], key("dns", "0.9.10.in-addr.arpa.", "53"));
        assert_eq!(expanded[63], key("dns", "63.9.10.in-addr.arpa.", "53"));
        assert_eq!(
            normalize_key("0.0.0.0/0").unwrap(),
            [key("dns", "in-addr.arpa.", "53")]
        );
    }

    #[test]
    fn expands_ipv6_networks_on_nibble_boundaries() {
        assert_eq!(
            normalize_key("2001:db8::/31").unwrap(),
            [
                key("dns", "8.b.d.0.1.0.0.2.ip6.arpa.", "53"),
                key("dns", "9.b.d.0.1.0.0.2.ip6.arpa.", "53"),
            ]
        );
        let expanded = normalize_key("2001:db8::/29:853").unwrap();
        assert_eq!(expanded.len(), 8);
        assert_eq!(expanded[7], key("dns", "f.b.d.0.1.0.0.2.ip6.arpa.", "853"));
        assert!(normalize_key("::1/128").is_ok());
        assert!(normalize_key("0:1::/32").is_ok());
        assert_eq!(
            normalize_key("2001:db8::/0").unwrap(),
            [key("dns", "ip6.arpa.", "53")]
        );
    }

    #[test]
    fn trailing_dot_and_invalid_cidr_remain_domains() {
        for (input, domain) in [
            ("10.0.0.0/8.", "10.0.0.0/8."),
            ("2001:db8::/32.", "2001:db8::/32."),
            ("10.0.0.0/99", "10.0.0.0/99."),
            ("10.0.0/8", "10.0.0/8."),
        ] {
            assert_eq!(
                normalize_key(input).unwrap(),
                [key("dns", domain, "53")],
                "{input}"
            );
        }
    }

    #[test]
    fn validates_domain_names_like_coredns() {
        for input in ["", "dns://", "example:", ".example", "a..b", "a\\", "ȶ\\."] {
            assert!(normalize_key(input).is_err(), "{input:?}");
        }
        assert!(normalize_key(&format!("{}.example", "a".repeat(64))).is_err());
        assert!(normalize_key(&"a".repeat(256)).is_err());
        assert_eq!(
            normalize_key("A\\.B.Example").unwrap(),
            [key("dns", "a\\.b.example.", "53")]
        );
        assert_eq!(normalize_key("A\\.").unwrap(), [key("dns", "a\\..", "53")]);
        assert_eq!(
            normalize_key("AİᲉ\u{10d50}\u{16ea0}").unwrap(),
            [key("dns", "aİᲉ\u{10d50}\u{16ea0}.", "53")]
        );
    }

    #[test]
    fn name_limits_count_wire_octets_not_presentation_escapes() {
        let long_presentation = [
            "A".repeat(63),
            "B".repeat(63),
            "C".repeat(63),
            "D".repeat(61),
        ]
        .iter()
        .map(|label| {
            label
                .chars()
                .map(|c| format!("\\{:03}", c as u8))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(".");
        let key = normalize_key(&long_presentation).unwrap();
        assert_eq!(key[0].domain, format!("{long_presentation}."));
        let overlong = vec!["a".repeat(63); 4].join(".");
        assert!(normalize_key(&overlong).is_err());
    }
}
