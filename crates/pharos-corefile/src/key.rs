use std::{fmt::Write as _, net::IpAddr};

/// A normalized Server Block Key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ServerBlockKey {
    /// Transport selected by the key.
    pub transport: String,
    /// Fully qualified Domain in ASCII presentation, with non-ASCII octets escaped.
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
    // RFC 1035 §2.3.4 / ADR 0003: preserve CoreDNS v1.15.0's 255-byte presentation cap.
    if host.len() > 255 || !valid_domain(host) {
        return Err(format!("invalid Domain: {host}"));
    }

    let domains = match parse_cidr(host) {
        Some((ip, prefix)) => {
            // RFC 4291 §2.3 / ADR 0003: preserve CoreDNS v1.15.0's IPv6 CIDR rejection.
            if host.starts_with(':') || (host.starts_with('0') && host.contains(':')) {
                return Err(format!("invalid CIDR {host}"));
            }
            reverse_domains(ip, prefix)
        }
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
            // RFC 1035 §2.3.4 / ADR 0003: CoreDNS also caps the qualified presentation.
            if domain.len() > 255 || !valid_domain(&domain) {
                return Err(format!("invalid Domain: {domain}"));
            }
            Ok(ServerBlockKey {
                transport: transport.to_owned(),
                domain: ascii_presentation(&domain.chars().map(go_lowercase).collect::<String>()),
                port: port.clone(),
            })
        })
        .collect()
}

fn go_lowercase(c: char) -> char {
    // RFC 4343 §3 / ADR 0003: match CoreDNS Go 1.26.0 ToLower; recheck on Go upgrade.
    match c {
        '\u{1c89}'
        | '\u{a7cb}'
        | '\u{a7cc}'
        | '\u{a7ce}'
        | '\u{a7d2}'
        | '\u{a7d4}'
        | '\u{a7da}'
        | '\u{a7dc}'
        | '\u{10d50}'..='\u{10d65}'
        | '\u{16ea0}'..='\u{16eb8}' => c,
        _ => c.to_lowercase().next().unwrap_or(c),
    }
}

fn ascii_presentation(domain: &str) -> String {
    if domain.is_ascii() {
        return domain.to_owned();
    }
    // RFC 4343 §2.1: Non-ASCII UTF-8 octets need decimal escapes in ASCII presentation.
    let mut escaped = String::with_capacity(domain.len());
    for byte in domain.bytes() {
        if byte.is_ascii() {
            escaped.push(char::from(byte));
        } else {
            write!(escaped, "\\{byte:03}").expect("writing to a String");
        }
    }
    escaped
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
    if name.is_empty() {
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
                    // RFC 1035 §5.1: decimal escapes must fit in one octet.
                    let value = u16::from(bytes[i + 1] - b'0') * 100
                        + u16::from(bytes[i + 2] - b'0') * 10
                        + u16::from(bytes[i + 3] - b'0');
                    if value > u16::from(u8::MAX) {
                        return false;
                    }
                    label_len += 1;
                    i += 4;
                } else if i + 1 < bytes.len() {
                    label_len += 1;
                    i += 2;
                } else {
                    return false;
                }
                was_dot = false;
            }
            b'.' => {
                if (i == 0 && bytes.len() > 1) || was_dot {
                    return false;
                }
                name_len += 1 + label_len;
                // RFC 1035 §2.3.4: leave one octet for the root label.
                if name_len > 254 {
                    return false;
                }
                label_len = 0;
                was_dot = true;
                i += 1;
            }
            _ => {
                label_len += 1;
                was_dot = false;
                i += 1;
            }
        }
        // RFC 1035 §2.3.4: each DNS label is at most 63 wire octets.
        if label_len > 63 {
            return false;
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
mod tests;
