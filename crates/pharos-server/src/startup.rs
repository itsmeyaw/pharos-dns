use std::fmt::Write;

/// Render sorted served-Domain lines in CoreDNS's startup format.
pub fn startup_domains(protocol: &str, address: &str, domains: &[&str]) -> String {
    let mut domains = domains.to_vec();
    domains.sort_unstable();
    domains.dedup();
    let parsed = split_address(address);
    let mut output = String::new();
    for domain in domains {
        if !preferred(domain) {
            writeln!(
                output,
                "Warning: Domain {domain:?} does not follow RFC1035 preferred syntax"
            )
            .unwrap();
        }
        match parsed {
            Some(("", port)) => writeln!(output, "{protocol}{domain}:{port}").unwrap(),
            Some((host, port)) => writeln!(output, "{protocol}{domain}:{port} on {host}").unwrap(),
            None => writeln!(output, "{protocol}{domain}:{address}").unwrap(),
        }
    }
    output
}

fn split_address(address: &str) -> Option<(&str, &str)> {
    let address = address
        .split_once("://")
        .map_or(address, |(_, address)| address);
    let (host, port) = address.rsplit_once(':')?;
    let host = if host.starts_with('[') {
        host.strip_prefix('[')?.strip_suffix(']')?
    } else if host.contains(':') || host.contains(['[', ']']) {
        return None;
    } else {
        host
    };
    Some((host, port))
}

fn preferred(domain: &str) -> bool {
    if domain == "." || domain.ends_with(".in-addr.arpa.") || domain.ends_with(".ip6.arpa.") {
        return true;
    }
    let Some(domain) = domain.strip_suffix('.') else {
        return false;
    };
    domain.split('.').all(|label| {
        let bytes = label.as_bytes();
        bytes.first().is_some_and(u8::is_ascii_alphabetic)
            && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    })
}
