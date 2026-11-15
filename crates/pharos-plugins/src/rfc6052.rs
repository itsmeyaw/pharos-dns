use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) const WELL_KNOWN_PREFIX: [u8; 16] =
    [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

// RFC 6052 §3.1: The Well-Known Prefix must not represent non-global IPv4 addresses.
pub(crate) fn is_global_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && a != 0
        && !(a == 100 && b & 0xc0 == 0x40)
        && !(a == 192 && b == 0 && c == 0 && !matches!(d, 9 | 10))
        && !(a == 192 && b == 88 && c == 99)
        && !(a == 192 && b == 0 && c == 2)
        && !(a == 198 && (b == 18 || b == 19))
        && !(a == 198 && b == 51 && c == 100)
        && !(a == 203 && b == 0 && c == 113)
        && a < 240
}

pub(crate) enum PrefixError {
    Format,
    Length,
    WellKnownLength,
    ReservedOctet,
}

pub(crate) fn parse(value: &str) -> Result<([u8; 16], u8), PrefixError> {
    let (ip, len) = value.split_once('/').ok_or(PrefixError::Format)?;
    // RFC 4291 §2.2: IPv6 addresses use conventional textual address forms.
    let ip: Ipv6Addr = ip.parse().map_err(|_| PrefixError::Format)?;
    let len: u8 = len.parse().map_err(|_| PrefixError::Format)?;
    let mut bytes = ip.octets();
    normalize(&mut bytes, len)?;
    Ok((bytes, len))
}

fn normalize(bytes: &mut [u8; 16], len: u8) -> Result<(), PrefixError> {
    // RFC 6052 §2.2: only the six defined prefix lengths are valid.
    if !matches!(len, 32 | 40 | 48 | 56 | 64 | 96) {
        return Err(PrefixError::Length);
    }
    bytes[usize::from(len / 8)..].fill(0);
    // RFC 6052 §2.1: check the masked prefix so host bits cannot hide the WKP.
    if len != 96 && bytes[..12] == WELL_KNOWN_PREFIX[..12] {
        return Err(PrefixError::WellKnownLength);
    }
    // RFC 6052 §2.2: the reserved octet must be zero.
    if bytes[8] != 0 {
        return Err(PrefixError::ReservedOctet);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_global_ipv4;
    use std::net::Ipv4Addr;

    #[test]
    fn globally_reachable_ipv4_excludes_special_use_ranges() {
        for address in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
        ] {
            assert!(
                !is_global_ipv4(address.parse::<Ipv4Addr>().unwrap()),
                "{address}"
            );
        }
        assert!(is_global_ipv4("8.8.8.8".parse().unwrap()));
        assert!(is_global_ipv4("192.0.0.9".parse().unwrap()));
    }
}
