//! Parse reverse Query names without allocating.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(super) fn is_reverse(labels: &[&[u8]]) -> bool {
    labels.len() > 2
        && labels[labels.len() - 1].eq_ignore_ascii_case(b"arpa")
        && (labels[labels.len() - 2].eq_ignore_ascii_case(b"in-addr")
            || labels[labels.len() - 2].eq_ignore_ascii_case(b"ip6"))
}

pub(crate) fn address(labels: &[&[u8]]) -> Option<IpAddr> {
    let (suffix, body) = labels.split_last()?;
    if !suffix.eq_ignore_ascii_case(b"arpa") {
        return None;
    }
    let (kind, body) = body.split_last()?;
    // RFC 1035 §3.5: IPv4 reverse names use four reversed decimal octets without leading zeros.
    if kind.eq_ignore_ascii_case(b"in-addr") {
        if body.len() != 4 {
            return None;
        }
        let mut octets = [0; 4];
        for (target, label) in octets.iter_mut().zip(body.iter().rev()) {
            if label.is_empty()
                || label.len() > 1 && label[0] == b'0'
                || !label.iter().all(u8::is_ascii_digit)
            {
                return None;
            }
            *target = std::str::from_utf8(label).ok()?.parse().ok()?;
        }
        return Some(Ipv4Addr::from(octets).into());
    }
    // RFC 3596 §2.5: IPv6 reverse names encode 32 nibbles; extra labels are accepted here.
    if !kind.eq_ignore_ascii_case(b"ip6") || !(32..=35).contains(&body.len()) {
        return None;
    }
    // RFC 3596 §2.5: IPv6 reverse names use hexadecimal nibbles in reverse order.
    let mut octets = [0; 16];
    for (i, label) in body.iter().rev().take(32).enumerate() {
        if label.len() != 1 {
            return None;
        }
        let nibble = (label[0] as char).to_digit(16)? as u8;
        octets[i / 2] |= nibble << (4 * (1 - i % 2));
    }
    let ip = Ipv6Addr::from(octets);
    Some(ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4))
}

#[cfg(test)]
mod tests {
    use super::{address, is_reverse};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_reverse_ipv4_addresses() {
        assert_eq!(
            address(&[b"4", b"3", b"2", b"1", b"in-addr", b"arpa"]),
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        );
        assert_eq!(
            address(&[b"04", b"3", b"2", b"1", b"in-addr", b"arpa"]),
            None
        );
        assert_eq!(address(&[b"4", b"3", b"2", b"in-addr", b"arpa"]), None);
    }

    #[test]
    fn reverse_detection_requires_a_label_before_the_arpa_suffix() {
        assert!(is_reverse(&[b"svc", b"0", b"10", b"in-addr", b"arpa"]));
        assert!(is_reverse(&[b"1", b"ip6", b"arpa"]));
        assert!(!is_reverse(&[b"in-addr", b"arpa"]));
        assert!(!is_reverse(&[b"ip6", b"arpa"]));
    }

    #[test]
    fn parses_reverse_ipv6_nibbles() {
        let mut labels: Vec<&[u8]> = vec![b"0"; 32];
        labels[0] = b"1";
        labels.extend([&b"ip6"[..], &b"arpa"[..]]);
        assert_eq!(address(&labels), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        labels.insert(0, b"ignored");
        assert_eq!(address(&labels), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        labels.remove(0);
        labels[1] = b"gg";
        assert_eq!(address(&labels), None);
    }

    #[test]
    fn ipv4_mapped_reverse_uses_ipv4_address() {
        let mut labels: Vec<&[u8]> = vec![b"0"; 32];
        labels[0] = b"1";
        labels[2] = b"2";
        labels[7] = b"c";
        labels[8..12].fill(b"f");
        labels.extend([&b"ip6"[..], &b"arpa"[..]]);
        assert_eq!(
            address(&labels),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
    }
}
