use std::net::IpAddr;

pub(crate) fn contains(network: IpAddr, prefix: u8, client: IpAddr) -> bool {
    // RFC 4291 §2.5.5.2: Compare IPv4 clients in the IPv4-mapped IPv6 address space.
    let client = match (network, client) {
        (IpAddr::V6(_), IpAddr::V4(ip)) => IpAddr::V6(ip.to_ipv6_mapped()),
        (IpAddr::V4(_), IpAddr::V6(ip)) => ip.to_ipv4_mapped().map_or(client, IpAddr::V4),
        _ => client,
    };
    // RFC 4632 §3.1 and RFC 4291 §2.3: CIDR prefixes identify leading address bits.
    // RFC 4632 §3.1 and RFC 4291 §2.5: IPv6 unicast prefixes can use arbitrary bit lengths.
    match (network, client) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
            u32::from(net) & mask == u32::from(ip) & mask
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
            u128::from(net) & mask == u128::from(ip) & mask
        }
        _ => false,
    }
}
