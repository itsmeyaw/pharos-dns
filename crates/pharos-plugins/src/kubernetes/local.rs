//! Snapshot the addresses used for Kubernetes NS discovery.

use std::net::IpAddr;

pub(super) fn snapshot(hosts: &[String]) -> Vec<IpAddr> {
    select(hosts, || {
        nix::ifaddrs::getifaddrs()
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                let address = entry.address?;
                address
                    .as_sockaddr_in()
                    .map(|ip| IpAddr::V4(ip.ip()))
                    .or_else(|| address.as_sockaddr_in6().map(|ip| IpAddr::V6(ip.ip())))
            })
            .collect()
    })
}

pub(super) fn select(hosts: &[String], interfaces: impl FnOnce() -> Vec<IpAddr>) -> Vec<IpAddr> {
    let normalize = |ip: IpAddr| {
        let ip = match ip {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
            ip => ip,
        };
        (!ip.is_loopback()).then_some(ip)
    };
    if hosts.first().is_none_or(String::is_empty) {
        return interfaces().into_iter().filter_map(normalize).collect();
    }
    hosts
        .iter()
        .filter_map(|host| {
            let (address, prefix) = host.split_once('/')?;
            if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let ip: IpAddr = address.parse().ok()?;
            let bits: u8 = prefix.parse().ok()?;
            if bits > if ip.is_ipv4() { 32 } else { 128 } {
                return None;
            }
            normalize(ip)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::select;
    use std::{cell::Cell, net::IpAddr};

    #[test]
    fn wildcard_uses_one_interface_snapshot_and_filters_loopback() {
        let calls = Cell::new(0);
        let addresses = select(&[String::new()], || {
            calls.set(calls.get() + 1);
            ["127.0.0.1", "192.0.2.1", "::1", "2001:db8::1", "192.0.2.1"]
                .into_iter()
                .map(|value| value.parse().unwrap())
                .collect()
        });
        assert_eq!(calls.get(), 1);
        assert_eq!(
            addresses,
            ["192.0.2.1", "2001:db8::1", "192.0.2.1"].map(|value| value.parse::<IpAddr>().unwrap())
        );
    }

    // CoreDNS bind emits literal IPs; boundIPs only accepts CIDR-form hosts.
    #[test]
    fn explicit_hosts_match_coredns_cidr_parsing() {
        let hosts = [
            "192.0.2.1",
            "127.0.0.1/8",
            "192.0.2.4/24",
            "2001:db8::1/64",
            "10.0.0.1/33",
            "10.0.0.1/+1",
        ]
        .map(str::to_owned);
        let addresses = select(&hosts, || {
            panic!("explicit hosts must not enumerate interfaces")
        });
        assert_eq!(
            addresses,
            ["192.0.2.4", "2001:db8::1"].map(|value| value.parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn plugin_instances_keep_independent_address_snapshots() {
        fn plugin(address: &str) -> super::super::Kubernetes {
            let blocks =
                pharos_corefile::parse("Corefile", ".:53 {\n kubernetes cluster.local\n}").unwrap();
            let tokens = &blocks[0].directives["kubernetes"];
            let config = super::super::setup::parse(
                &mut pharos_corefile::Cursor::new("Corefile", tokens),
                &["."],
            )
            .unwrap();
            super::super::Kubernetes::with_listen_addresses(config, &[address.to_owned()]).unwrap()
        }
        let original = plugin("192.0.2.1/24");
        let reloaded = plugin("192.0.2.2/24");
        assert_eq!(original.local_ips, ["192.0.2.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(reloaded.local_ips, ["192.0.2.2".parse::<IpAddr>().unwrap()]);
    }
}
