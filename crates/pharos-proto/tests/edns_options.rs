#![forbid(unsafe_code)]

use pharos_proto::{ClientSubnet, EdnsOption, EdnsOptions};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::alloc::System;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn parse_and_iteration_do_not_allocate() {
    const CHILD: &str = "PHAROS_EDNS_ALLOCATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "parse_and_iteration_do_not_allocate",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let wire = [0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2, 0, 15, 0, 3, 0, 1, b'x'];
    let region = Region::new(GLOBAL);
    let options = EdnsOptions::parse(&wire).unwrap();
    for option in options {
        std::hint::black_box(option);
    }
    let stats = region.change();
    assert_eq!(stats.allocations, 0);
    assert_eq!(stats.reallocations, 0);
}

#[test]
fn parses_borrowed_options_and_formats_like_miekg() {
    let wire = [
        0, 3, 0, 2, 0xab, 0xcd, // NSID
        0, 10, 0, 2, 0x12, 0x34, // cookie
        0, 15, 0, 5, 0, 15, b'b', b'a', b'd', // EDE
        0, 12, 0, 2, 0, 0xff, // padding
        0xfd, 0xe9, 0, 2, 0x48, 0x52, // local option
    ];
    let options = EdnsOptions::parse(&wire).unwrap();
    assert_eq!(options.as_bytes().as_ptr(), wire.as_ptr());
    let items: Vec<_> = options.iter().collect();
    assert_eq!(items[0], EdnsOption::Nsid(&wire[4..6]));
    assert_eq!(items[0].to_string(), "abcd");
    assert_eq!(items[1].to_string(), "1234");
    assert_eq!(items[2].to_string(), "15 (Blocked): (bad)");
    assert_eq!(items[3].to_string(), "00FF");
    assert_eq!(items[4].to_string(), "65001:0x4852");
    let mut encoded = Vec::new();
    for option in items {
        option.encode(&mut encoded).unwrap();
    }
    assert_eq!(encoded, wire);
}

#[test]
fn subnet_miekg_fixtures_and_prefix_masking() {
    for (ip, prefix, expected) in [
        (
            IpAddr::V4(Ipv4Addr::new(0xde, 0xad, 0xbe, 0xef)),
            32,
            "222.173.190.239/32/0",
        ),
        (
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            32,
            "192.0.2.1/32/0",
        ),
        (
            IpAddr::V6("2001:db8::68".parse::<Ipv6Addr>().unwrap()),
            128,
            "[2001:db8::68]/128/0",
        ),
        (
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 255)),
            25,
            "192.0.2.128/25/0",
        ),
    ] {
        let subnet = ClientSubnet::new(ip, prefix, 0).unwrap();
        let mut wire = Vec::new();
        EdnsOption::ClientSubnet(subnet).encode(&mut wire).unwrap();
        let option = EdnsOptions::parse(&wire).unwrap().iter().next().unwrap();
        assert_eq!(option.to_string(), expected);
        assert_eq!(option, EdnsOption::ClientSubnet(subnet));
    }
}

#[test]
fn keepalive_empty_and_timeout_roundtrip() {
    for (wire, expected, display) in [
        (
            &[0, 11, 0, 0][..],
            None,
            "use tcp keep-alive, timeout omitted",
        ),
        (
            &[0, 11, 0, 2, 0, 1][..],
            Some(1),
            "use tcp keep-alive, timeout 100ms",
        ),
        (
            &[0, 11, 0, 2, 0, 0][..],
            Some(0),
            "use tcp keep-alive, timeout omitted",
        ),
    ] {
        let option = EdnsOptions::parse(wire).unwrap().iter().next().unwrap();
        assert_eq!(option, EdnsOption::TcpKeepalive(expected));
        assert_eq!(option.to_string(), display);
        let mut encoded = Vec::new();
        option.encode(&mut encoded).unwrap();
        assert_eq!(encoded, wire);
    }
}

#[test]
fn rejects_malformed_framing_and_structured_payloads() {
    for wire in [
        &[0][..],
        &[0, 3, 0][..],
        &[0, 3, 0, 2, 1][..],
        &[0, 15, 0, 1, 0][..],
        &[0, 11, 0, 3, 0, 1, 3][..],
        &[0, 8, 0, 3, 0, 1, 0][..],
        &[0, 8, 0, 4, 0, 1, 33, 0][..],
        &[0, 8, 0, 5, 0, 1, 16, 0, 192][..],
        &[0, 8, 0, 5, 0, 1, 1, 0, 0xff][..],
        &[0, 8, 0, 4, 0, 3, 0, 0][..],
    ] {
        assert!(EdnsOptions::parse(wire).is_err(), "accepted {wire:?}");
    }
    assert!(ClientSubnet::new(Ipv4Addr::LOCALHOST.into(), 33, 0).is_err());
    assert!(ClientSubnet::new(Ipv6Addr::LOCALHOST.into(), 0, 129).is_err());
}

#[test]
fn builder_rejects_oversized_data_without_modifying_output() {
    let data = vec![0; 65536];
    let mut output = vec![42];
    assert!(EdnsOption::Nsid(&data).encode(&mut output).is_err());
    assert!(
        EdnsOption::ExtendedError {
            info_code: 1,
            extra_text: &data
        }
        .encode(&mut output)
        .is_err()
    );
    assert!(
        EdnsOption::Unknown {
            code: 11,
            data: &[1]
        }
        .encode(&mut output)
        .is_err()
    );
    assert_eq!(output, [42]);
}

#[test]
fn empty_options_and_unknown_ede_codes() {
    assert_eq!(EdnsOptions::parse(&[]).unwrap().iter().count(), 0);
    let wire = [0, 15, 0, 2, 0xff, 0xff];
    assert_eq!(
        EdnsOptions::parse(&wire)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .to_string(),
        "65535: ()"
    );
}

#[test]
fn zero_prefix_and_family_zero_roundtrip() {
    let cases: &[&[u8]] = &[
        &[0, 8, 0, 4, 0, 0, 0, 0],
        &[0, 8, 0, 4, 0, 1, 0, 32],
        &[0, 8, 0, 4, 0, 2, 0, 128],
    ];
    for wire in cases {
        let options = EdnsOptions::parse(wire).unwrap();
        let mut output = Vec::new();
        for option in options {
            option.encode(&mut output).unwrap();
        }
        assert_eq!(&output, wire);
    }
}

#[test]
fn subnet_display_uses_miekg_ipv4_mapped_format() {
    let subnet = ClientSubnet::new("::ffff:192.0.2.1".parse().unwrap(), 128, 0).unwrap();
    assert_eq!(
        EdnsOption::ClientSubnet(subnet).to_string(),
        "192.0.2.1/128/0"
    );
}
