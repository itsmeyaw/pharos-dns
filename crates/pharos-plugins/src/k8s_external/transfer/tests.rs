use super::super::External;
use super::*;
use crate::transfer::{TransferRequest, Transferer};
use pharos_corefile::{Cursor, parse};
use pharos_proto::{Class, Message, Name, NameRef, Rdata, Type};
use pharos_server::Protocol;

fn plugin() -> External {
    let blocks = parse("Corefile", ".:53 {\n k8s_external example.com\n}").unwrap();
    let config = super::super::setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
        &["."],
    )
    .unwrap();
    let mut external = External::new(config).unwrap();
    let blocks = parse("Corefile", ".:53 {\n kubernetes cluster.local\n}").unwrap();
    let config = crate::kubernetes::setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["kubernetes"]),
        &["."],
    )
    .unwrap();
    external.bind_kubernetes(&crate::kubernetes::Kubernetes::new(config).unwrap());
    external
}

fn request(zone: &Name, qtype: Type, serial: u32, protocol: Protocol) -> TransferRequest<'_> {
    TransferRequest {
        zone: NameRef::parse(zone.as_wire(), 0).unwrap(),
        serial,
        id: 42,
        flags: 0x0100,
        protocol,
        qtype,
        qclass: Class::IN,
    }
}

#[test]
fn transfer_requires_an_exact_configured_zone() {
    let plugin = plugin();
    for name in ["child.example.com.", "elsewhere."] {
        let zone: Name = name.parse().unwrap();
        assert!(
            plugin
                .transfer(request(&zone, Type::AXFR, 0, Protocol::Tcp))
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn transfer_clears_cd_and_rejects_non_in_class() {
    let plugin = plugin();
    let zone: Name = "example.com.".parse().unwrap();
    let mut query = request(&zone, Type::AXFR, 0, Protocol::Tcp);
    query.flags |= 0x0010;
    let mut stream = plugin.transfer(query).unwrap().unwrap();
    let mut wire = Vec::new();
    assert!(stream.next(&mut wire).unwrap());
    assert_eq!(Message::parse(&wire).unwrap().flags() & 0x0010, 0);

    query.qclass = Class::CH;
    assert!(plugin.transfer(query).unwrap().is_none());
}

#[test]
fn axfr_has_matching_soa_boundaries_and_apex_nameserver() {
    let zone: Name = "example.com.".parse().unwrap();
    let mut stream = plugin()
        .transfer(request(&zone, Type::AXFR, 0, Protocol::Tcp))
        .unwrap()
        .unwrap();
    let mut wire = Vec::new();
    let mut records = Vec::new();
    while stream.next(&mut wire).unwrap() {
        let message = Message::parse(&wire).unwrap();
        assert_eq!(message.id(), 42);
        for record in message.answers() {
            match record.data().unwrap() {
                Rdata::Soa {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                } => {
                    assert_eq!(record.ttl, 5);
                    assert_eq!(mname.to_string(), "ns1.dns.example.com.");
                    assert_eq!(rname.to_string(), "hostmaster.dns.example.com.");
                    assert_eq!(
                        (serial, refresh, retry, expire, minimum),
                        (0, 7200, 1800, 86400, 5)
                    );
                }
                Rdata::Ns(target) => assert_eq!(target.to_string(), "ns1.dns.example.com."),
                _ => {}
            }
            records.push(record.rtype);
        }
    }
    assert_eq!(records.first(), Some(&Type::SOA));
    assert_eq!(records.last(), Some(&Type::SOA));
    assert_eq!(records.iter().filter(|&&kind| kind == Type::SOA).count(), 2);
    assert_eq!(records.iter().filter(|&&kind| kind == Type::NS).count(), 1);
}

#[test]
fn ixfr_with_newer_serial_returns_only_current_soa() {
    let zone: Name = "example.com.".parse().unwrap();
    let mut stream = plugin()
        .transfer(request(&zone, Type::IXFR, 1, Protocol::Tcp))
        .unwrap()
        .unwrap();
    let mut wire = Vec::new();
    assert!(stream.next(&mut wire).unwrap());
    let message = Message::parse(&wire).unwrap();
    assert_eq!(message.answer_count(), 1);
    assert_eq!(message.answers().next().unwrap().rtype, Type::SOA);
    assert!(!stream.next(&mut wire).unwrap());
}

#[test]
fn ixfr_serials_use_rfc1982_half_space_ordering() {
    assert!(serial_at_least(0, u32::MAX));
    assert!(serial_at_least(u32::MAX, u32::MAX));
    assert!(!serial_at_least(u32::MAX, 0));
    assert!(!serial_at_least(1 << 31, 0));
    let zone: Name = "example.com.".parse().unwrap();
    assert!(soa_only(
        request(&zone, Type::IXFR, 1, Protocol::Tcp),
        u32::MAX
    ));
    assert!(!soa_only(
        request(&zone, Type::IXFR, u32::MAX, Protocol::Tcp),
        1
    ));
}

#[test]
fn zero_is_a_valid_ixfr_serial() {
    let zone: Name = "example.com.".parse().unwrap();
    let request = request(&zone, Type::IXFR, 0, Protocol::Tcp);
    assert!(soa_only(request, 0));
    assert!(!soa_only(request, 1));
}

#[test]
fn udp_ixfr_returns_only_current_soa() {
    let zone: Name = "example.com.".parse().unwrap();
    let mut stream = plugin()
        .transfer(request(&zone, Type::IXFR, 0, Protocol::Udp))
        .unwrap()
        .unwrap();
    let mut wire = Vec::new();
    assert!(stream.next(&mut wire).unwrap());
    let message = Message::parse(&wire).unwrap();
    assert_eq!(message.answer_count(), 1);
    assert_eq!(message.answers().next().unwrap().rtype, Type::SOA);
    assert!(!stream.next(&mut wire).unwrap());
}

#[test]
fn soa_only_ixfr_does_not_scan_services_for_scratch() {
    let store = pharos_kubernetes::store::Store::default();
    let zone: Name = "example.com.".parse().unwrap();
    for (serial, protocol) in [
        (5, Protocol::Tcp),
        (6, Protocol::Tcp),
        (0, Protocol::Udp),
        (1, Protocol::Udp),
    ] {
        store.with_read(|index| {
            let services =
                std::iter::from_fn(|| -> Option<&Service> { panic!("unexpected service scan") });
            assert_eq!(
                scratch_capacity(
                    index,
                    services,
                    request(&zone, Type::IXFR, serial, protocol),
                    5,
                    true
                )
                .unwrap(),
                0
            );
        });
    }
    let service = fixture_service();
    store.with_read(|index| {
        assert_eq!(
            scratch_capacity(
                index,
                std::iter::once(&service),
                request(&zone, Type::AXFR, 0, Protocol::Tcp),
                5,
                false
            )
            .unwrap(),
            2
        );
    });
}

fn fixture_service() -> pharos_kubernetes::object::Service {
    use pharos_kubernetes::object::{Port, Service};
    Service {
        version: "1".into(),
        name: "web".into(),
        namespace: "hidden".into(),
        cluster_ips: vec!["10.0.0.1".into()],
        service_type: "LoadBalancer".into(),
        external_name: String::new(),
        external_ips: vec!["192.0.2.1".into(), "lb.example.net".into()],
        ports: vec![
            Port {
                name: "http".into(),
                protocol: "TCP".into(),
                port: 80,
            },
            Port {
                name: "https".into(),
                protocol: "TCP".into(),
                port: 443,
            },
        ],
        tolerate_unready_endpoints: false,
    }
}

fn fixture_snapshot<'a>(plugin: &'a External, zone: &'a Name) -> Snapshot<'a> {
    Snapshot {
        request: request(zone, Type::AXFR, 0, Protocol::Tcp),
        ns: NameRef::parse(plugin.zones[0].ns.as_ref().unwrap().as_wire(), 0).unwrap(),
        host: NameRef::parse(plugin.zones[0].host.as_ref().unwrap().as_wire(), 0).unwrap(),
        ttl: plugin.config.ttl,
        service_ttl: plugin.kubernetes.as_ref().unwrap().ttl(),
        authoritative: true,
        bytes: Some(Vec::new()),
        size: 0,
    }
}

#[test]
fn external_service_preserves_coredns_ttls_and_duplicates() {
    let mut plugin = plugin();
    let blocks = parse(
        "Corefile",
        ".:53 {\n kubernetes cluster.local {\n ttl 37\n }\n}",
    )
    .unwrap();
    let config = crate::kubernetes::setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["kubernetes"]),
        &["."],
    )
    .unwrap();
    plugin.bind_kubernetes(&crate::kubernetes::Kubernetes::new(config).unwrap());
    let zone: Name = "example.com.".parse().unwrap();
    let base: Name = "web.hidden.example.com.".parse().unwrap();
    let mut snapshot = fixture_snapshot(&plugin, &zone);
    non_headless(
        &mut snapshot,
        &fixture_service(),
        NameRef::parse(base.as_wire(), 0).unwrap(),
        &mut HashMap::with_capacity(2),
    )
    .unwrap();
    let mut stream = stream_snapshot(snapshot.bytes.unwrap());
    let mut wire = Vec::new();
    let mut a_count = 0;
    let mut cname_count = 0;
    let mut bare_srv = 0;
    let mut named_srv = 0;
    while stream.next(&mut wire).unwrap() {
        let message = Message::parse(&wire).unwrap();
        for rr in message.answers() {
            if rr.name.to_string() == "web.hidden.example.com." {
                match rr.data().unwrap() {
                    Rdata::A(_) => {
                        assert_eq!(rr.ttl, 5);
                        a_count += 1;
                    }
                    Rdata::Cname(_) => {
                        assert_eq!(rr.ttl, 37);
                        cname_count += 1;
                    }
                    Rdata::Srv { port, weight, .. } => {
                        assert_eq!((rr.ttl, port, weight), (37, 80, 100));
                        bare_srv += 1;
                    }
                    _ => {}
                }
            } else if rr.rtype == Type::SRV {
                assert_eq!(rr.ttl, 37);
                named_srv += 1;
            }
        }
    }
    assert_eq!((a_count, cname_count, bare_srv, named_srv), (1, 1, 1, 2));
}

#[test]
fn non_headless_many_ports_and_ips_preserve_name_seen_order() {
    use pharos_kubernetes::object::Port;
    let plugin = plugin();
    let zone: Name = "example.com.".parse().unwrap();
    let base: Name = "web.hidden.example.com.".parse().unwrap();
    let mut service = fixture_service();
    service.external_ips = vec![
        "192.0.2.1".into(),
        "lb.example.net".into(),
        "192.0.2.2".into(),
    ];
    service.ports = vec![Port {
        name: "port0".into(),
        protocol: "TCP".into(),
        port: -1,
    }];
    service.ports.extend((0..200).map(|i| Port {
        name: if i % 2 == 0 {
            format!("port{}", i / 2)
        } else {
            format!("PORT{}", i / 2)
        },
        protocol: if i % 2 == 0 { "TCP" } else { "tcp" }.into(),
        port: 1000 + i,
    }));
    let mut snapshot = fixture_snapshot(&plugin, &zone);
    let mut seen = HashMap::with_capacity(service.ports.len());
    let capacity = seen.capacity();
    non_headless(
        &mut snapshot,
        &service,
        NameRef::parse(base.as_wire(), 0).unwrap(),
        &mut seen,
    )
    .unwrap();
    assert_eq!(seen.capacity(), capacity);
    let first = snapshot.bytes.clone().unwrap();
    snapshot.bytes.as_mut().unwrap().clear();
    snapshot.size = 0;
    non_headless(
        &mut snapshot,
        &service,
        NameRef::parse(base.as_wire(), 0).unwrap(),
        &mut seen,
    )
    .unwrap();
    assert_eq!(seen.capacity(), capacity);
    assert_eq!(snapshot.bytes.as_ref().unwrap(), &first);
    let mut stream = stream_snapshot(snapshot.bytes.unwrap());
    let mut wire = Vec::new();
    let mut actual = Vec::new();
    while stream.next(&mut wire).unwrap() {
        for rr in Message::parse(&wire).unwrap().answers() {
            actual.push(match rr.data().unwrap() {
                Rdata::A(ip) => format!("{} A {ip}", rr.name),
                Rdata::Cname(target) => format!("{} CNAME {target}", rr.name),
                Rdata::Srv {
                    weight,
                    port,
                    target,
                    ..
                } => {
                    format!("{} SRV {weight} {port} {target}", rr.name)
                }
                _ => panic!("unexpected record"),
            });
        }
    }
    let mut expected = Vec::new();
    for (ip_index, ip) in service.external_ips.iter().enumerate() {
        if ip_index == 1 {
            expected.push(format!("{base} CNAME lb.example.net."));
        } else {
            expected.push(format!("{base} A {ip}"));
        }
        for (port_index, port) in service.ports.iter().enumerate() {
            if ip_index == 0 && port_index == 1 {
                expected.push(format!("{base} SRV 100 1000 {base}"));
            }
            if ip_index == 0 && port_index > 0 && port_index % 2 == 1 {
                expected.push(format!(
                    "_{}._tcp.{base} SRV 100 {} {base}",
                    port.name, port.port
                ));
            }
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn axfr_hostname_emits_cname_without_target_addresses() {
    let plugin = plugin();
    let zone: Name = "example.com.".parse().unwrap();
    let base: Name = "web.hidden.example.com.".parse().unwrap();
    let mut service = fixture_service();
    service.external_ips = vec!["lb.example.net".into()];
    let mut snapshot = fixture_snapshot(&plugin, &zone);
    non_headless(
        &mut snapshot,
        &service,
        NameRef::parse(base.as_wire(), 0).unwrap(),
        &mut HashMap::with_capacity(2),
    )
    .unwrap();
    let mut stream = stream_snapshot(snapshot.bytes.unwrap());
    let mut wire = Vec::new();
    let mut cnames = 0;
    while stream.next(&mut wire).unwrap() {
        for rr in Message::parse(&wire).unwrap().answers() {
            assert!(
                !(rr.name.to_string() == "lb.example.net."
                    && matches!(rr.rtype, Type::A | Type::AAAA))
            );
            if let Rdata::Cname(target) = rr.data().unwrap() {
                assert_eq!(rr.name.to_string(), "web.hidden.example.com.");
                assert_eq!(target.to_string(), "lb.example.net.");
                cnames += 1;
            }
        }
    }
    assert_eq!(cnames, 1);
}

#[test]
fn unnamed_port_does_not_create_transfer_srv_records() {
    use pharos_kubernetes::object::Port;
    let plugin = plugin();
    let zone: Name = "example.com.".parse().unwrap();
    let base: Name = "web.hidden.example.com.".parse().unwrap();
    let mut service = fixture_service();
    service.external_ips = vec!["192.0.2.1".into()];
    service.ports = vec![Port {
        name: String::new(),
        protocol: "TCP".into(),
        port: 80,
    }];
    let mut snapshot = fixture_snapshot(&plugin, &zone);
    non_headless(
        &mut snapshot,
        &service,
        NameRef::parse(base.as_wire(), 0).unwrap(),
        &mut HashMap::with_capacity(1),
    )
    .unwrap();
    let mut stream = stream_snapshot(snapshot.bytes.unwrap());
    let mut wire = Vec::new();
    let mut records = Vec::new();
    while stream.next(&mut wire).unwrap() {
        records.extend(Message::parse(&wire).unwrap().answers().map(|rr| rr.rtype));
    }
    assert_eq!(records, [Type::A]);
}

#[test]
fn transfer_hostname_fqdn_handles_escaped_final_dot() {
    let mut wire = [0; 255];
    assert_eq!(
        hostname(r"example\.", 0, &mut wire).unwrap().to_string(),
        r"example\.."
    );
    assert_eq!(
        hostname(r"example\\.", 0, &mut wire).unwrap().to_string(),
        r"example\\."
    );
}

#[test]
fn headless_transfers_weighted_and_repeated_srv_records() {
    use pharos_kubernetes::object::{EndpointAddress, Endpoints, Port};
    let plugin = plugin();
    let endpoints = Endpoints {
        version: "1".into(),
        name: "slice".into(),
        namespace: "hidden".into(),
        service_name: "web".into(),
        addresses: ["192.0.2.1", "192.0.2.2"]
            .into_iter()
            .enumerate()
            .map(|(i, ip)| EndpointAddress {
                ip: ip.into(),
                hostname: format!("node{i}"),
                target_ref_name: String::new().into(),
                ready: true,
            })
            .collect(),
        ports: vec![Port {
            name: "http".into(),
            protocol: "TCP".into(),
            port: 80,
        }],
        zones: None,
    };
    let zone: Name = "example.com.".parse().unwrap();
    let base: Name = "web.hidden.example.com.".parse().unwrap();
    let service = fixture_service();
    let mut snapshot = fixture_snapshot(&plugin, &zone);
    headless(
        &mut snapshot,
        || {
            endpoints
                .addresses
                .iter()
                .flat_map(|address| endpoints.ports.iter().map(move |port| (address, port)))
        },
        NameRef::parse(base.as_wire(), 0).unwrap(),
        (&service, NameRef::parse(zone.as_wire(), 0).unwrap()),
        false,
        &mut HashMap::with_capacity(8),
    )
    .unwrap();
    let mut stream = stream_snapshot(snapshot.bytes.unwrap());
    let mut wire = Vec::new();
    let mut base = Vec::new();
    let mut endpoint = Vec::new();
    let mut named = Vec::new();
    while stream.next(&mut wire).unwrap() {
        let message = Message::parse(&wire).unwrap();
        for rr in message.answers().filter(|rr| rr.rtype == Type::SRV) {
            let Rdata::Srv {
                weight,
                port,
                target,
                ..
            } = rr.data().unwrap()
            else {
                panic!("SRV")
            };
            let value = (weight, port, target.to_string());
            match rr.name.to_string().as_str() {
                "web.hidden.example.com." => base.push(value),
                "_http._tcp.web.hidden.example.com." => named.push(value),
                _ => endpoint.push(value),
            }
        }
    }
    assert_eq!(base.len(), 2);
    assert!(base.iter().all(|v| v.0 == 50));
    assert_eq!(endpoint.len(), 2);
    assert!(endpoint.iter().all(|v| v.0 == 100));
    assert_eq!(named.len(), 2);
    assert!(named.iter().all(|v| v.0 == 50));
}

#[test]
fn headless_base_address_survives_invalid_endpoint_hostname() {
    use pharos_kubernetes::object::{EndpointAddress, Port};
    let plugin = plugin();
    let zone: Name = "example.com.".parse().unwrap();
    let base: Name = "web.hidden.example.com.".parse().unwrap();
    let service = fixture_service();
    let addresses: Vec<_> = ["a".repeat(64), "node".to_owned()]
        .into_iter()
        .map(|hostname| EndpointAddress {
            ip: "192.0.2.1".into(),
            hostname,
            target_ref_name: String::new().into(),
            ready: true,
        })
        .collect();
    let port = Port {
        name: "http".into(),
        protocol: "TCP".into(),
        port: 80,
    };
    for count in [1, 2] {
        let mut snapshot = fixture_snapshot(&plugin, &zone);
        headless(
            &mut snapshot,
            || addresses[..count].iter().map(|address| (address, &port)),
            NameRef::parse(base.as_wire(), 0).unwrap(),
            (&service, NameRef::parse(zone.as_wire(), 0).unwrap()),
            false,
            &mut HashMap::with_capacity(8),
        )
        .unwrap();
        let mut stream = stream_snapshot(snapshot.bytes.unwrap());
        let mut wire = Vec::new();
        let mut found = 0;
        while stream.next(&mut wire).unwrap() {
            for rr in Message::parse(&wire).unwrap().answers() {
                if rr.name.to_string() == "web.hidden.example.com."
                    && matches!(rr.data().unwrap(), Rdata::A(_))
                {
                    found += 1;
                }
            }
        }
        assert_eq!(found, 1, "{count} endpoints");
    }
}

#[test]
fn headless_many_repeated_endpoints_and_ports_preserve_order() {
    use pharos_kubernetes::object::{EndpointAddress, Port};
    let plugin = plugin();
    let zone: Name = "example.com.".parse().unwrap();
    let base: Name = "web.hidden.example.com.".parse().unwrap();
    let service = fixture_service();
    let addresses: Vec<_> = (0..48)
        .map(|i| EndpointAddress {
            ip: format!("192.0.2.{}", i % 24 + 1),
            hostname: format!("node{}", i % 24),
            target_ref_name: String::new().into(),
            ready: true,
        })
        .collect();
    let ports: Vec<_> = [("http", 80), ("HTTP", 80), ("http", 81), ("metrics", 90)]
        .into_iter()
        .map(|(name, port)| Port {
            name: name.into(),
            protocol: "TCP".into(),
            port,
        })
        .collect();
    let mut snapshot = fixture_snapshot(&plugin, &zone);
    let mut seen = HashMap::with_capacity(addresses.len() * ports.len() * 4);
    let capacity = seen.capacity();
    headless(
        &mut snapshot,
        || {
            addresses
                .iter()
                .flat_map(|a| ports.iter().map(move |p| (a, p)))
        },
        NameRef::parse(base.as_wire(), 0).unwrap(),
        (&service, NameRef::parse(zone.as_wire(), 0).unwrap()),
        false,
        &mut seen,
    )
    .unwrap();
    assert_eq!(seen.capacity(), capacity);
    let mut stream = stream_snapshot(snapshot.bytes.unwrap());
    let mut wire = Vec::new();
    let mut actual = Vec::new();
    while stream.next(&mut wire).unwrap() {
        for rr in Message::parse(&wire).unwrap().answers() {
            let owner = rr.name.to_string();
            let value = match rr.data().unwrap() {
                Rdata::A(ip) => format!("{owner} A {ip}"),
                Rdata::Srv {
                    weight,
                    port,
                    target,
                    ..
                } => {
                    format!("{owner} SRV {weight} {port} {target}")
                }
                _ => panic!("unexpected record"),
            };
            actual.push(value);
        }
    }
    let mut expected = Vec::new();
    for i in 0..48 {
        let endpoint = format!("node{}.web.hidden.example.com.", i % 24);
        let ip = format!("192.0.2.{}", i % 24 + 1);
        for (p, port) in ports.iter().enumerate() {
            if i < 24 && p == 0 {
                expected.push(format!("{base} A {ip}"));
            }
            if i < 24 && p != 1 {
                expected.push(format!("{base} SRV 1 {} {endpoint}", port.port));
            }
            if i < 24 && p == 0 {
                expected.push(format!("{endpoint} A {ip}"));
            }
            if i < 24 && p != 1 {
                expected.push(format!("{endpoint} SRV 100 {} {endpoint}", port.port));
            }
            if i < 24 && p != 1 {
                let name = port.name.to_ascii_lowercase();
                let weight = if p == 3 { 2 } else { 1 };
                expected.push(format!(
                    "_{name}._tcp.{base} SRV {weight} {} {endpoint}",
                    port.port
                ));
            }
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn headless_dedup_uses_host_text_and_resets_between_services() {
    use pharos_kubernetes::object::{EndpointAddress, Port};
    let plugin = plugin();
    let zone: Name = "example.com.".parse().unwrap();
    let addresses: Vec<_> = ["2001:db8::1", "2001:0db8::1", "2001:db8::1"]
        .into_iter()
        .map(|ip| EndpointAddress {
            ip: ip.into(),
            hostname: "node".into(),
            target_ref_name: String::new().into(),
            ready: true,
        })
        .collect();
    let port = Port {
        name: "http".into(),
        protocol: "TCP".into(),
        port: 80,
    };
    let mut api = fixture_service();
    api.name = "api".into();
    let services = [fixture_service(), api];
    let mut snapshot = fixture_snapshot(&plugin, &zone);
    let mut seen = HashMap::with_capacity(12);
    for (name, service) in ["web.hidden.example.com.", "api.hidden.example.com."]
        .into_iter()
        .zip(&services)
    {
        let base: Name = name.parse().unwrap();
        headless(
            &mut snapshot,
            || addresses.iter().map(|address| (address, &port)),
            NameRef::parse(base.as_wire(), 0).unwrap(),
            (service, NameRef::parse(zone.as_wire(), 0).unwrap()),
            false,
            &mut seen,
        )
        .unwrap();
    }
    let mut stream = stream_snapshot(snapshot.bytes.unwrap());
    let mut wire = Vec::new();
    let mut addresses_per_service = [0, 0];
    while stream.next(&mut wire).unwrap() {
        for rr in Message::parse(&wire).unwrap().answers() {
            if rr.rtype == Type::AAAA {
                match rr.name.to_string().as_str() {
                    "web.hidden.example.com." => addresses_per_service[0] += 1,
                    "api.hidden.example.com." => addresses_per_service[1] += 1,
                    _ => {}
                }
            }
        }
    }
    assert_eq!(addresses_per_service, [2, 2]);
}

#[test]
fn headless_group_deduplicates_hostname_srv_targets() {
    use pharos_kubernetes::object::{EndpointAddress, Port};
    let plugin = plugin();
    let zone: Name = "example.com.".parse().unwrap();
    let base: Name = "web.hidden.example.com.".parse().unwrap();
    let service = fixture_service();
    let addresses: Vec<_> = ["node0", "node1"]
        .into_iter()
        .map(|hostname| EndpointAddress {
            ip: "target.example.net".into(),
            hostname: hostname.into(),
            target_ref_name: String::new().into(),
            ready: true,
        })
        .collect();
    let port = Port {
        name: "http".into(),
        protocol: "TCP".into(),
        port: 80,
    };
    let mut snapshot = fixture_snapshot(&plugin, &zone);
    headless(
        &mut snapshot,
        || addresses.iter().map(|address| (address, &port)),
        NameRef::parse(base.as_wire(), 0).unwrap(),
        (&service, NameRef::parse(zone.as_wire(), 0).unwrap()),
        false,
        &mut HashMap::with_capacity(8),
    )
    .unwrap();
    let mut stream = stream_snapshot(snapshot.bytes.unwrap());
    let mut wire = Vec::new();
    let mut count = 0;
    while stream.next(&mut wire).unwrap() {
        let message = Message::parse(&wire).unwrap();
        count += message
            .answers()
            .filter(|rr| rr.rtype == Type::SRV && rr.name.to_string() == "web.hidden.example.com.")
            .count();
    }
    assert_eq!(count, 1);
}

#[test]
fn headless_bare_keys_remain_compact() {
    assert!(std::mem::size_of::<Seen<'_>>() <= 96);
}

#[test]
fn headless_bare_targets_resolve_hash_collisions_by_full_name() {
    #[derive(Default)]
    struct ConstantHasher;
    impl Hasher for ConstantHasher {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, _: &[u8]) {}
    }

    let service = fixture_service();
    let zone: Name = "example.com.".parse().unwrap();
    let addresses: Vec<_> = [
        ("192.0.2.1", "node"),
        ("node.web.hidden.example.com.", "alias"),
        ("other.web.hidden.example.com.", "alias"),
        ("no\\100e.web.hidden.example.com", "alias"),
        ("no\\100e.web.hidden.example.com.", "alias"),
        ("192.0.2.2", "node."),
        ("tail\\.", "alias"),
        ("tail\\..", "alias"),
        ("192.0.2.3", "no\\100e"),
    ]
    .into_iter()
    .map(|(ip, hostname)| EndpointAddress {
        ip: ip.into(),
        hostname: hostname.into(),
        target_ref_name: String::new().into(),
        ready: true,
    })
    .collect();
    let mut seen = HashMap::with_hasher(std::hash::BuildHasherDefault::<ConstantHasher>::default());
    for (i, address) in addresses.iter().enumerate() {
        let key = Seen::Bare(
            Target {
                address,
                service: &service,
                zone: NameRef::parse(zone.as_wire(), 0).unwrap(),
                pod_names: false,
            },
            80,
        );
        assert_eq!(
            seen.insert(key, i),
            [
                None,
                Some(0),
                None,
                None,
                Some(3),
                None,
                None,
                Some(6),
                Some(4)
            ][i]
        );
    }
    assert_eq!(seen.len(), 5);
}

#[test]
fn headless_ip_target_uses_coredns_zone_path_presentation() {
    let service = fixture_service();
    for (zone_text, target) in [
        ("a\\.b.example.com.", "node.web.hidden.a\\.b.example.com."),
        ("a/b.example.com.", "node.web.hidden.b.a.example.com."),
        (".", "node.web.hidden."),
    ] {
        let zone: Name = zone_text.parse().unwrap();
        let addresses = [
            EndpointAddress {
                ip: "192.0.2.1".into(),
                hostname: "node".into(),
                target_ref_name: String::new().into(),
                ready: true,
            },
            EndpointAddress {
                ip: target.into(),
                hostname: "alias".into(),
                target_ref_name: String::new().into(),
                ready: true,
            },
        ];
        let mut seen = HashMap::new();
        for (i, address) in addresses.iter().enumerate() {
            let key = Seen::Bare(
                Target {
                    address,
                    service: &service,
                    zone: NameRef::parse(zone.as_wire(), 0).unwrap(),
                    pod_names: false,
                },
                80,
            );
            assert_eq!(
                seen.insert(key, i),
                if i == 0 { None } else { Some(0) },
                "{zone_text}"
            );
        }
    }
}

#[test]
fn headless_bare_srv_compares_full_ip_and_hostname_targets() {
    use pharos_kubernetes::object::{EndpointAddress, Port};
    let plugin = plugin();
    let zone: Name = "example.com.".parse().unwrap();
    let base: Name = "web.hidden.example.com.".parse().unwrap();
    let service = fixture_service();
    let addresses: Vec<_> = [
        ("192.0.2.1", "node"),
        ("node.web.hidden.example.com", "alias"),
        ("node.web.hidden.example.com.", "alias2"),
        ("other.web.hidden.example.com", "alias3"),
        ("192.0.2.2", "other"),
        ("Node.web.hidden.example.com", "alias4"),
        ("no\\100e.web.hidden.example.com", "alias5"),
        ("192.0.2.3", "no\\100e"),
        ("192.0.2.4", "nod\\.e"),
        ("nod\\.e.web.hidden.example.com.", "alias6"),
    ]
    .into_iter()
    .map(|(ip, hostname)| EndpointAddress {
        ip: ip.into(),
        hostname: hostname.into(),
        target_ref_name: String::new().into(),
        ready: true,
    })
    .collect();
    let ports: Vec<_> = [80, 81]
        .into_iter()
        .map(|port| Port {
            name: "http".into(),
            protocol: "TCP".into(),
            port,
        })
        .collect();
    let mut snapshot = fixture_snapshot(&plugin, &zone);
    headless(
        &mut snapshot,
        || {
            addresses
                .iter()
                .flat_map(|a| ports.iter().map(move |p| (a, p)))
        },
        NameRef::parse(base.as_wire(), 0).unwrap(),
        (&service, NameRef::parse(zone.as_wire(), 0).unwrap()),
        false,
        &mut HashMap::with_capacity(addresses.len() * ports.len() * 4),
    )
    .unwrap();
    let mut stream = stream_snapshot(snapshot.bytes.unwrap());
    let mut wire = Vec::new();
    let mut actual = Vec::new();
    while stream.next(&mut wire).unwrap() {
        for rr in Message::parse(&wire).unwrap().answers() {
            if rr.rtype == Type::SRV && rr.name.to_string() == base.to_string() {
                let Rdata::Srv { port, target, .. } = rr.data().unwrap() else {
                    panic!("SRV")
                };
                actual.push((port, target.to_string()));
            }
        }
    }
    let mut expected = Vec::new();
    for name in ["node", "other", "Node", "node", "nod\\.e"] {
        for port in [80, 81] {
            expected.push((port, format!("{name}.web.hidden.example.com.")));
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn headless_pod_name_with_dots_uses_coredns_domain_labels() {
    use pharos_kubernetes::object::{EndpointAddress, Port};
    let plugin = plugin();
    let zone: Name = "example.com.".parse().unwrap();
    let base: Name = "web.hidden.example.com.".parse().unwrap();
    let service = fixture_service();
    let address = EndpointAddress {
        ip: "192.0.2.1".into(),
        hostname: String::new(),
        target_ref_name: "pod.region".into(),
        ready: true,
    };
    let port = Port {
        name: "http".into(),
        protocol: "TCP".into(),
        port: 80,
    };
    let mut snapshot = fixture_snapshot(&plugin, &zone);
    headless(
        &mut snapshot,
        || std::iter::once((&address, &port)),
        NameRef::parse(base.as_wire(), 0).unwrap(),
        (&service, NameRef::parse(zone.as_wire(), 0).unwrap()),
        true,
        &mut HashMap::with_capacity(4),
    )
    .unwrap();
    let mut stream = stream_snapshot(snapshot.bytes.unwrap());
    let mut wire = Vec::new();
    let mut found = false;
    while stream.next(&mut wire).unwrap() {
        let message = Message::parse(&wire).unwrap();
        found |= message.answers().any(|rr| {
            rr.rtype == Type::A && rr.name.to_string() == "pod.region.web.hidden.example.com."
        });
    }
    assert!(found);
}

#[test]
fn invalid_nameserver_address_emits_no_aaaa_rdata() {
    let plugin = plugin();
    let zone: Name = "example.com.".parse().unwrap();
    let mut snapshot = fixture_snapshot(&plugin, &zone);
    snapshot.ip(snapshot.ns, None, 5).unwrap();
    assert_eq!(snapshot.size, 0);
}

#[test]
fn transfer_uses_configured_apex_and_ttl() {
    let mut plugin = plugin();
    let blocks = parse(
        "Corefile",
        ".:53 {\n k8s_external example.com {\n  apex external\n  ttl 30\n }\n}",
    )
    .unwrap();
    let config = super::super::setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["k8s_external"]),
        &["."],
    )
    .unwrap();
    let kubernetes = plugin.kubernetes.take().unwrap();
    let mut plugin = External::new(config).unwrap();
    plugin.bind_kubernetes(&kubernetes);
    let zone: Name = "example.com.".parse().unwrap();
    let mut stream = plugin
        .transfer(request(&zone, Type::AXFR, 0, Protocol::Tcp))
        .unwrap()
        .unwrap();
    let mut wire = Vec::new();
    assert!(stream.next(&mut wire).unwrap());
    let message = Message::parse(&wire).unwrap();
    let soa = message.answers().next().unwrap();
    assert_eq!(soa.ttl, 30);
    let Rdata::Soa {
        mname,
        rname,
        minimum,
        ..
    } = soa.data().unwrap()
    else {
        panic!("SOA")
    };
    assert_eq!(mname.to_string(), "ns1.external.example.com.");
    assert_eq!(rname.to_string(), "hostmaster.external.example.com.");
    assert_eq!(minimum, 30);
}

#[test]
fn snapshot_batches_large_zones_without_losing_records() {
    let plugin = plugin();
    let zone: Name = "example.com.".parse().unwrap();
    let mut snapshot = fixture_snapshot(&plugin, &zone);
    snapshot.soa(0).unwrap();
    for _ in 0..4000 {
        snapshot
            .ip(
                NameRef::parse(zone.as_wire(), 0).unwrap(),
                Some("192.0.2.1".parse().unwrap()),
                5,
            )
            .unwrap();
    }
    snapshot.soa(0).unwrap();
    let mut stream = stream_snapshot(snapshot.bytes.unwrap());
    let mut wire = Vec::new();
    let mut messages = 0;
    let mut count = 0;
    while stream.next(&mut wire).unwrap() {
        assert!(wire.len() <= 64500);
        count += Message::parse(&wire).unwrap().answer_count() as usize;
        messages += 1;
    }
    assert_eq!(count, 4002);
    assert!(messages > 1);
}

#[tokio::test]
async fn transfer_reads_unfiltered_services_and_headless_endpoints() {
    use pharos_server::{Lifecycle, Phase};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = [0; 4096];
                let n = socket.read(&mut request).await.unwrap();
                let request = String::from_utf8_lossy(&request[..n]);
                let (kind, items) = if request.contains("/services") {
                    (
                        "ServiceList",
                        r#"[{"metadata":{"name":"web","namespace":"hidden"},"spec":{"clusterIP":"10.0.0.1","externalIPs":["192.0.2.1","lb.example.net"],"ports":[{"name":"http","protocol":"TCP","port":80}]}},{"metadata":{"name":"head","namespace":"hidden"},"spec":{"clusterIP":"None"}}]"#,
                    )
                } else if request.contains("/endpointslices") {
                    (
                        "EndpointSliceList",
                        r#"[{"metadata":{"name":"head-1","namespace":"hidden","labels":{"kubernetes.io/service-name":"head"}},"addressType":"IPv4","endpoints":[{"addresses":["192.0.2.2"],"hostname":"node"}],"ports":[{"name":"http","protocol":"TCP","port":80}]}]"#,
                    )
                } else {
                    ("NamespaceList", r#"[{"metadata":{"name":"visible"}}]"#)
                };
                let body = if request.contains("watch=true") {
                    String::new()
                } else {
                    format!(
                        r#"{{"apiVersion":"v1","kind":"{kind}","metadata":{{"resourceVersion":"1"}},"items":{items}}}"#
                    )
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    let text = format!(
        ".:53 {{\n kubernetes cluster.local {{\n  endpoint http://{server}\n  namespaces visible\n  ttl 37\n  startup_timeout 3s\n }}\n}}"
    );
    let blocks = parse("Corefile", &text).unwrap();
    let config = crate::kubernetes::setup::parse(
        &mut Cursor::new("Corefile", &blocks[0].directives["kubernetes"]),
        &["."],
    )
    .unwrap();
    let kubernetes = crate::kubernetes::Kubernetes::new(config).unwrap();
    let mut lifecycle = Lifecycle::default();
    kubernetes.register_hooks(&mut lifecycle);
    lifecycle.run(Phase::Startup).await.unwrap();
    let mut external = plugin();
    external.config.headless = true;
    external.bind_kubernetes(&kubernetes);
    let zone: Name = "example.com.".parse().unwrap();
    let mut stream = external
        .transfer(request(&zone, Type::AXFR, 0, Protocol::Tcp))
        .unwrap()
        .unwrap();
    let mut wire = Vec::new();
    let mut web = false;
    let mut head = false;
    let mut srv = false;
    let mut cname = false;
    while stream.next(&mut wire).unwrap() {
        let message = Message::parse(&wire).unwrap();
        for rr in message.answers() {
            match (rr.name.to_string().as_str(), rr.rtype) {
                ("web.hidden.example.com.", Type::A) => web = true,
                ("web.hidden.example.com.", Type::CNAME) => {
                    assert!(
                        matches!(rr.data().unwrap(), Rdata::Cname(target) if target.to_string() == "lb.example.net.")
                    );
                    cname = true;
                }
                ("lb.example.net.", Type::A | Type::AAAA) => {
                    panic!("unexpected target address")
                }
                ("node.head.hidden.example.com.", Type::A) => {
                    assert!(web);
                    head = true;
                }
                ("_http._tcp.head.hidden.example.com.", Type::SRV) => {
                    assert_eq!(rr.ttl, 37);
                    srv = true;
                }
                _ => {}
            }
        }
    }
    assert!(web && head && srv && cname);
    lifecycle.run(Phase::Shutdown).await.unwrap();
    task.abort();
}
