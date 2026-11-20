use super::*;
use crate::transfer::Transferer;
use pharos_kubernetes::object::{EndpointAddress, Endpoints, Port};
use pharos_proto::Rdata;

struct Ready;
impl pharos_server::Readiness for Ready {
    fn ready(&self) -> bool {
        true
    }
}

fn plugin() -> Kubernetes {
    let blocks =
        pharos_corefile::parse("Corefile", ".:53 {\n kubernetes cluster.local\n}").unwrap();
    let config = setup::parse(
        &mut pharos_corefile::Cursor::new("Corefile", &blocks[0].directives["kubernetes"]),
        &["."],
    )
    .unwrap();
    let mut plugin = Kubernetes::new(config).unwrap();
    plugin.local_ips = vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
    plugin
}

fn answers(mut stream: pharos_server::Stream) -> Vec<(String, Type)> {
    let mut wire = Vec::new();
    let mut records = Vec::new();
    while stream.next(&mut wire).unwrap() {
        let msg = Message::parse(&wire).unwrap();
        assert_eq!(msg.id(), 42);
        records.extend(msg.answers().map(|rr| (rr.name.to_string(), rr.rtype)));
    }
    records
}

fn request(zone: &Name, flags: u16) -> TransferRequest<'_> {
    TransferRequest {
        zone: NameRef::parse(zone.as_wire(), 0).unwrap(),
        serial: 0,
        id: 42,
        flags,
        protocol: Protocol::Tcp,
        qtype: Type::AXFR,
        qclass: Class::IN,
    }
}

#[test]
fn axfr_frames_zone_with_soa_and_source_ns() {
    let plugin = plugin();
    let zone: Name = "cluster.local.".parse().unwrap();
    let stream = plugin.transfer(request(&zone, 0)).unwrap().unwrap();
    assert_eq!(
        answers(stream),
        [
            ("cluster.local.".into(), Type::SOA),
            ("cluster.local.".into(), Type::NS),
            ("ns.dns.cluster.local.".into(), Type::A),
            ("ns.dns.cluster.local.".into(), Type::AAAA),
            ("dns-version.cluster.local.".into(), Type::TXT),
            ("cluster.local.".into(), Type::SOA),
        ]
    );
}

#[test]
fn axfr_clears_cd_and_rejects_non_in_class() {
    let plugin = plugin();
    let zone: Name = "cluster.local.".parse().unwrap();
    let mut query = request(&zone, 0x0110);
    let mut stream = plugin.transfer(query).unwrap().unwrap();
    let mut wire = Vec::new();
    assert!(stream.next(&mut wire).unwrap());
    assert_eq!(Message::parse(&wire).unwrap().flags() & 0x0010, 0);

    query.qclass = Class::CH;
    assert!(plugin.transfer(query).unwrap().is_none());
}

#[test]
fn small_zone_is_batched_into_one_message() {
    let plugin = plugin();
    let zone: Name = "cluster.local.".parse().unwrap();
    let mut stream = plugin.transfer(request(&zone, 0x0100)).unwrap().unwrap();
    let mut wire = Vec::new();
    assert!(stream.next(&mut wire).unwrap());
    assert_eq!(Message::parse(&wire).unwrap().answer_count(), 6);
    assert_eq!(Message::parse(&wire).unwrap().flags(), 0x8500);
    assert!(!stream.next(&mut wire).unwrap());
}

#[test]
fn large_zone_spans_bounded_messages_without_losing_records() {
    let zone: Name = "cluster.local.".parse().unwrap();
    let mut snapshot = snapshot(&zone);
    snapshot.soa(1).unwrap();
    for _ in 0..4000 {
        snapshot
            .address(NameRef::parse(zone.as_wire(), 0).unwrap(), "192.0.2.1")
            .unwrap();
    }
    snapshot.soa(1).unwrap();
    let mut stream = stream_snapshot(snapshot.bytes.unwrap());
    let mut wire = Vec::new();
    let mut count = 0;
    let mut messages = 0;
    while stream.next(&mut wire).unwrap() {
        assert!(wire.len() <= 64500);
        count += Message::parse(&wire).unwrap().answer_count() as usize;
        messages += 1;
    }
    assert_eq!(count, 4002);
    assert!(messages > 1);
}

#[test]
fn source_ns_addresses_have_coredns_zero_ttl() {
    let plugin = plugin();
    let zone: Name = "cluster.local.".parse().unwrap();
    let mut stream = plugin.transfer(request(&zone, 0)).unwrap().unwrap();
    let mut wire = Vec::new();
    while stream.next(&mut wire).unwrap() {
        let message = Message::parse(&wire).unwrap();
        for rr in message.answers() {
            if matches!(rr.rtype, Type::A | Type::AAAA) {
                assert_eq!(rr.ttl, 0);
            }
        }
    }
}

#[test]
fn transfer_outside_zone_returns_none() {
    let zone: Name = "elsewhere.".parse().unwrap();
    assert!(plugin().transfer(request(&zone, 0)).unwrap().is_none());
}

fn snapshot(zone: &Name) -> Snapshot<'_> {
    Snapshot {
        zone: NameRef::parse(zone.as_wire(), 0).unwrap(),
        id: 42,
        flags: 0,
        protocol: Protocol::Tcp,
        authoritative: true,
        qtype: Type::AXFR,
        qclass: Class::IN,
        ttl: 5,
        pod_names: false,
        bytes: Some(Vec::new()),
        size: 0,
    }
}

fn messages(bytes: &[u8]) -> Vec<&[u8]> {
    let mut messages = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        messages.push(&rest[2..2 + len]);
        rest = &rest[2 + len..];
    }
    messages
}

#[test]
fn cluster_service_transfers_addresses_and_named_and_unnamed_srv() {
    let zone: Name = "cluster.local.".parse().unwrap();
    let mut snapshot = snapshot(&zone);
    let ports = [
        Port {
            name: "HTTP".into(),
            protocol: "TCP".into(),
            port: 8080,
        },
        Port {
            name: "".into(),
            protocol: "TCP".into(),
            port: 53,
        },
    ];
    snapshot
        .service(
            &Index::default(),
            "prod",
            "web",
            &["10.0.0.1".into(), "2001:db8::1".into()],
            &ports,
            false,
        )
        .unwrap();
    let bytes = snapshot.bytes.unwrap();
    let messages = messages(&bytes);
    let records: Vec<_> = messages
        .iter()
        .map(|wire| Message::parse(wire).unwrap().answers().next().unwrap())
        .collect();
    assert_eq!(
        records.iter().map(|rr| rr.rtype).collect::<Vec<_>>(),
        [Type::A, Type::AAAA, Type::SRV, Type::SRV]
    );
    assert!(matches!(
        records[2].data().unwrap(),
        Rdata::Srv {
            weight: 100,
            port: 8080,
            target,
            ..
        } if target.to_string() == "web.prod.svc.cluster.local."
    ));
    assert_eq!(
        records[3].name.to_string(),
        "_http._tcp.web.prod.svc.cluster.local."
    );
    assert!(
        matches!(records[3].data().unwrap(), Rdata::Srv { weight: 100, port: 8080, target, .. } if target.to_string() == "web.prod.svc.cluster.local.")
    );
}

// CoreDNS's Kubernetes controller represents a Service with no ports by port -1.
#[test]
fn service_without_ports_transfers_no_sentinel_srv() {
    let zone: Name = "cluster.local.".parse().unwrap();
    let mut snapshot = snapshot(&zone);
    snapshot
        .service(
            &Index::default(),
            "prod",
            "web",
            &["10.0.0.1".into()],
            &[Port {
                name: String::new(),
                protocol: String::new(),
                port: -1,
            }],
            false,
        )
        .unwrap();
    let bytes = snapshot.bytes.unwrap();
    let messages = messages(&bytes);
    assert_eq!(messages.len(), 1);
    assert_eq!(
        Message::parse(messages[0])
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rtype,
        Type::A
    );
}

#[test]
fn unnamed_service_port_does_not_transfer_base_srv() {
    let zone: Name = "cluster.local.".parse().unwrap();
    let mut snapshot = snapshot(&zone);
    snapshot
        .service(
            &Index::default(),
            "prod",
            "web",
            &["10.0.0.1".into()],
            &[Port {
                name: String::new(),
                protocol: "TCP".into(),
                port: 80,
            }],
            false,
        )
        .unwrap();
    let records: Vec<_> = messages(&snapshot.bytes.unwrap())
        .into_iter()
        .flat_map(|wire| {
            Message::parse(wire)
                .unwrap()
                .answers()
                .map(|rr| rr.rtype)
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(records, [Type::A]);
}

#[test]
fn nil_endpoint_port_does_not_transfer_srv_port_65535() {
    let zone: Name = "cluster.local.".parse().unwrap();
    let base_name: Name = "web.prod.svc.cluster.local.".parse().unwrap();
    let base = NameRef::parse(base_name.as_wire(), 0).unwrap();
    let endpoints = Endpoints {
        version: "1".into(),
        name: "slice".into(),
        namespace: "prod".into(),
        service_name: "web".into(),
        addresses: vec![EndpointAddress {
            ip: "10.0.0.1".into(),
            hostname: "node".into(),
            target_ref_name: String::new().into(),
            ready: true,
        }],
        ports: vec![Port {
            name: String::new(),
            protocol: "TCP".into(),
            port: -1,
        }],
        zones: None,
    };
    let mut snapshot = snapshot(&zone);
    snapshot
        .endpoints(base, &endpoints, false, false, None)
        .unwrap();
    let records: Vec<_> = messages(&snapshot.bytes.unwrap())
        .into_iter()
        .map(|wire| {
            Message::parse(wire)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rtype
        })
        .collect();
    // KEP-752 §Proposal > Endpoint Port: nil endpoint ports are omitted, not cast to 65535.
    assert_eq!(records, [Type::A, Type::A]);
}

#[test]
fn transfer_includes_unready_endpoint_only_when_service_allows_it() {
    let zone: Name = "cluster.local.".parse().unwrap();
    let base_name: Name = "web.prod.svc.cluster.local.".parse().unwrap();
    let base = NameRef::parse(base_name.as_wire(), 0).unwrap();
    let endpoints = Endpoints {
        version: "1".into(),
        name: "slice".into(),
        namespace: "prod".into(),
        service_name: "web".into(),
        addresses: vec![EndpointAddress {
            ip: "10.0.0.1".into(),
            hostname: "node".into(),
            target_ref_name: String::new().into(),
            ready: false,
        }],
        ports: vec![Port {
            name: "http".into(),
            protocol: "TCP".into(),
            port: 80,
        }],
        zones: None,
    };
    let mut transfer = snapshot(&zone);
    transfer
        .endpoints(base, &endpoints, false, false, None)
        .unwrap();
    assert_eq!(transfer.size, 0);

    // Kubernetes DNS spec 1.1.0 §2.1: the Service annotation opts into unready endpoints.
    let mut tolerated = snapshot(&zone);
    tolerated
        .endpoints(base, &endpoints, false, true, None)
        .unwrap();
    let bytes = tolerated.bytes.unwrap();
    let mut srv = Vec::new();
    for wire in messages(&bytes) {
        for record in Message::parse(wire).unwrap().answers() {
            if let Rdata::Srv { port, target, .. } = record.data().unwrap() {
                srv.push((record.name.to_string(), port, target.to_string()));
            }
        }
    }
    // RFC 2782 §3: include the tolerated endpoint's named SRV port.
    assert_eq!(
        srv,
        [(
            "_http._tcp.web.prod.svc.cluster.local.".into(),
            80,
            "node.web.prod.svc.cluster.local.".into()
        )]
    );
}

#[test]
fn headless_endpoints_transfer_hostnames_and_weighted_srv() {
    let zone: Name = "cluster.local.".parse().unwrap();
    let base_name: Name = "web.prod.svc.cluster.local.".parse().unwrap();
    let base = NameRef::parse(base_name.as_wire(), 0).unwrap();
    let mut snapshot = snapshot(&zone);
    let endpoints = Endpoints {
        version: "1".into(),
        name: "slice".into(),
        namespace: "prod".into(),
        service_name: "web".into(),
        addresses: ["10.0.0.1", "10.0.0.2"]
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
    snapshot
        .endpoints(base, &endpoints, false, false, None)
        .unwrap();
    let bytes = snapshot.bytes.unwrap();
    let messages = messages(&bytes);
    let records: Vec<_> = messages
        .iter()
        .map(|wire| Message::parse(wire).unwrap().answers().next().unwrap())
        .collect();
    assert_eq!(records.len(), 6);
    assert_eq!(
        records[1].name.to_string(),
        "node0.web.prod.svc.cluster.local."
    );
    assert_eq!(
        records[2].name.to_string(),
        "_http._tcp.web.prod.svc.cluster.local."
    );
    assert!(
        matches!(records[2].data().unwrap(), Rdata::Srv { weight: 50, port: 80, target, .. } if target.to_string() == "node0.web.prod.svc.cluster.local.")
    );
}

#[test]
fn multicluster_transfer_includes_source_cluster_in_endpoint_name() {
    let zone: Name = "clusterset.local.".parse().unwrap();
    let base_name: Name = "web.prod.svc.clusterset.local.".parse().unwrap();
    let base = NameRef::parse(base_name.as_wire(), 0).unwrap();
    let endpoints = Endpoints {
        version: "1".into(),
        name: "slice".into(),
        namespace: "prod".into(),
        service_name: "web".into(),
        addresses: vec![EndpointAddress {
            ip: "10.0.0.1".into(),
            hostname: "node".into(),
            target_ref_name: String::new().into(),
            ready: true,
        }],
        ports: vec![Port {
            name: "http".into(),
            protocol: "TCP".into(),
            port: 80,
        }],
        zones: None,
    };
    let mut snapshot = snapshot(&zone);
    snapshot
        .endpoints(base, &endpoints, false, false, Some("west.east"))
        .unwrap();
    let bytes = snapshot.bytes.unwrap();
    let records: Vec<_> = messages(&bytes)
        .into_iter()
        .map(|wire| Message::parse(wire).unwrap().answers().next().unwrap())
        .collect();
    assert_eq!(
        records[1].name.to_string(),
        "node.west.east.web.prod.svc.clusterset.local."
    );
    assert!(matches!(
        records[2].data().unwrap(),
        Rdata::Srv { target, .. }
            if target.to_string() == "node.west.east.web.prod.svc.clusterset.local."
    ));
}

#[test]
fn current_ixfr_has_one_soa_with_unchanged_fields() {
    let zone: Name = "cluster.local.".parse().unwrap();
    let mut snapshot = snapshot(&zone);
    snapshot.qtype = Type::IXFR;
    generate(&mut snapshot, &Index::default(), &plugin(), 123, 123, false).unwrap();
    let bytes = snapshot.bytes.unwrap();
    let messages = messages(&bytes);
    assert_eq!(messages.len(), 1);
    let message = Message::parse(messages[0]).unwrap();
    assert_eq!(message.flags() & 0x0400, 0);
    let rr = message.answers().next().unwrap();
    assert_eq!(rr.ttl, 5);
    assert!(matches!(
        rr.data().unwrap(),
        Rdata::Soa {
            serial: 123,
            refresh: 7200,
            retry: 1800,
            expire: 86400,
            minimum: 5,
            ..
        }
    ));
}

#[test]
fn ixfr_uses_rfc1982_order_across_serial_wraparound() {
    let zone: Name = "cluster.local.".parse().unwrap();
    for (serial, current, soa_only) in [(0, u32::MAX, true), (u32::MAX, 0, false)] {
        let mut snapshot = snapshot(&zone);
        snapshot.qtype = Type::IXFR;
        generate(
            &mut snapshot,
            &Index::default(),
            &plugin(),
            serial,
            current,
            false,
        )
        .unwrap();
        let bytes = snapshot.bytes.unwrap();
        let messages = messages(&bytes);
        assert_eq!(messages.len() == 1, soa_only);
        assert_eq!(Message::parse(messages[0]).unwrap().answer_count(), 1);
        assert_eq!(
            Message::parse(messages[0]).unwrap().flags() & 0x0400 == 0,
            soa_only
        );
    }
}

#[test]
fn current_udp_ixfr_keeps_authoritative_flag() {
    let zone: Name = "cluster.local.".parse().unwrap();
    let mut snapshot = snapshot(&zone);
    snapshot.qtype = Type::IXFR;
    snapshot.protocol = Protocol::Udp;
    generate(&mut snapshot, &Index::default(), &plugin(), 123, 123, false).unwrap();
    let bytes = snapshot.bytes.unwrap();
    let messages = messages(&bytes);
    assert_ne!(Message::parse(messages[0]).unwrap().flags() & 0x0400, 0);
}

#[test]
fn outdated_udp_ixfr_snapshots_only_current_soa() {
    let zone: Name = "cluster.local.".parse().unwrap();
    let mut snapshot = snapshot(&zone);
    snapshot.qtype = Type::IXFR;
    snapshot.protocol = Protocol::Udp;
    generate(&mut snapshot, &Index::default(), &plugin(), 1, 123, false).unwrap();
    let bytes = snapshot.bytes.unwrap();
    let messages = messages(&bytes);
    assert_eq!(messages.len(), 1);
    assert_eq!(
        Message::parse(messages[0])
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rtype,
        Type::SOA
    );
}

#[tokio::test]
async fn empty_zone_is_notified_after_initial_sync() {
    use crate::transfer::{Destination, Transfer, TransferZone};
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transfer = Transfer {
        zones: vec![TransferZone {
            domains: vec![".".parse().unwrap()],
            destinations: vec![Destination::Address {
                host: "127.0.0.1".parse().unwrap(),
                port: socket.local_addr().unwrap().port().to_string(),
            }],
            source: None,
        }],
    };
    let (send, receive) = tokio::sync::watch::channel(pharos_kubernetes::store::Changes::default());
    let task = tokio::spawn(watch_changes(
        receive,
        transfer,
        vec!["cluster.local.".parse().unwrap()],
        vec![],
        Arc::new(Ready),
    ));
    let mut wire = [0; 512];
    let (len, from) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.recv_from(&mut wire),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        Message::parse(&wire[..len])
            .unwrap()
            .questions()
            .next()
            .unwrap()
            .name
            .to_string(),
        "cluster.local."
    );
    wire[2] |= 0x80;
    socket.send_to(&wire[..len], from).await.unwrap();
    drop(send);
    task.await.unwrap();
}

#[tokio::test]
async fn initial_notify_waits_for_first_sync() {
    use crate::transfer::{Destination, Transfer, TransferZone};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Sync(AtomicBool);
    impl pharos_server::Readiness for Sync {
        fn ready(&self) -> bool {
            self.0.load(Ordering::Acquire)
        }
    }
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transfer = Transfer {
        zones: vec![TransferZone {
            domains: vec![".".parse().unwrap()],
            destinations: vec![Destination::Address {
                host: "127.0.0.1".parse().unwrap(),
                port: socket.local_addr().unwrap().port().to_string(),
            }],
            source: None,
        }],
    };
    let sync = Arc::new(Sync(AtomicBool::new(false)));
    let (send, receive) = tokio::sync::watch::channel(pharos_kubernetes::store::Changes::default());
    let task = tokio::spawn(watch_changes(
        receive,
        transfer,
        vec!["cluster.local.".parse().unwrap()],
        vec![],
        sync.clone(),
    ));
    send.send_modify(|value| value.internal += 1);
    let mut wire = [0; 512];
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(80),
            socket.recv_from(&mut wire)
        )
        .await
        .is_err()
    );
    sync.0.store(true, Ordering::Release);
    let (len, from) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.recv_from(&mut wire),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        Message::parse(&wire[..len])
            .unwrap()
            .questions()
            .next()
            .unwrap()
            .name
            .to_string(),
        "cluster.local."
    );
    wire[2] |= 0x80;
    socket.send_to(&wire[..len], from).await.unwrap();
    drop(send);
    task.await.unwrap();
}

#[tokio::test]
async fn change_watcher_notifies_affected_zones_and_stops() {
    use crate::transfer::{Destination, Transfer, TransferZone};
    use pharos_kubernetes::store::Changes;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transfer = Transfer {
        zones: vec![TransferZone {
            domains: vec![".".parse().unwrap()],
            destinations: vec![Destination::Address {
                host: "127.0.0.1".parse().unwrap(),
                port: socket.local_addr().unwrap().port().to_string(),
            }],
            source: None,
        }],
    };
    let zones: Vec<Name> = ["cluster.local.", "clusterset.local."]
        .map(|z| z.parse().unwrap())
        .into();
    let multi = vec![zones[1].clone()];
    let (send, receive) = tokio::sync::watch::channel(Changes::default());
    let task = tokio::spawn(watch_changes(
        receive,
        transfer,
        zones,
        multi,
        Arc::new(Ready),
    ));
    let mut wire = [0; 512];
    for expected in ["cluster.local.", "clusterset.local."] {
        let (len, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut wire),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            Message::parse(&wire[..len])
                .unwrap()
                .questions()
                .next()
                .unwrap()
                .name
                .to_string(),
            expected
        );
        wire[2] |= 0x80;
        socket.send_to(&wire[..len], from).await.unwrap();
    }
    send.send_modify(|v| v.multicluster += 1);
    let (len, from) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.recv_from(&mut wire),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        Message::parse(&wire[..len])
            .unwrap()
            .questions()
            .next()
            .unwrap()
            .name
            .to_string(),
        "clusterset.local."
    );
    wire[2] |= 0x80;
    socket.send_to(&wire[..len], from).await.unwrap();
    send.send_modify(|v| v.internal += 1);
    for expected in ["cluster.local.", "clusterset.local."] {
        let (len, from) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.recv_from(&mut wire),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            Message::parse(&wire[..len])
                .unwrap()
                .questions()
                .next()
                .unwrap()
                .name
                .to_string(),
            expected
        );
        wire[2] |= 0x80;
        socket.send_to(&wire[..len], from).await.unwrap();
    }
    task.abort();
    let _ = task.await;
    send.send_modify(|v| v.internal += 1);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            socket.recv_from(&mut wire)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn notifier_lifecycle_rebinds_and_stops_watcher() {
    let plugin = plugin();
    let transfer = crate::transfer::Transfer { zones: Vec::new() };
    Transferer::bind_transfer(&plugin, Some(&transfer));
    {
        let mut cache = plugin.state.cache.write().unwrap();
        cache.store = Some(Store::default());
        cache.sync = Some(Arc::new(Ready));
    }
    start(&plugin.state, &plugin.zones, &plugin.multicluster_zones);
    assert!(plugin.state.notifier.lock().unwrap().task.is_some());
    Transferer::bind_transfer(&plugin, None);
    assert!(plugin.state.notifier.lock().unwrap().task.is_none());
    Transferer::bind_transfer(&plugin, Some(&transfer));
    assert!(plugin.state.notifier.lock().unwrap().task.is_some());
    stop(&plugin.state);
    let notifier = plugin.state.notifier.lock().unwrap();
    assert!(!notifier.active);
    assert!(notifier.task.is_none());
}
