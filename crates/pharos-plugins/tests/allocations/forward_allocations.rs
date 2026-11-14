#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-forward", feature = "plugin-prometheus"))]

use std::{
    alloc::System,
    io::{Read, Write},
    net::{TcpListener, UdpSocket},
    time::Duration,
};

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{EdnsOption, Message, Rcode};
use pharos_server::{Action, Handler, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn warmed_forward_queries_with_metrics_do_not_allocate() {
    if crate::run_isolated(
        "forward::forward_allocations::warmed_forward_queries_with_metrics_do_not_allocate",
    ) {
        return;
    }
    for (protocol, failover) in [
        (Protocol::Udp, false),
        (Protocol::Tcp, false),
        (Protocol::Udp, true),
    ] {
        check_forward(protocol, failover);
    }
}

fn check_forward(protocol: Protocol, failover: bool) {
    let mut addresses = Vec::new();
    let mut threads = Vec::new();
    for index in 0..if failover { 2 } else { 1 } {
        // RFC 1035 §4.1.1: RCODE 2 denotes server failure.
        let rcode = if failover && index == 0 { 2 } else { 0 };
        if protocol == Protocol::Tcp {
            let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
            addresses.push(upstream.local_addr().unwrap());
            threads.push(std::thread::spawn(move || {
                let (mut stream, _) = upstream.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut wire = [0; 512];
                for _ in 0..20 {
                    // RFC 1035 §4.2.2: TCP DNS messages use a two-byte length prefix.
                    let mut size = [0; 2];
                    stream.read_exact(&mut size).unwrap();
                    let len = usize::from(u16::from_be_bytes(size));
                    stream.read_exact(&mut wire[..len]).unwrap();
                    wire[2] |= 0x80;
                    wire[3] = rcode;
                    stream.write_all(&size).unwrap();
                    stream.write_all(&wire[..len]).unwrap();
                }
            }));
        } else {
            let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
            upstream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            addresses.push(upstream.local_addr().unwrap());
            threads.push(std::thread::spawn(move || {
                let mut wire = [0; 512];
                for _ in 0..20 {
                    let (len, peer) = upstream.recv_from(&mut wire).unwrap();
                    wire[2] |= 0x80;
                    wire[3] = rcode;
                    upstream.send_to(&wire[..len], peer).unwrap();
                }
            }));
        }
    }
    let destinations = addresses
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let text = format!(
        ".:0 {{\n prometheus\n forward . {destinations} {{\n policy sequential\n failover SERVFAIL\n }}\n}}"
    );
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let query = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];
        let peer = "127.0.0.1:1000".parse().unwrap();
        let mut response = Vec::with_capacity(65535);
        for id in 0..10u8 {
            let mut query = query;
            query[1] = id;
            assert_eq!(
                server.handle(&query, peer, protocol, &mut response).await,
                Action::Respond
            );
            // RFC 1035 §4.1.1: Copy the query ID into its corresponding response.
            assert_eq!(&response[..2], &query[..2]);
            // RFC 1035 §4.1.1: RCODE 0 denotes no error condition.
            assert_eq!(
                pharos_proto::Message::parse(&response).unwrap().rcode(),
                pharos_proto::Rcode::NOERROR
            );
        }
        let before = GLOBAL.stats();
        for id in 10..20u8 {
            let mut query = query;
            query[1] = id;
            assert_eq!(
                server.handle(&query, peer, protocol, &mut response).await,
                Action::Respond
            );
            assert_eq!(&response[..2], &query[..2]);
        }
        let after = GLOBAL.stats();
        assert_eq!(after.allocations - before.allocations, 0);
        assert_eq!(after.reallocations - before.reallocations, 0);
    });
    for thread in threads {
        thread.join().unwrap();
    }
}

#[test]
fn warmed_refused_ecs_retry_does_not_allocate() {
    if crate::run_isolated(
        "forward::forward_allocations::warmed_refused_ecs_retry_does_not_allocate",
    ) {
        return;
    }
    check_refused_ecs_forward();
}

// RFC 7871 §6 and RFC 7828 §3.2.1: exercise sanitized ECS and TCP Keepalive options.
fn ecs_query() -> Vec<u8> {
    let options = [
        0, 11, 0, 2, 0, 100, // TCP Keepalive
        0, 8, 0, 7, 0, 1, 24, 8, 192, 0, 2, // ECS
    ];
    let mut query =
        b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0\x07example\x03org\0\0\x01\0\x01".to_vec();
    query[10..12].copy_from_slice(&1_u16.to_be_bytes());
    let opt_start = query.len();
    query.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    query[opt_start + 9..opt_start + 11]
        .copy_from_slice(&u16::try_from(options.len()).unwrap().to_be_bytes());
    query.extend_from_slice(&options);
    query
}

// RFC 1035 §§4.1.1, 4.1.3: Build a two-address A response without heap allocation.
fn two_a_response(query: &[u8], response: &mut [u8]) -> usize {
    let message = Message::parse(query).unwrap();
    let question_len = 12 + message.questions().next().unwrap().name.wire_len() + 4;
    response[..question_len].copy_from_slice(&query[..question_len]);
    response[2] |= 0x80;
    response[3] = Rcode::NOERROR.0 as u8;
    response[6..8].copy_from_slice(&2_u16.to_be_bytes());
    response[10..12].fill(0);
    let records = [
        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0,
        60, 0, 4, 192, 0, 2, 2,
    ];
    response[question_len..question_len + records.len()].copy_from_slice(&records);
    question_len + records.len()
}

fn check_refused_ecs_forward() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let address = upstream.local_addr().unwrap();
    let task = std::thread::spawn(move || {
        let mut query_wire = [0; 512];
        let mut response = [0; 512];
        for _ in 0..20 {
            let (len, peer) = upstream.recv_from(&mut query_wire).unwrap();
            let query = Message::parse(&query_wire[..len]).unwrap();
            let ecs = query
                .opt()
                .unwrap()
                .options()
                .iter()
                .find_map(|option| match option {
                    EdnsOption::ClientSubnet(subnet) => Some(subnet),
                    _ => None,
                });
            assert_eq!(ecs.map(|subnet| subnet.scope_prefix()), Some(0));
            response[..len].copy_from_slice(&query_wire[..len]);
            response[2] |= 0x80;
            response[3] = Rcode::REFUSED.0 as u8;
            upstream.send_to(&response[..len], peer).unwrap();
            let (len, peer) = upstream.recv_from(&mut query_wire).unwrap();
            let retry = Message::parse(&query_wire[..len]).unwrap();
            assert!(retry.opt().unwrap().options().iter().all(|option| {
                !matches!(option, EdnsOption::ClientSubnet(_))
                    && !matches!(option, EdnsOption::TcpKeepalive(_))
            }));
            let response_len = two_a_response(&query_wire[..len], &mut response);
            upstream.send_to(&response[..response_len], peer).unwrap();
        }
    });

    let text = format!(".:0 {{\n prometheus\n forward . {address}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut query = ecs_query();
    let peer = "127.0.0.1:1000".parse().unwrap();
    let mut response = Vec::with_capacity(65535);
    runtime.block_on(async {
        for id in 0..10_u8 {
            query[1] = id;
            assert_eq!(
                server
                    .handle(&query, peer, Protocol::Udp, &mut response)
                    .await,
                Action::Respond
            );
        }
        let before = GLOBAL.stats();
        for id in 10..20_u8 {
            query[1] = id;
            assert_eq!(
                server
                    .handle(&query, peer, Protocol::Udp, &mut response)
                    .await,
                Action::Respond
            );
        }
        let after = GLOBAL.stats();
        assert_eq!(after.allocations - before.allocations, 0);
        assert_eq!(after.reallocations - before.reallocations, 0);
    });
    task.join().unwrap();
}
