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
use pharos_server::{Action, Handler, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn warmed_forward_queries_with_metrics_do_not_allocate() {
    let _serial = crate::serial();
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
        for _ in 0..10 {
            assert_eq!(
                server.handle(&query, peer, protocol, &mut response).await,
                Action::Respond
            );
            assert_eq!(
                pharos_proto::Message::parse(&response).unwrap().rcode(),
                pharos_proto::Rcode::NOERROR
            );
        }
        let before = GLOBAL.stats();
        for _ in 0..10 {
            assert_eq!(
                server.handle(&query, peer, protocol, &mut response).await,
                Action::Respond
            );
        }
        let after = GLOBAL.stats();
        assert_eq!(after.allocations - before.allocations, 0);
        assert_eq!(after.reallocations - before.reallocations, 0);
    });
    for thread in threads {
        thread.join().unwrap();
    }
}
