#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-forward", feature = "plugin-prometheus"))]
#![recursion_limit = "512"]

use std::{alloc::System, net::UdpSocket, time::Duration};

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::{Action, Handler, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn warmed_forward_queries_with_metrics_do_not_allocate() {
    let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
    upstream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let text = format!(
        ".:0 {{\n prometheus\n forward . {}\n}}",
        upstream.local_addr().unwrap()
    );
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let thread = std::thread::spawn(move || {
        let mut wire = [0; 512];
        for _ in 0..20 {
            let (len, peer) = upstream.recv_from(&mut wire).unwrap();
            wire[2] |= 0x80;
            upstream.send_to(&wire[..len], peer).unwrap();
        }
    });
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
                server
                    .handle(&query, peer, Protocol::Udp, &mut response)
                    .await,
                Action::Respond
            );
        }
        let before = GLOBAL.stats();
        for _ in 0..10 {
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
    thread.join().unwrap();
}
