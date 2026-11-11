#![forbid(unsafe_code)]

use pharos_plugins::proxy::{Options, Proxy, Transport};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::{
    alloc::System,
    io::{Read, Write},
    net::TcpListener,
    time::Duration,
};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
const QUERY: &[u8] = &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];

#[test]
fn warmed_tcp_exchange_does_not_allocate() {
    let _serial = crate::serial();
    if crate::run_isolated("proxy::proxy_tcp_allocations::warmed_tcp_exchange_does_not_allocate") {
        return;
    }
    let server = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut proxy = Proxy::new(server.local_addr().unwrap());
    let registry = pharos_server::metrics::Registry::new("v", "r", "rust");
    proxy.set_metrics(&registry, "forward");
    let upstream = std::thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut wire = [0; 512];
        for _ in 0..20 {
            let mut length = [0; 2];
            stream.read_exact(&mut length).unwrap();
            let len = usize::from(u16::from_be_bytes(length));
            stream.read_exact(&mut wire[..len]).unwrap();
            wire[2] |= 0x80;
            stream.write_all(&length).unwrap();
            stream.write_all(&wire[..len]).unwrap();
        }
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut response = [0; 512];
        for _ in 0..10 {
            proxy
                .exchange(QUERY, &mut response, Transport::Tcp, Options::default())
                .await
                .unwrap();
        }
        let before = GLOBAL.stats();
        for _ in 0..10 {
            proxy
                .exchange(QUERY, &mut response, Transport::Tcp, Options::default())
                .await
                .unwrap();
        }
        let after = GLOBAL.stats();
        assert_eq!(after.allocations - before.allocations, 0);
        assert_eq!(after.reallocations - before.reallocations, 0);
    });
    upstream.join().unwrap();
}
