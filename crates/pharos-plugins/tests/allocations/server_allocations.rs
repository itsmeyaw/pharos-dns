#![forbid(unsafe_code)]
#![cfg(feature = "plugin-whoami")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::{Message, Rcode};
use pharos_server::{Action, Handler, Listener, Protocol, Server};
use stats_alloc::{INSTRUMENTED_SYSTEM, Stats, StatsAlloc};
use std::{
    alloc::System,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[derive(Default)]
struct Counts {
    queries: usize,
    before: Option<Stats>,
    after: Option<Stats>,
}
struct Counting {
    server: Server<Arc<Chain>>,
    counts: Arc<Mutex<Counts>>,
}

impl Handler for Counting {
    fn parallel_query(
        &self,
        query: &[u8],
        peer: SocketAddr,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        self.server.parallel_query(query, peer)
    }

    async fn handle(
        &self,
        query: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        {
            let mut counts = self.counts.lock().unwrap();
            counts.queries += 1;
            if counts.queries == 101 {
                counts.before = Some(GLOBAL.stats());
            }
            if counts.queries == 201 {
                counts.after = Some(GLOBAL.stats());
            }
        }
        self.server.handle(query, peer, protocol, response).await
    }
}

#[tokio::test(flavor = "current_thread")]
async fn routed_udp_queries_do_not_allocate() {
    if crate::run_isolated("server::server_allocations::routed_udp_queries_do_not_allocate") {
        return;
    }
    check_routed_udp_queries_do_not_allocate(".:0 {\n whoami\n}").await;
    #[cfg(feature = "plugin-errors")]
    check_routed_udp_queries_do_not_allocate(".:0 {\n errors\n whoami\n}").await;
    #[cfg(feature = "plugin-prometheus")]
    check_routed_udp_queries_do_not_allocate(".:0 {\n prometheus\n whoami\n}").await;
    #[cfg(feature = "plugin-health")]
    check_routed_udp_queries_do_not_allocate(".:0 {\n health 127.0.0.1:0\n whoami\n}").await;
    #[cfg(feature = "plugin-loop")]
    {
        check_routed_udp_queries_do_not_allocate(".:0 {\n loop\n whoami\n}").await;
        check_routed_udp_queries_of_type(".:0 {\n loop\n whoami\n}", 13).await;
    }
}

async fn check_routed_udp_queries_do_not_allocate(corefile: &str) {
    check_routed_udp_queries_of_type(corefile, 1).await;
}

async fn check_routed_udp_queries_of_type(corefile: &str, qtype: u8) {
    let blocks = parse("Corefile", corefile).unwrap();
    let (mut servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (key, server) = servers.drain().next().unwrap();
    let counts = Arc::new(Mutex::new(Counts::default()));
    let listener = Listener::bind(
        key.address,
        Counting {
            server,
            counts: Arc::clone(&counts),
        },
    )
    .await
    .unwrap();
    let address = SocketAddr::from(([127, 0, 0, 1], listener.local_addr().port()));
    let (done, finished) = tokio::sync::oneshot::channel();
    let client = std::thread::spawn(move || {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let query = [
            0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, b'a', 0, 0, qtype, 0, 1, 0, 0, 41, 2, 0, 0, 0,
            0x80, 0, 0, 0,
        ];
        let mut buf = [0; 512];
        for _ in 0..201 {
            socket.send_to(&query, address).unwrap();
            let (n, _) = socket.recv_from(&mut buf).unwrap();
            // RFC 1035 §4.1.1: QR marks a response and RCODE 0 means no error.
            let response = Message::parse(&buf[..n]).unwrap();
            assert!(response.qr());
            assert_eq!(response.rcode(), Rcode::NOERROR);
        }
        let _ = done.send(());
    });
    finished.await.unwrap();
    client.join().unwrap();
    let (before, after) = {
        let counts = counts.lock().unwrap();
        (counts.before.unwrap(), counts.after.unwrap())
    };
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    listener.shutdown().await.unwrap();
}
