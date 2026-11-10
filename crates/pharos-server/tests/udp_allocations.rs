#![forbid(unsafe_code)]

use std::{
    alloc::System,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use pharos_server::{Action, Handler, Listener, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

struct Echo {
    counts: Arc<Mutex<Counts>>,
}

#[derive(Default)]
struct Counts {
    queries: usize,
    before: Option<Stats>,
    after: Option<Stats>,
}

impl Handler for Echo {
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        let mut counts = self.counts.lock().unwrap();
        counts.queries += 1;
        if counts.queries == 101 {
            counts.before = Some(GLOBAL.stats());
        }
        if counts.queries == 201 {
            counts.after = Some(GLOBAL.stats());
        }
        response.extend_from_slice(query);
        Action::Respond
    }
}

// A separate test process and one runtime thread isolate allocation counts.
#[tokio::test(flavor = "current_thread")]
async fn udp_worker_reuses_buffers_without_per_query_allocations() {
    let counts = Arc::new(Mutex::new(Counts::default()));
    let listener = Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        Echo {
            counts: Arc::clone(&counts),
        },
    )
    .await
    .unwrap();
    let address = listener.local_addr();
    let (done, finished) = tokio::sync::oneshot::channel();
    let client = std::thread::spawn(move || {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0; 32];
        for _ in 0..201 {
            socket.send_to(b"query", address).unwrap();
            let (n, _) = socket.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"query");
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
