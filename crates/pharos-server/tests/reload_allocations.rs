#![forbid(unsafe_code)]

use pharos_server::{Action, Handler, ListenerKey, ListenerRegistry, Protocol, Transport};
use stats_alloc::{INSTRUMENTED_SYSTEM, Stats, StatsAlloc};
use std::{
    alloc::System,
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[derive(Default)]
struct Counts {
    queries: usize,
    before: Option<Stats>,
    after: Option<Stats>,
}
struct Echo(Arc<Mutex<Counts>>);
impl Handler for Echo {
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        let mut counts = self.0.lock().unwrap();
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

#[tokio::test(flavor = "current_thread")]
async fn swappable_listener_does_not_allocate_per_query() {
    let counts = Arc::new(Mutex::new(Counts::default()));
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let mut listeners = ListenerRegistry::default();
    listeners
        .apply(HashMap::from([(key, Echo(Arc::clone(&counts)))]))
        .await
        .unwrap();
    let address = listeners.get(&key).unwrap().local_addr();
    let (done, finished) = tokio::sync::oneshot::channel();
    let client = std::thread::spawn(move || {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut response = [0; 32];
        for _ in 0..201 {
            socket.send_to(b"query", address).unwrap();
            let (length, _) = socket.recv_from(&mut response).unwrap();
            assert_eq!(&response[..length], b"query");
        }
        done.send(()).unwrap();
    });
    finished.await.unwrap();
    client.join().unwrap();
    let (before, after) = {
        let counts = counts.lock().unwrap();
        (counts.before.unwrap(), counts.after.unwrap())
    };
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
    listeners.shutdown().await.unwrap();
}
