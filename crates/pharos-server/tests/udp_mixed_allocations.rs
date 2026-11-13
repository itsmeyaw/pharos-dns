#![forbid(unsafe_code)]

use std::{
    alloc::System,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use pharos_server::{Action, Handler, Listener, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

struct Mixed {
    started: Arc<AtomicBool>,
    counts: Arc<Mutex<(Option<Stats>, Option<Stats>)>>,
    shed: Option<pharos_server::metrics::ShedMetrics>,
}

impl Handler for Mixed {
    fn udp_workers(&self) -> usize {
        1
    }
    fn shed_metrics(&self) -> Option<pharos_server::metrics::ShedMetrics> {
        self.shed.clone()
    }
    fn parallel_query(
        &self,
        query: &[u8],
        _: SocketAddr,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        if query == b"ready" {
            self.counts.lock().unwrap().0 = Some(GLOBAL.stats());
        }
        None
    }

    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        // Rust Future::poll: a waiting Query must not force allocation in the next ready Query.
        if query == b"slow" {
            tokio::task::yield_now().await;
            self.started.store(true, Ordering::Release);
            std::future::pending().await
        } else {
            self.counts.lock().unwrap().1 = Some(GLOBAL.stats());
            response.extend_from_slice(query);
            Action::Respond
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn ready_query_after_pending_query_does_not_allocate() {
    for shed in [false, true] {
        let started = Arc::new(AtomicBool::new(false));
        let counts = Arc::new(Mutex::new((None, None)));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            Mixed {
                started: started.clone(),
                counts: counts.clone(),
                shed: shed.then(|| pharos_server::metrics::Registry::default().shed("dns://:53")),
            },
        )
        .await
        .unwrap();
        let address = listener.local_addr();
        let (done, finished) = tokio::sync::oneshot::channel();
        let client = std::thread::spawn(move || {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut response = [0; 16];
            for _ in 0..100 {
                socket.send_to(b"warm", address).unwrap();
                let (length, _) = socket.recv_from(&mut response).unwrap();
                assert_eq!(&response[..length], b"warm");
            }
            socket.send_to(b"slow", address).unwrap();
            while !started.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            socket.send_to(b"ready", address).unwrap();
            let (length, _) = socket.recv_from(&mut response).unwrap();
            assert_eq!(&response[..length], b"ready");
            done.send(()).unwrap();
        });
        finished.await.unwrap();
        client.join().unwrap();
        let (before, after) = *counts.lock().unwrap();
        let (before, after) = (before.unwrap(), after.unwrap());
        assert_eq!(
            after.allocations - before.allocations,
            0,
            "before={before:?} after={after:?}"
        );
        assert_eq!(after.reallocations - before.reallocations, 0);
        listener.shutdown().await.unwrap();
    }
}
