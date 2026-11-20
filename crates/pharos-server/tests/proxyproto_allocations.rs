#![forbid(unsafe_code)]

use std::{
    alloc::System,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use pharos_server::{
    Action, Handler, Listener, Protocol,
    proxyproto::{Config, Policy, UdpTracking},
};
use stats_alloc::{INSTRUMENTED_SYSTEM, Stats, StatsAlloc};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

// Queries seen, then the allocator stats at the 101st and 201st.
type Counts = (usize, Option<Stats>, Option<Stats>);

struct Probe {
    config: Arc<Config>,
    counts: Arc<Mutex<Counts>>,
}

impl Handler for Probe {
    fn proxyproto(&self) -> Option<Arc<Config>> {
        Some(Arc::clone(&self.config))
    }
    async fn handle(&self, _: &[u8], _: SocketAddr, _: Protocol, _: &mut Vec<u8>) -> Action {
        Action::Drop
    }
    async fn handle_shared(
        self: &Arc<Self>,
        query: &[u8],
        peer: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        self.handle_proxied(query, peer, protocol, "", response)
            .await
    }
    async fn handle_proxied(
        self: &Arc<Self>,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        tlv: &str,
        response: &mut Vec<u8>,
    ) -> Action {
        // Rust Future::poll: a pending Query must not prevent later slot reuse.
        if query == b"slow" {
            tokio::task::yield_now().await;
        }
        let mut counts = self.counts.lock().unwrap();
        counts.0 += 1;
        if counts.0 == 101 {
            counts.1 = Some(GLOBAL.stats());
        }
        if counts.0 == 201 {
            counts.2 = Some(GLOBAL.stats());
        }
        response.extend_from_slice(query);
        response.extend_from_slice(tlv.as_bytes());
        Action::Respond
    }
}

// PROXY protocol §2.2: a v2 DGRAM PROXY header for IPv4 with one TLV.
fn header() -> Vec<u8> {
    let mut wire = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    wire.extend([0x21, 0x12, 0, 16]);
    wire.extend([192, 0, 2, 1, 192, 0, 2, 53, 0x30, 0x39, 0, 53]);
    wire.extend([0xEA, 0, 1, 7]);
    wire
}

async fn measure(config: Config, header_first: bool, with_header: bool, tlv: &'static [u8]) {
    let counts = Arc::new(Mutex::new((0, None, None)));
    let listener = Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        Probe {
            config: Arc::new(config),
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
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        if header_first {
            // Cloudflare Spectrum: the header-only datagram opens the session and gets no reply.
            socket.send_to(&header(), address).unwrap();
        }
        let mut buf = [0; 64];
        // The client thread shares the global allocator, so it builds its datagram once.
        let datagram = |payload: &[u8]| {
            if with_header {
                [header().as_slice(), payload].concat()
            } else {
                payload.to_vec()
            }
        };
        let sent = [datagram(b"slow"), datagram(b"query")];
        let replied = [[b"slow", tlv].concat(), [b"query", tlv].concat()];
        for index in 0..201 {
            let kind = usize::from(index > 0);
            socket.send_to(&sent[kind], address).unwrap();
            let (n, _) = socket.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], replied[kind]);
        }
        let _ = done.send(());
    });
    finished.await.unwrap();
    client.join().unwrap();
    let (before, after) = {
        let counts = counts.lock().unwrap();
        (counts.1.unwrap(), counts.2.unwrap())
    };
    assert_eq!(
        after.allocations - before.allocations,
        0,
        "allocations (header_first={header_first}, with_header={with_header})"
    );
    assert_eq!(
        after.reallocations - before.reallocations,
        0,
        "reallocations (header_first={header_first}, with_header={with_header})"
    );
    listener.shutdown().await.unwrap();
}

fn proxied(tracking: bool) -> Config {
    let mut config = Config::new(|_| Policy::Use);
    config.tlv_metadata = true;
    if tracking {
        config.udp_tracking = Some(UdpTracking {
            ttl: Duration::from_secs(30),
            max_sessions: 100,
        });
    }
    config
}

// Each Listener runs in its own test process: nextest isolates the global allocator counts.
#[tokio::test(flavor = "current_thread")]
async fn plain_datagrams_allocate_nothing_with_proxyproto_configured() {
    measure(proxied(false), false, false, b"").await;
}

#[tokio::test(flavor = "current_thread")]
async fn datagram_headers_allocate_nothing_per_query() {
    measure(proxied(false), false, true, b"ea000107").await;
}

#[tokio::test(flavor = "current_thread")]
async fn spectrum_sessions_allocate_nothing_per_query() {
    measure(proxied(true), true, false, b"ea000107").await;
}

#[test]
fn accept_datagram_allocates_nothing_after_the_first_header() {
    let mut config = Config::new(|_| Policy::Use);
    config.tlv_metadata = true;
    let mut state = pharos_server::proxyproto::UdpState::default();
    let wire = [header(), b"query".to_vec()].concat();
    let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
    assert!(config.accept_datagram(&mut state, &wire, peer, 1).is_some());
    let before = GLOBAL.stats();
    for _ in 0..100 {
        assert!(config.accept_datagram(&mut state, &wire, peer, 1).is_some());
    }
    let after = GLOBAL.stats();
    assert_eq!(after.allocations - before.allocations, 0);
    assert_eq!(after.reallocations - before.reallocations, 0);
}
