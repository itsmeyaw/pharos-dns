#![forbid(unsafe_code)]

use std::{net::SocketAddr, time::Duration};

use pharos_server::{
    Action, Handler, Listener, ListenerKey, ListenerRegistry, Protocol, Transport,
};
use tokio::net::UdpSocket;

struct Echo;

struct AsyncEcho;

struct DropThenEcho(Option<pharos_server::metrics::ShedMetrics>);
impl Handler for DropThenEcho {
    fn udp_workers(&self) -> usize {
        1
    }
    fn shed_metrics(&self) -> Option<pharos_server::metrics::ShedMetrics> {
        self.0.clone()
    }
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        // RFC 1035 §4.2.1: independent UDP Messages retain their own Responses.
        if query == b"drop" {
            return Action::Drop;
        }
        if query == b"pending" {
            tokio::task::yield_now().await;
        }
        response.extend_from_slice(query);
        Action::Respond
    }
}

#[tokio::test]
async fn dropped_query_does_not_leak_into_reused_slot() {
    for shed in [false, true] {
        let metrics = shed.then(|| pharos_server::metrics::Registry::default().shed("dns://:53"));
        let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), DropThenEcho(metrics))
            .await
            .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(listener.local_addr()).await.unwrap();
        for query in [b"drop".as_slice(), b"ready", b"pending"] {
            socket.send(query).await.unwrap();
        }
        let mut seen = Vec::new();
        for _ in 0..2 {
            let mut response = [0; 16];
            let length = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut response))
                .await
                .unwrap()
                .unwrap();
            seen.push(response[..length].to_vec());
        }
        seen.sort();
        assert_eq!(seen, [b"pending".to_vec(), b"ready".to_vec()]);
        listener.shutdown().await.unwrap();
    }
}

struct RecycledEcho(std::sync::Arc<std::sync::Mutex<Vec<usize>>>);
impl Handler for RecycledEcho {
    fn udp_workers(&self) -> usize {
        1
    }
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        // Rust Future::poll: a pending Query retains its buffer until completion.
        self.0.lock().unwrap().push(response.as_ptr() as usize);
        tokio::task::yield_now().await;
        response.extend_from_slice(query);
        Action::Respond
    }
}

#[tokio::test]
async fn completed_pending_queries_reuse_response_buffers() {
    let addresses = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let listener = Listener::bind(
        "127.0.0.1:0".parse().unwrap(),
        RecycledEcho(addresses.clone()),
    )
    .await
    .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(listener.local_addr()).await.unwrap();
    for _ in 0..20 {
        socket.send(b"query").await.unwrap();
        let mut response = [0; 16];
        let length = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..length], b"query");
    }
    {
        let addresses = addresses.lock().unwrap();
        assert_eq!(addresses.len(), 20);
        // Rust Pin: the active slot and its prefilled replacement are both reused.
        assert!(
            addresses
                .iter()
                .all(|address| *address == addresses[0] || *address == addresses[1]),
            "{addresses:?}"
        );
    }
    listener.shutdown().await.unwrap();
}

struct SlowEcho {
    started: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Notify>,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    shed: Option<pharos_server::metrics::ShedMetrics>,
}

struct Alternating {
    started: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    permits: std::sync::Arc<tokio::sync::Semaphore>,
    shed: Option<pharos_server::metrics::ShedMetrics>,
}
impl Handler for Alternating {
    fn udp_workers(&self) -> usize {
        1
    }
    fn shed_metrics(&self) -> Option<pharos_server::metrics::ShedMetrics> {
        self.shed.clone()
    }
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        // RFC 1035 §4.2.1: each UDP Response belongs to its original Query.
        if query[0].is_multiple_of(2) {
            self.started
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.permits.acquire().await.unwrap().forget();
        }
        response.extend_from_slice(query);
        Action::Respond
    }
}

#[tokio::test]
async fn simultaneous_pending_and_ready_queries_keep_their_responses() {
    for shed in [false, true] {
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            Alternating {
                started: started.clone(),
                permits: permits.clone(),
                shed: shed.then(|| pharos_server::metrics::Registry::default().shed("dns://:53")),
            },
        )
        .await
        .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(listener.local_addr()).await.unwrap();
        for id in 0..32_u8 {
            socket.send(&[id]).await.unwrap();
        }
        wait_for_count(&started, 16).await;
        let mut seen = [false; 32];
        for _ in 0..16 {
            let mut response = [0; 1];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut response))
                    .await
                    .unwrap()
                    .unwrap(),
                1
            );
            assert_eq!(response[0] % 2, 1);
            assert!(!seen[usize::from(response[0])]);
            seen[usize::from(response[0])] = true;
        }
        permits.add_permits(16);
        for _ in 0..16 {
            let mut response = [0; 1];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut response))
                    .await
                    .unwrap()
                    .unwrap(),
                1
            );
            assert_eq!(response[0] % 2, 0);
            assert!(!seen[usize::from(response[0])]);
            seen[usize::from(response[0])] = true;
        }
        assert!(seen.into_iter().all(|value| value));
        listener.shutdown().await.unwrap();
    }
}

impl Handler for SlowEcho {
    fn udp_workers(&self) -> usize {
        1
    }

    fn shed_metrics(&self) -> Option<pharos_server::metrics::ShedMetrics> {
        self.shed.clone()
    }

    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        // RFC 1035 §4.2.1: UDP carries each Query in a separate datagram.
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if query == b"slow" {
            self.started.notify_one();
            self.release.notified().await;
        }
        response.extend_from_slice(query);
        Action::Respond
    }
}

#[tokio::test]
async fn slow_query_does_not_delay_fast_query_on_same_socket() {
    for shed in [false, true] {
        let started = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            SlowEcho {
                started: started.clone(),
                release: release.clone(),
                calls: calls.clone(),
                shed: shed.then(|| pharos_server::metrics::Registry::default().shed("dns://:53")),
            },
        )
        .await
        .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(listener.local_addr()).await.unwrap();
        socket.send(b"slow").await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        socket.send(b"fast").await.unwrap();
        let mut response = [0; 16];
        let length = tokio::time::timeout(Duration::from_millis(300), socket.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..length], b"fast");
        release.notify_one();
        let length = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..length], b"slow");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        listener.shutdown().await.unwrap();
    }
}

struct PendingQueries {
    started: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    dropped: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    permits: std::sync::Arc<tokio::sync::Semaphore>,
    shed: Option<pharos_server::metrics::ShedMetrics>,
    cancelled: tokio::sync::watch::Sender<bool>,
}

struct PendingGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Handler for PendingQueries {
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
        (query == b"probe").then(|| self.cancelled.subscribe())
    }
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        // RFC 1035 §4.2.1: UDP carries each Query in a separate datagram.
        if query == b"probe" {
            response.extend_from_slice(query);
            return Action::Respond;
        }
        let _guard = PendingGuard(self.dropped.clone());
        self.started
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.permits.acquire().await.unwrap().forget();
        response.extend_from_slice(query);
        Action::Respond
    }
}

async fn wait_for_count(count: &std::sync::atomic::AtomicUsize, expected: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while count.load(std::sync::atomic::Ordering::SeqCst) < expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn udp_pending_limit_resumes_after_completion() {
    for shed in [false, true] {
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            PendingQueries {
                started: started.clone(),
                dropped: dropped.clone(),
                permits: permits.clone(),
                shed: shed.then(|| pharos_server::metrics::Registry::default().shed("dns://:53")),
                cancelled: tokio::sync::watch::channel(false).0,
            },
        )
        .await
        .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(listener.local_addr()).await.unwrap();
        for count in 1..=256 {
            socket.send(b"slow").await.unwrap();
            wait_for_count(&started, count).await;
        }
        socket.send(b"queued").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), wait_for_count(&started, 257))
                .await
                .is_err()
        );
        // RFC 1035 §4.2.1: probes remain separate UDP Messages even under overload.
        socket.send(b"probe").await.unwrap();
        let mut probe = [0; 16];
        let length = tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut probe))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&probe[..length], b"probe");
        permits.add_permits(1);
        wait_for_count(&started, 257).await;
        listener.shutdown().await.unwrap();
        assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 257);
    }
}

#[tokio::test]
async fn udp_shutdown_cancels_pending_queries() {
    for shed in [false, true] {
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            PendingQueries {
                started: started.clone(),
                dropped: dropped.clone(),
                permits: std::sync::Arc::new(tokio::sync::Semaphore::new(0)),
                shed: shed.then(|| pharos_server::metrics::Registry::default().shed("dns://:53")),
                cancelled: tokio::sync::watch::channel(false).0,
            },
        )
        .await
        .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .send_to(b"slow", listener.local_addr())
            .await
            .unwrap();
        wait_for_count(&started, 1).await;
        tokio::time::timeout(Duration::from_secs(2), listener.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn udp_shutdown_at_pending_limit_cancels_all_queries() {
    for shed in [false, true] {
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener = Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            PendingQueries {
                started: started.clone(),
                dropped: dropped.clone(),
                permits: std::sync::Arc::new(tokio::sync::Semaphore::new(0)),
                shed: shed.then(|| pharos_server::metrics::Registry::default().shed("dns://:53")),
                cancelled: tokio::sync::watch::channel(false).0,
            },
        )
        .await
        .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(listener.local_addr()).await.unwrap();
        for count in 1..=256 {
            socket.send(b"slow").await.unwrap();
            wait_for_count(&started, count).await;
        }
        socket.send(b"queued").await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), listener.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dropped.load(std::sync::atomic::Ordering::SeqCst), 256);
    }
}

struct PanickingEcho {
    metrics: Option<pharos_server::metrics::ShedMetrics>,
    panicked: std::sync::Arc<tokio::sync::Notify>,
    cancelled: tokio::sync::watch::Sender<bool>,
}
impl Handler for PanickingEcho {
    fn udp_workers(&self) -> usize {
        1
    }
    fn shed_metrics(&self) -> Option<pharos_server::metrics::ShedMetrics> {
        self.metrics.clone()
    }
    fn parallel_query(
        &self,
        query: &[u8],
        _: SocketAddr,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        (query == b"parallel panic").then(|| self.cancelled.subscribe())
    }
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        // RFC 1035 §4.2.1: UDP carries each Query in a separate datagram.
        if query == b"pending panic" || query == b"parallel panic" {
            tokio::task::yield_now().await;
        }
        if query == b"panic" || query == b"pending panic" || query == b"parallel panic" {
            self.panicked.notify_one();
        }
        assert!(
            query != b"panic" && query != b"pending panic" && query != b"parallel panic",
            "test panic"
        );
        response.extend_from_slice(query);
        Action::Respond
    }
}

#[tokio::test]
async fn udp_handler_panics_do_not_stop_worker() {
    for shed in [false, true] {
        let metrics = shed.then(|| pharos_server::metrics::Registry::default().shed("dns://:53"));
        let panicked = std::sync::Arc::new(tokio::sync::Notify::new());
        let listener = Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            PanickingEcho {
                metrics,
                panicked: panicked.clone(),
                cancelled: tokio::sync::watch::channel(false).0,
            },
        )
        .await
        .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(listener.local_addr()).await.unwrap();
        for query in [b"panic".as_slice(), b"pending panic", b"parallel panic"] {
            socket.send(query).await.unwrap();
            tokio::time::timeout(Duration::from_secs(2), panicked.notified())
                .await
                .unwrap();
        }
        socket.send(b"ok").await.unwrap();
        let mut response = [0; 16];
        let length = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[..length], b"ok");
        listener.shutdown().await.unwrap();
    }
}

#[test]
fn udp_handler_panics_are_logged() {
    // Rust catch_unwind: verify both inline and spawned panics are reported.
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "udp_handler_panics_do_not_stop_worker",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.matches("ERROR server: Recovered panic in UDP Query")
            .count()
            >= 6,
        "{text}"
    );
}

struct ClientEcho(tokio::sync::watch::Sender<bool>);

impl Handler for ClientEcho {
    fn parallel_query(
        &self,
        query: &[u8],
        peer: SocketAddr,
    ) -> Option<tokio::sync::watch::Receiver<bool>> {
        assert_eq!(
            peer.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        );
        (query == b"parallel").then(|| self.0.subscribe())
    }

    async fn handle(
        &self,
        _: &[u8],
        peer: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        response.extend_from_slice(peer.ip().to_string().as_bytes());
        Action::Respond
    }
}

#[tokio::test]
async fn wildcard_udp_passes_native_peer_to_both_handler_paths() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        return;
    }
    let (sender, _) = tokio::sync::watch::channel(false);
    let listener = Listener::bind("[::]:0".parse().unwrap(), ClientEcho(sender))
        .await
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for query in [b"normal".as_slice(), b"parallel"] {
        socket
            .send_to(query, ("127.0.0.1", listener.local_addr().port()))
            .await
            .unwrap();
        let mut response = [0; 64];
        let (len, _) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&response[..len], b"127.0.0.1");
    }
    listener.shutdown().await.unwrap();
}

impl Handler for AsyncEcho {
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        tokio::task::yield_now().await;
        response.extend_from_slice(query);
        Action::Respond
    }
}

#[tokio::test]
async fn udp_awaits_async_handler() {
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), AsyncEcho)
        .await
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(b"query", listener.local_addr())
        .await
        .unwrap();
    let mut buf = [0; 32];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"query");
    listener.shutdown().await.unwrap();
}

impl Handler for Echo {
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        protocol: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        assert_eq!(protocol, Protocol::Udp);
        response.extend_from_slice(query);
        Action::Respond
    }
}

#[tokio::test]
async fn wildcard_listener_uses_one_dual_stack_address() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        return;
    }
    let listener = Listener::bind("[::]:0".parse().unwrap(), Echo)
        .await
        .unwrap();
    let address = listener.local_addr();
    assert!(
        address.is_ipv6(),
        "wildcard must use an IPv6 socket: {address}"
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(b"query", ("127.0.0.1", address.port()))
        .await
        .unwrap();
    let mut response = [0; 32];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response[..len], b"query");
    listener.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_queries_receive_responses() {
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Echo)
        .await
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(b"query", listener.local_addr())
        .await
        .unwrap();
    let mut buf = [0; 32];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"query");
    listener.shutdown().await.unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn queued_queries_return_to_their_own_clients() {
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Echo)
        .await
        .unwrap();
    let mut clients = Vec::new();
    for id in 0..32_u8 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        for sequence in 0..2_u8 {
            socket
                .send_to(&[id, sequence], listener.local_addr())
                .unwrap();
        }
        clients.push(UdpSocket::from_std(socket).unwrap());
    }
    for (id, client) in clients.iter().enumerate() {
        let mut seen = [false; 2];
        for _ in 0..2 {
            let mut response = [0; 2];
            let (length, peer) =
                tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(peer, listener.local_addr());
            assert_eq!(length, 2);
            assert_eq!(response[0], id as u8);
            seen[usize::from(response[1])] = true;
        }
        assert_eq!(seen, [true, true]);
    }
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn registry_keeps_a_listener_by_transport_and_address() {
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Echo)
        .await
        .unwrap();
    let key = ListenerKey {
        transport: Transport::Dns,
        address: listener.local_addr(),
    };
    let mut registry = ListenerRegistry::default();
    assert!(registry.insert(key, listener).is_none());
    assert_eq!(registry.get(&key).unwrap().local_addr(), key.address);
    let listener = registry.remove(&key).unwrap();
    assert!(registry.get(&key).is_none());
    listener.shutdown().await.unwrap();
}

struct Oversized;

impl Handler for Oversized {
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        if query == b"large" {
            response.resize(65536, 0);
        } else {
            response.extend_from_slice(query);
        }
        Action::Respond
    }
}

#[tokio::test]
async fn oversized_response_does_not_stop_worker() {
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Oversized)
        .await
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(listener.local_addr()).await.unwrap();
    socket.send(b"large").await.unwrap();
    socket.send(b"valid").await.unwrap();
    let mut buf = [0; 32];
    let n = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"valid");
    listener.shutdown().await.unwrap();
}
