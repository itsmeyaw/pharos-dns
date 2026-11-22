//! Ported from CoreDNS v1.15.0 plugin/dnstap/listener_test.go, with real sockets instead of mock connections.
use std::net::SocketAddr;

use pharos_server::tls::{ClientOptions, ServerName, TlsConnector, client_config};
use tokio::{io::AsyncReadExt, net::UnixStream};

use super::*;
use crate::dnstap::{
    Role, TlsFiles,
    testing::{Collector, Frame, config, eventually, metric, query, tap},
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

fn listening(endpoint: Endpoint) -> Config {
    Config {
        role: Role::Listen,
        ..config(endpoint)
    }
}

struct Running {
    tap: Tap,
    registry: pharos_server::metrics::Registry,
    address: SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    async fn tcp(config: Config) -> Self {
        let (tap, registry, _) = tap(config);
        let bound = bind(&tap.0.config).await.unwrap().unwrap();
        let address = bound.local_address().unwrap();
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(run(tap.clone(), Some(bound), stopped));
        Self {
            tap,
            registry,
            address,
            stop,
            task,
        }
    }

    async fn collector(&self) -> Collector<TcpStream> {
        let tcp = TcpStream::connect(self.address).await.unwrap();
        Collector::accept(tcp).await.unwrap()
    }

    async fn sinks(&self, count: u64) {
        eventually(|| metric(&self.registry, "pharos_dnstap_connected") == count).await;
    }

    async fn stop(self) {
        self.stop.send(true).unwrap();
        self.task.await.unwrap();
    }
}

// TestListenerBroadcast: every connected collector receives every message, in order.
#[tokio::test]
async fn broadcasts_to_every_collector() {
    let running = Running::tcp(listening(Endpoint::Tcp("127.0.0.1:0".into()))).await;
    let mut first = running.collector().await;
    let mut second = running.collector().await;
    running.sinks(2).await;
    for number in 1..=3 {
        running.tap.send(&query(number));
    }
    for collector in [&mut first, &mut second] {
        for number in 1..=3 {
            assert_eq!(collector.number().await, number);
        }
    }
    assert_eq!(
        metric(&running.registry, "pharos_dnstap_messages_written_total"),
        6
    );
    running.stop().await;
}

// TestListenerBroadcast: with no collector connected `send` skips the message, so a later collector sees only later ones.
#[tokio::test]
async fn messages_before_a_collector_connects_are_not_kept() {
    let running = Running::tcp(listening(Endpoint::Tcp("127.0.0.1:0".into()))).await;
    running.tap.send(&query(1));
    let mut collector = running.collector().await;
    running.sinks(1).await;
    running.tap.send(&query(2));
    assert_eq!(collector.number().await, 2);
    running.stop().await;
}

// TestListenerDnstapFlushErrorNoDeadlock: a collector that goes away is removed and the others keep receiving.
#[tokio::test]
async fn a_failing_collector_is_closed_alone() {
    let running = Running::tcp(listening(Endpoint::Tcp("127.0.0.1:0".into()))).await;
    let gone = running.collector().await;
    let mut kept = running.collector().await;
    running.sinks(2).await;
    drop(gone);
    // The broken connection is noticed by a write that fails; keep sending until it is removed.
    let mut number = 0_u16;
    eventually(|| {
        number += 1;
        running.tap.send(&query(number));
        metric(&running.registry, "pharos_dnstap_connected") == 1
    })
    .await;
    let last = number;
    // Frames are written and flushed per batch, so the kept collector has all of them.
    for expected in 1..=u64::from(last) {
        assert_eq!(kept.number().await, expected);
    }
    running.tap.send(&query(1000));
    assert_eq!(kept.number().await, 1000);
    running.stop().await;
}

// TestListenerClose: stopping sends STOP to every collector and flushes what was queued before it.
#[tokio::test]
async fn stop_flushes_and_closes_every_collector() {
    let running = Running::tcp(listening(Endpoint::Tcp("127.0.0.1:0".into()))).await;
    let collectors = [running.collector().await, running.collector().await];
    running.sinks(2).await;
    running.tap.send(&query(5));
    let registry = running.registry.clone();
    let reading = collectors.map(|mut collector| {
        tokio::spawn(async move {
            let number = collector.number().await;
            (number, collector.frame().await.unwrap())
        })
    });
    running.stop().await;
    for reader in reading {
        assert_eq!(reader.await.unwrap(), (5, Frame::Stop));
    }
    assert_eq!(metric(&registry, "pharos_dnstap_connected"), 0);
}

// listener.go acceptLoop: a client that never completes the Frame Streams handshake does not hold up the others.
#[tokio::test]
async fn a_silent_client_does_not_block_others() {
    let running = Running::tcp(listening(Endpoint::Tcp("127.0.0.1:0".into()))).await;
    let _silent = TcpStream::connect(running.address).await.unwrap();
    let mut collector = running.collector().await;
    running.sinks(1).await;
    running.tap.send(&query(3));
    assert_eq!(collector.number().await, 3);
    running.stop().await;
}

// Pharos hardening: handshakes in flight are capped, and a peer beyond the cap is closed at once.
#[tokio::test]
async fn peers_beyond_the_handshake_cap_are_closed_at_once() {
    let running = Running::tcp(listening(Endpoint::Tcp("127.0.0.1:0".into()))).await;
    let mut silent = Vec::new();
    for _ in 0..MAX_HANDSHAKES {
        silent.push(TcpStream::connect(running.address).await.unwrap());
    }
    let mut excess = TcpStream::connect(running.address).await.unwrap();
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_millis(400), excess.read(&mut byte))
        .await
        .expect("excess peer is closed before the handshakes time out");
    assert!(matches!(closed, Ok(0) | Err(_)));
    // Once the silent handshakes time out their slots are free again.
    drop(silent);
    let mut collector = loop {
        let tcp = TcpStream::connect(running.address).await.unwrap();
        if let Ok(collector) = Collector::accept(tcp).await {
            break collector;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    running.sinks(1).await;
    running.tap.send(&query(9));
    assert_eq!(collector.number().await, 9);
    running.stop().await;
}

// listener.go listen: `unix` endpoints serve over a socket file that is removed on close, as Go's listener does.
#[tokio::test]
async fn unix_listener_starts_and_removes_its_socket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dnstap.sock");
    let (tap, registry, _) = tap(listening(Endpoint::Unix(
        path.to_string_lossy().into_owned(),
    )));
    tap.start().await;
    let mut collector = Collector::accept(UnixStream::connect(&path).await.unwrap())
        .await
        .unwrap();
    eventually(|| metric(&registry, "pharos_dnstap_connected") == 1).await;
    tap.send(&query(8));
    assert_eq!(collector.number().await, 8);
    let stopped = tokio::spawn(async move { collector.frame().await.unwrap() });
    tap.stop().await;
    assert_eq!(stopped.await.unwrap(), Frame::Stop);
    assert!(!path.exists());
}

// listener.go close: stopping never leaves the socket file or the gauge behind, even when clients never answer STOP.
#[tokio::test]
async fn stop_with_clients_that_never_answer_stop_still_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dnstap.sock");
    let (tap, registry, _) = tap(listening(Endpoint::Unix(
        path.to_string_lossy().into_owned(),
    )));
    tap.start().await;
    // Closed one after another these would outlast the stop limit of three timeouts.
    let mut collectors = Vec::new();
    for _ in 0..4 {
        collectors.push(
            Collector::accept(UnixStream::connect(&path).await.unwrap())
                .await
                .unwrap(),
        );
    }
    eventually(|| metric(&registry, "pharos_dnstap_connected") == 4).await;
    let started = tokio::time::Instant::now();
    tap.stop().await;
    assert!(started.elapsed() < tap.0.timing.timeout * 2);
    assert!(!path.exists());
    assert_eq!(metric(&registry, "pharos_dnstap_connected"), 0);
}

// setup.go OnStartup: a listener that cannot start is logged, not fatal, and stopping afterwards is harmless.
#[tokio::test]
async fn bind_failure_only_logs() {
    let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = taken.local_addr().unwrap().to_string();
    let (tap, _, _) = tap(listening(Endpoint::Tcp(address)));
    tap.start().await;
    tap.stop().await;
}

// listener.go listen: `tls://` needs the Corefile's `tls` files; without them there is nothing to listen on.
#[tokio::test]
async fn tls_listener_without_files_does_not_bind() {
    let config = listening(Endpoint::Tls("127.0.0.1:0".into()));
    assert!(bind(&config).await.unwrap().is_none());
}

fn tls_listening(ca: bool, skip_verify: bool) -> Config {
    let mut config = listening(Endpoint::Tls("127.0.0.1:0".into()));
    config.skip_verify = skip_verify;
    config.tls = Some(TlsFiles {
        cert: format!("{FIXTURES}/server.pem"),
        key: format!("{FIXTURES}/server.key.pem"),
        ca: ca.then(|| format!("{FIXTURES}/ca.pem")),
    });
    config
}

async fn tls_collector(
    running: &Running,
    identity: bool,
) -> std::io::Result<Collector<pharos_server::tls::ClientStream<TcpStream>>> {
    let config = client_config(&ClientOptions {
        ca: Some(format!("{FIXTURES}/ca.pem").into()),
        identity: identity.then(|| {
            (
                format!("{FIXTURES}/client.pem").into(),
                format!("{FIXTURES}/client.key.pem").into(),
            )
        }),
    })?;
    let tcp = TcpStream::connect(running.address).await?;
    let stream = TlsConnector::from(config)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await?;
    Collector::accept(stream).await
}

// listener.go listen: without a CA file no client certificate is asked for.
#[tokio::test]
async fn tls_without_a_ca_accepts_any_client() {
    let running = Running::tcp(tls_listening(false, false)).await;
    let mut collector = tls_collector(&running, false).await.unwrap();
    running.sinks(1).await;
    running.tap.send(&query(4));
    assert_eq!(collector.number().await, 4);
    running.stop().await;
}

// listener.go listen: a CA file requires and verifies client certificates.
#[tokio::test]
async fn tls_with_a_ca_requires_a_client_certificate() {
    let running = Running::tcp(tls_listening(true, false)).await;
    assert!(tls_collector(&running, false).await.is_err());
    let mut collector = tls_collector(&running, true).await.unwrap();
    running.sinks(1).await;
    running.tap.send(&query(6));
    assert_eq!(collector.number().await, 6);
    running.stop().await;
}

// listener.go listen: with `skipverify` a client certificate is verified only when presented.
#[tokio::test]
async fn tls_with_a_ca_and_skipverify_makes_the_certificate_optional() {
    let running = Running::tcp(tls_listening(true, true)).await;
    let mut collector = tls_collector(&running, false).await.unwrap();
    running.sinks(1).await;
    running.tap.send(&query(7));
    assert_eq!(collector.number().await, 7);
    running.stop().await;
}
