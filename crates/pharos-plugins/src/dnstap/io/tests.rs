//! Ported from CoreDNS v1.15.0 plugin/dnstap/io_test.go, plus the writer behaviour Pharos adds.
use std::{path::Path, time::Duration};

use tokio::net::{TcpListener, UnixListener};

use super::*;
use crate::dnstap::testing::{Collector, Frame, config, eventually, metric, query, tap};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");

fn unix(dir: &Path) -> (UnixListener, Endpoint) {
    let path = dir.join("dnstap.sock");
    let listener = UnixListener::bind(&path).unwrap();
    (
        listener,
        Endpoint::Unix(path.to_string_lossy().into_owned()),
    )
}

async fn tcp() -> (TcpListener, Endpoint) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint::Tcp(listener.local_addr().unwrap().to_string());
    (listener, endpoint)
}

// TestTransport: one message reaches a collector over TCP and over a Unix socket, after the Frame Streams handshake.
#[tokio::test]
async fn transport_delivers_over_tcp_and_unix() {
    let dir = tempfile::tempdir().unwrap();
    let (tcp_listener, tcp_endpoint) = tcp().await;
    let (unix_listener, unix_endpoint) = unix(dir.path());
    let tcp_task = tokio::spawn(async move {
        let mut collector = Collector::accept(tcp_listener.accept().await.unwrap().0)
            .await
            .unwrap();
        let number = collector.number().await;
        assert_eq!(collector.frame().await.unwrap(), Frame::Stop);
        number
    });
    let unix_task = tokio::spawn(async move {
        let mut collector = Collector::accept(unix_listener.accept().await.unwrap().0)
            .await
            .unwrap();
        let number = collector.number().await;
        assert_eq!(collector.frame().await.unwrap(), Frame::Stop);
        number
    });
    for (endpoint, number) in [(tcp_endpoint, 11), (unix_endpoint, 22)] {
        let (tap, registry, _) = tap(config(endpoint));
        tap.start().await;
        eventually(|| metric(&registry, "pharos_dnstap_connected") == 1).await;
        tap.send(&query(number));
        tap.stop().await;
    }
    assert_eq!(tcp_task.await.unwrap(), 11);
    assert_eq!(unix_task.await.unwrap(), 22);
}

// TestRace: messages from many threads all arrive.
#[tokio::test]
async fn concurrent_senders_all_arrive() {
    let (listener, endpoint) = tcp().await;
    let collector = tokio::spawn(async move {
        let mut collector = Collector::accept(listener.accept().await.unwrap().0)
            .await
            .unwrap();
        let mut seen = Vec::new();
        for _ in 0..10 {
            seen.push(collector.number().await);
        }
        seen.sort_unstable();
        seen
    });
    let (tap, _, _) = tap(config(endpoint));
    tap.start().await;
    std::thread::scope(|scope| {
        for number in 1..=10 {
            let tap = tap.clone();
            scope.spawn(move || tap.send(&query(number)));
        }
    });
    assert_eq!(collector.await.unwrap(), (1..=10).collect::<Vec<_>>());
    tap.stop().await;
}

// Frame Streams: stop sends STOP and waits for FINISH, and what was queued before it is written first.
#[tokio::test]
async fn stop_flushes_the_queue_then_closes_the_stream() {
    let (listener, endpoint) = tcp().await;
    let (tap, registry, _) = tap(config(endpoint));
    tap.start().await;
    let collector = tokio::spawn(async move {
        let mut collector = Collector::accept(listener.accept().await.unwrap().0)
            .await
            .unwrap();
        let mut frames = Vec::new();
        loop {
            match collector.frame().await.unwrap() {
                Frame::Data(payload) => frames.push(payload),
                Frame::Stop => return frames.len(),
            }
        }
    });
    eventually(|| metric(&registry, "pharos_dnstap_connected") == 1).await;
    for number in 1..=3 {
        tap.send(&query(number));
    }
    tap.stop().await;
    assert_eq!(collector.await.unwrap(), 3);
    assert_eq!(metric(&registry, "pharos_dnstap_messages_written_total"), 3);
    assert_eq!(metric(&registry, "pharos_dnstap_connected"), 0);
}

// TestReconnect/ConnectedOnStart: after the collector goes away and comes back on the same address, messages flow again.
#[tokio::test]
async fn reconnects_after_the_collector_restarts() {
    let (listener, endpoint) = tcp().await;
    let Endpoint::Tcp(address) = endpoint.clone() else {
        unreachable!()
    };
    let (tap, registry, warnings) = tap(config(endpoint));
    tap.start().await;
    let mut first = Collector::accept(listener.accept().await.unwrap().0)
        .await
        .unwrap();
    tap.send(&query(1));
    assert_eq!(first.number().await, 1);
    drop((first, listener));

    let listener = TcpListener::bind(&address).await.unwrap();
    let accepted = tokio::spawn(async move {
        Collector::accept(listener.accept().await.unwrap().0)
            .await
            .unwrap()
    });
    let sent = 5;
    for number in 2..2 + sent {
        tokio::time::sleep(Duration::from_millis(40)).await;
        tap.send(&query(number));
    }
    let mut second = accepted.await.unwrap();
    // The first frames after the break may be lost to the dead connection; later ones arrive.
    assert!(second.number().await >= 2);
    assert!(warnings.lock().unwrap().len() < sent as usize);
    assert_eq!(metric(&registry, "pharos_dnstap_reconnects_total"), 1);
    tap.stop().await;
}

// TestReconnect/NotConnectedOnStart: a collector that appears after startup is found by the retry loop.
#[tokio::test]
async fn dials_a_collector_that_appears_later() {
    let (probe, endpoint) = tcp().await;
    let Endpoint::Tcp(address) = endpoint.clone() else {
        unreachable!()
    };
    drop(probe);
    let (tap, registry, warnings) = tap(config(endpoint));
    tap.start().await;
    tap.send(&query(1));
    eventually(|| metric(&registry, "pharos_dnstap_connect_failures_total") >= 1).await;

    let listener = TcpListener::bind(&address).await.unwrap();
    let accepted = tokio::spawn(async move {
        Collector::accept(listener.accept().await.unwrap().0)
            .await
            .unwrap()
    });
    let sent = 5;
    for number in 2..2 + sent {
        tokio::time::sleep(Duration::from_millis(40)).await;
        tap.send(&query(number));
    }
    let mut collector = accepted.await.unwrap();
    assert!(collector.number().await >= 2);
    assert!(warnings.lock().unwrap().len() < sent as usize);
    // The first connection is not a reconnect.
    assert_eq!(metric(&registry, "pharos_dnstap_reconnects_total"), 0);
    tap.stop().await;
}

// TestFullQueueWriteFail: a full queue drops, counts and warns.
#[tokio::test]
async fn full_queue_drops_and_warns() {
    let dir = tempfile::tempdir().unwrap();
    let (_listener, endpoint) = unix(dir.path());
    // Not started: nothing drains the queue.
    let (tap, registry, warnings) = tap(config(endpoint));
    let capacity = 10_000;
    for _ in 0..capacity + 100 {
        tap.send(&query(1));
    }
    assert_eq!(
        metric(&registry, "pharos_dnstap_messages_enqueued_total"),
        capacity
    );
    assert_eq!(
        metric(
            &registry,
            "pharos_dnstap_messages_dropped_total{reason=\"queue_full\"}"
        ),
        100
    );
    tap.report_drops();
    assert_eq!(*warnings.lock().unwrap(), ["Dropped dnstap messages: 100"]);
    tap.report_drops();
    assert_eq!(
        warnings.lock().unwrap().len(),
        1,
        "a report resets the count"
    );
}

// io.go dio.write: with no connection a dequeued message is dropped, and the drops are warned about every report interval.
#[tokio::test]
async fn messages_without_a_collector_are_dropped_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    let (tap, registry, warnings) = tap(config(Endpoint::Unix(
        dir.path()
            .join("absent.sock")
            .to_string_lossy()
            .into_owned(),
    )));
    tap.start().await;
    eventually(|| metric(&registry, "pharos_dnstap_connect_failures_total") >= 1).await;
    for number in 1..=3 {
        tap.send(&query(number));
    }
    eventually(|| {
        metric(
            &registry,
            "pharos_dnstap_messages_dropped_total{reason=\"no_connection\"}",
        ) == 3
    })
    .await;
    eventually(|| {
        warnings
            .lock()
            .unwrap()
            .iter()
            .any(|text| text.contains("Dropped dnstap messages: 3"))
    })
    .await;
    assert_eq!(metric(&registry, "pharos_dnstap_messages_written_total"), 0);
    tap.stop().await;
}

// A failed first dial only logs and the writer keeps retrying; stopping then does not wait on the dial.
#[tokio::test]
async fn stop_returns_promptly_while_no_collector_is_reachable() {
    let dir = tempfile::tempdir().unwrap();
    let (tap, _, _) = tap(config(Endpoint::Unix(
        dir.path()
            .join("absent.sock")
            .to_string_lossy()
            .into_owned(),
    )));
    tap.start().await;
    tokio::time::timeout(Duration::from_secs(1), tap.stop())
        .await
        .unwrap();
}

#[tokio::test]
async fn start_and_stop_are_idempotent_and_restartable() {
    let (listener, endpoint) = tcp().await;
    let (tap, registry, _) = tap(config(endpoint));
    tap.start().await;
    tap.start().await;
    let mut first = Collector::accept(listener.accept().await.unwrap().0)
        .await
        .unwrap();
    let stopped = tokio::spawn(async move { first.frame().await.unwrap() });
    eventually(|| metric(&registry, "pharos_dnstap_connected") == 1).await;
    tap.stop().await;
    assert_eq!(stopped.await.unwrap(), Frame::Stop);
    tap.stop().await;
    // A failed reload restarts the old taps.
    tap.start().await;
    let mut second = Collector::accept(listener.accept().await.unwrap().0)
        .await
        .unwrap();
    tap.send(&query(7));
    assert_eq!(second.number().await, 7);
    let stopped = tokio::spawn(async move { second.frame().await.unwrap() });
    tap.stop().await;
    assert_eq!(stopped.await.unwrap(), Frame::Stop);
}

// golang-framestream Encoder: a collector that does not complete the handshake is a failed dial.
#[tokio::test]
async fn a_silent_collector_is_a_failed_dial() {
    let (listener, endpoint) = tcp().await;
    let (tap, registry, _) = tap(config(endpoint));
    tap.start().await;
    let (_silent, _) = listener.accept().await.unwrap();
    // The handshake limit is `Timing::timeout`; the dial fails and is retried with backoff.
    eventually(|| metric(&registry, "pharos_dnstap_connect_failures_total") >= 1).await;
    assert_eq!(metric(&registry, "pharos_dnstap_connected"), 0);
    tap.stop().await;
}

#[tokio::test]
async fn tls_with_skipverify_connects_without_it_does_not() {
    let acceptor = pharos_server::tls::ServerTls::load(&pharos_server::tls::ServerOptions {
        cert: format!("{FIXTURES}/server.pem").into(),
        key: format!("{FIXTURES}/server.key.pem").into(),
        ca: None,
        client_auth: pharos_server::tls::ClientAuth::NoCert,
        keylog: None,
    })
    .unwrap()
    .acceptor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let collector = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let Ok(stream) = acceptor.accept(tcp).await else {
                continue;
            };
            if let Ok(mut collector) = Collector::accept(stream).await {
                return collector.number().await;
            }
        }
    });

    // The certificate chains to a private CA, so system roots reject it.
    let (verifying, registry, _) = tap(config(Endpoint::Tls(address.clone())));
    verifying.start().await;
    eventually(|| metric(&registry, "pharos_dnstap_connect_failures_total") >= 1).await;
    verifying.stop().await;
    assert!(!collector.is_finished());

    let mut skipping = config(Endpoint::Tls(address));
    skipping.skip_verify = true;
    let (skipping, _, _) = tap(skipping);
    skipping.start().await;
    skipping.send(&query(9));
    assert_eq!(collector.await.unwrap(), 9);
    skipping.stop().await;
}

// CoreDNS retries every 10 s; Pharos doubles the wait up to a ceiling and starts over after a success.
#[test]
fn backoff_doubles_to_the_ceiling_and_resets() {
    let mut backoff = Backoff::new(Duration::from_millis(100), Duration::from_secs(10));
    let waits: Vec<_> = (0..9).map(|_| backoff.failed().as_millis()).collect();
    assert_eq!(
        waits,
        [100, 200, 400, 800, 1600, 3200, 6400, 10_000, 10_000]
    );
    backoff.reset();
    assert_eq!(backoff.failed(), Duration::from_millis(100));
}

// io.go dial: the socket send buffer is `writebuffer` MiB; the kernel may clamp it.
#[tokio::test]
async fn writebuffer_sets_the_send_buffer() {
    let socket = TcpSocket::new_v4().unwrap();
    let before = socket.send_buffer_size().unwrap();
    set_send_buffer(&socket, 1);
    assert!(socket.send_buffer_size().unwrap() > before);
}

#[test]
fn tls_server_name_is_the_host_of_the_address() {
    for (address, expected) in [
        ("collector.example:6000", "collector.example"),
        ("192.0.2.1:6000", "192.0.2.1"),
        ("[2001:db8::1]:6000", "2001:db8::1"),
    ] {
        assert_eq!(server_name(address).unwrap().to_str(), expected);
    }
}
