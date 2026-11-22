#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-dnstap", feature = "plugin-whoami"))]

use std::{
    alloc::System,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use pharos_corefile::{configure, parse};
use pharos_plugins::{
    Chain, directives,
    dnstap::framestream::{CONTENT_TYPE, ControlType, read_control},
    servers_with_registry,
};
use pharos_server::{Action, Handler, Lifecycle, Phase, Protocol, metrics::Registry};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    time::sleep,
};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
const QUERIES: usize = 50;
// The dnstap Plugin sends a CLIENT_QUERY and a CLIENT_RESPONSE per Query.
const MESSAGES: usize = 2 * QUERIES;
// `queue` 1 holds 10,000 messages.
const QUEUE: usize = 10_000;
const QUERY: [u8; 29] = [
    0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'o', b'r',
    b'g', 0, 0, 1, 0, 1,
];

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn server(corefile: &str) -> (impl Handler, Lifecycle) {
    let blocks = parse("Corefile", corefile).unwrap();
    let (mut servers, lifecycle) = servers_with_registry(
        configure::<Chain>(&blocks, directives()).unwrap(),
        Registry::new("test", "test", "test"),
    )
    .unwrap();
    (servers.drain().next().unwrap().1, lifecycle)
}

// Counts the data frames a dnstap collector receives, after the Frame Streams handshake.
async fn collect(listener: UnixListener, frames: Arc<AtomicUsize>) {
    let (mut stream, _) = listener.accept().await.unwrap();
    read_control(&mut stream).await.unwrap();
    let mut accept = 0_u32.to_be_bytes().to_vec();
    accept.extend(((4 + 8 + CONTENT_TYPE.len()) as u32).to_be_bytes());
    accept.extend((ControlType::Accept as u32).to_be_bytes());
    accept.extend(1_u32.to_be_bytes());
    accept.extend((CONTENT_TYPE.len() as u32).to_be_bytes());
    accept.extend(CONTENT_TYPE);
    stream.write_all(&accept).await.unwrap();
    read_control(&mut stream).await.unwrap();
    loop {
        let length = stream.read_u32().await.unwrap();
        let mut payload = vec![0; length as usize];
        stream.read_exact(&mut payload).await.unwrap();
        frames.fetch_add(1, Ordering::SeqCst);
    }
}

async fn ask(server: &impl Handler, response: &mut Vec<u8>) {
    response.clear();
    assert_eq!(
        server
            .handle(
                &QUERY,
                "192.0.2.7:5353".parse().unwrap(),
                Protocol::Udp,
                response,
            )
            .await,
        Action::Respond
    );
}

// Dropping at the queue's bound allocates nothing either: it is the overload path.
#[test]
fn a_full_queue_drops_without_allocating() {
    if crate::run_isolated("dnstap::dnstap_allocations::a_full_queue_drops_without_allocating") {
        return;
    }
    // No Startup: nothing drains the queue.
    let (server, _) = server(".:0 {\n dnstap /nonexistent/dnstap.sock full\n whoami\n}");
    runtime().block_on(async {
        let mut response = Vec::with_capacity(65535);
        for _ in 0..QUEUE / 2 {
            ask(&server, &mut response).await;
        }
        let region = Region::new(GLOBAL);
        for _ in 0..QUERIES {
            ask(&server, &mut response).await;
        }
        let stats = region.change();
        assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    });
}

// A warm pool of slots: the writer returned them, so a Query takes two and encodes into them.
#[test]
fn a_warmed_enqueue_allocates_nothing() {
    if crate::run_isolated("dnstap::dnstap_allocations::a_warmed_enqueue_allocates_nothing") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dnstap.sock");
    let (server, lifecycle) = server(&format!(
        ".:0 {{\n dnstap {} full\n whoami\n}}",
        path.display()
    ));
    runtime().block_on(async {
        let frames = Arc::new(AtomicUsize::new(0));
        tokio::spawn(collect(
            UnixListener::bind(&path).unwrap(),
            Arc::clone(&frames),
        ));
        lifecycle.run(Phase::Startup).await.unwrap();
        let mut response = Vec::with_capacity(65535);
        // The queue and the writer swap their two batch buffers, so it takes two rounds for both to be grown.
        for round in 1..=2 {
            for _ in 0..QUERIES {
                ask(&server, &mut response).await;
            }
            // The writer flushes every second; once the collector has them all the slots are free again.
            for _ in 0..500 {
                if frames.load(Ordering::SeqCst) == round * MESSAGES {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(frames.load(Ordering::SeqCst), round * MESSAGES);
        }

        let region = Region::new(GLOBAL);
        for _ in 0..QUERIES {
            ask(&server, &mut response).await;
        }
        let stats = region.change();
        assert_eq!((stats.allocations, stats.reallocations), (0, 0));
    });
}
