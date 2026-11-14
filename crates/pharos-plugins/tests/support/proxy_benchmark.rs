#![forbid(unsafe_code)]

// Run with: cargo test --release -p pharos-plugins --test proxy_throughput -- --nocapture
// The fake upstream delays every response asynchronously by 10 ms. The results
// measure concurrency under upstream latency, not maximum loopback throughput.

use std::{sync::Arc, time::Instant};

use pharos_plugins::proxy::{Options, Proxy, Transport};
use tokio::{net::UdpSocket, sync::Barrier, time::Duration};

// RFC 1035 §4.1.1: Header ID, flags, and counts identify a DNS query or response.
const QUERY: &[u8] = &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];
const REQUESTS: usize = 128;
const CONCURRENCY: usize = 16;
const DELAY: Duration = Duration::from_millis(10);

async fn measure(proxy: Arc<Proxy>, concurrency: usize) -> Duration {
    let ready = Arc::new(Barrier::new(concurrency + 1));
    let start = Arc::new(Barrier::new(concurrency + 1));
    let mut workers = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let proxy = Arc::clone(&proxy);
        let ready = Arc::clone(&ready);
        let start = Arc::clone(&start);
        workers.push(tokio::spawn(async move {
            let mut response = [0; 512];
            proxy
                // RFC 1035 §4.2.1: Send the benchmark query over UDP.
                .exchange(QUERY, &mut response, Transport::Udp, Options::default())
                .await
                .unwrap();
            ready.wait().await;
            start.wait().await;
            for _ in 0..REQUESTS / concurrency {
                proxy
                    .exchange(QUERY, &mut response, Transport::Udp, Options::default())
                    .await
                    .unwrap();
            }
        }));
    }
    ready.wait().await;
    let began = Instant::now();
    start.wait().await;
    for worker in workers {
        worker.await.unwrap();
    }
    began.elapsed()
}

#[test]
fn proxy_throughput() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let proxy = Arc::new(Proxy::new(socket.local_addr().unwrap()));
        let upstream = tokio::spawn(async move {
            loop {
                let mut wire = [0; 512];
                let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
                // RFC 1035 §4.1.1: QR distinguishes a DNS response from a query.
                wire[2] |= 0x80;
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    tokio::time::sleep(DELAY).await;
                    socket.send_to(&wire[..len], peer).await.unwrap();
                });
            }
        });

        let single = tokio::time::timeout(Duration::from_secs(15), measure(Arc::clone(&proxy), 1))
            .await
            .unwrap();
        let parallel = tokio::time::timeout(Duration::from_secs(15), measure(proxy, CONCURRENCY))
            .await
            .unwrap();
        println!(
            "UDP fake upstream: {DELAY:?} asynchronous response delay; {REQUESTS} requests per run"
        );
        for (concurrency, elapsed) in [(1, single), (CONCURRENCY, parallel)] {
            println!(
                "concurrency {concurrency}: {elapsed:?}, {:.1} requests/s",
                REQUESTS as f64 / elapsed.as_secs_f64()
            );
        }
        println!(
            "throughput ratio: {:.2}x",
            single.as_secs_f64() / parallel.as_secs_f64()
        );
        upstream.abort();
    });
}
