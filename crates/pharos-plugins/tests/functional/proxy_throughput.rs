#![forbid(unsafe_code)]

// Run the measurement with: cargo test --release -p pharos-plugins --test proxy_throughput -- --nocapture
#[path = "../support/proxy_benchmark.rs"]
mod benchmark;

use pharos_plugins::proxy::{Options, Proxy, Transport};
use tokio::{net::UdpSocket, time::Duration};

const QUERY: &[u8] = &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];

#[tokio::test]
async fn concurrent_queries_reach_upstream_before_either_response() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let proxy = Proxy::new(socket.local_addr().unwrap());
    let upstream = tokio::spawn(async move {
        let mut first = [0; 512];
        let mut second = [0; 512];
        let (first_len, first_peer) = socket.recv_from(&mut first).await.unwrap();
        let (second_len, second_peer) =
            tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut second))
                .await
                .expect("second query was blocked waiting for the first response")
                .unwrap();
        first[2] |= 0x80;
        second[2] |= 0x80;
        socket
            .send_to(&first[..first_len], first_peer)
            .await
            .unwrap();
        socket
            .send_to(&second[..second_len], second_peer)
            .await
            .unwrap();
    });
    let mut first = [0; 512];
    let mut second = [0; 512];
    let (first_result, second_result) = tokio::join!(
        proxy.exchange(QUERY, &mut first, Transport::Udp, Options::default()),
        proxy.exchange(QUERY, &mut second, Transport::Udp, Options::default()),
    );
    upstream.await.unwrap();
    assert_eq!(first_result.unwrap().len, QUERY.len());
    assert_eq!(second_result.unwrap().len, QUERY.len());
}
