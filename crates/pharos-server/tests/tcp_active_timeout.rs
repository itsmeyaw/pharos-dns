#![forbid(unsafe_code)]

use pharos_server::{Action, Handler, Listener, Protocol, TcpOptions};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

struct Slow(AtomicUsize);
impl Handler for Slow {
    fn udp_workers(&self) -> usize {
        1
    }
    fn tcp_options(&self) -> TcpOptions {
        TcpOptions {
            idle: Duration::from_secs(1),
            ..TcpOptions::default()
        }
    }
    async fn handle(
        &self,
        query: &[u8],
        _: SocketAddr,
        _: Protocol,
        response: &mut Vec<u8>,
    ) -> Action {
        if self.0.fetch_add(1, Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }
        response.extend_from_slice(query);
        Action::Respond
    }
}

#[tokio::test]
async fn idle_timeout_starts_after_active_query_finishes() {
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), Slow(AtomicUsize::new(0)))
        .await
        .unwrap();
    let mut tcp = TcpStream::connect(listener.local_addr()).await.unwrap();
    for _ in 0..2 {
        tcp.write_u16(2).await.unwrap();
        tcp.write_all(b"ok").await.unwrap();
        let length = timeout(Duration::from_secs(3), tcp.read_u16())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(length, 2);
        let mut response = [0; 2];
        tcp.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
    }
    listener.shutdown().await.unwrap();
}
