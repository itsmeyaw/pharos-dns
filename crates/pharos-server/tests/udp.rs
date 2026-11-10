#![forbid(unsafe_code)]

use std::{net::SocketAddr, time::Duration};

use pharos_server::{Action, Handler, Listener, Protocol};
use tokio::net::UdpSocket;

struct Echo;

impl Handler for Echo {
    fn handle(
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
