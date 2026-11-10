#![forbid(unsafe_code)]

use std::{net::SocketAddr, time::Duration};

use pharos_server::{
    Action, Handler, Listener, ListenerKey, ListenerRegistry, Protocol, Transport,
};
use tokio::net::UdpSocket;

struct Echo;

struct AsyncEcho;

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
