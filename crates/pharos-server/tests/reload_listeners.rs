#![forbid(unsafe_code)]

use std::{collections::HashMap, net::SocketAddr, time::Duration};

use pharos_server::{Action, Handler, ListenerKey, ListenerRegistry, Protocol, Transport};
use tokio::net::UdpSocket;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Notify,
};

#[derive(Debug)]
struct Answer(u8);

impl Handler for Answer {
    async fn handle(&self, _: &[u8], _: SocketAddr, _: Protocol, response: &mut Vec<u8>) -> Action {
        response.push(self.0);
        Action::Respond
    }
}

async fn query(socket: &UdpSocket, address: SocketAddr) -> Option<u8> {
    socket.send_to(b"query", address).await.unwrap();
    let mut response = [0];
    tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut response))
        .await
        .ok()
        .map(|result| {
            result.unwrap();
            response[0]
        })
}

#[tokio::test]
async fn unchanged_listener_swaps_without_rebinding_and_removed_listener_stops() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let mut listeners = ListenerRegistry::default();
    listeners
        .apply(HashMap::from([(key, Answer(1))]))
        .await
        .unwrap();
    let address = listeners.get(&key).unwrap().local_addr();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(query(&client, address).await, Some(1));
    listeners
        .apply(HashMap::from([(key, Answer(2))]))
        .await
        .unwrap();
    assert_eq!(listeners.get(&key).unwrap().local_addr(), address);
    assert_eq!(query(&client, address).await, Some(2));
    listeners.apply::<Answer>(HashMap::new()).await.unwrap();
    assert!(listeners.get(&key).is_none());
    assert_eq!(query(&client, address).await, None);
}

#[tokio::test]
async fn failed_new_bind_keeps_existing_handler() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let mut listeners = ListenerRegistry::default();
    listeners
        .apply(HashMap::from([(key, Answer(1))]))
        .await
        .unwrap();
    let address = listeners.get(&key).unwrap().local_addr();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let blocked = ListenerKey {
        transport: Transport::Dns,
        address: occupied.local_addr().unwrap(),
    };
    let error = listeners
        .apply(HashMap::from([(key, Answer(2)), (blocked, Answer(3))]))
        .await
        .unwrap_err();
    assert!(error.to_string().contains(&blocked.address.to_string()));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    assert_eq!(query(&client, address).await, Some(1));
    listeners.apply::<Answer>(HashMap::new()).await.unwrap();
}

struct WaitingAnswer {
    value: u8,
    entered: std::sync::Arc<Notify>,
    resume: std::sync::Arc<Notify>,
    wait: bool,
}

impl Handler for WaitingAnswer {
    async fn handle(&self, _: &[u8], _: SocketAddr, _: Protocol, response: &mut Vec<u8>) -> Action {
        if self.wait {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        response.push(self.value);
        Action::Respond
    }
}

#[tokio::test]
async fn in_flight_query_finishes_with_old_handler() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let entered = std::sync::Arc::new(Notify::new());
    let resume = std::sync::Arc::new(Notify::new());
    let handler = |value, wait| WaitingAnswer {
        value,
        entered: entered.clone(),
        resume: resume.clone(),
        wait,
    };
    let mut listeners = ListenerRegistry::default();
    listeners
        .apply(HashMap::from([(key, handler(1, true))]))
        .await
        .unwrap();
    let address = listeners.get(&key).unwrap().local_addr();
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client.write_all(&[0, 1, 42]).await.unwrap();
    entered.notified().await;
    let retired = listeners
        .apply_with_keys(HashMap::from([(key, handler(2, false))]))
        .await
        .unwrap();
    assert_eq!(retired[0].key.address, address);
    assert!(std::sync::Arc::strong_count(&retired[0].handler) > 1);
    resume.notify_one();
    let mut frame = [0; 3];
    client.read_exact(&mut frame).await.unwrap();
    assert_eq!(frame, [0, 1, 1]);
    assert_eq!(std::sync::Arc::strong_count(&retired[0].handler), 1);
    client.write_all(&[0, 1, 42]).await.unwrap();
    client.read_exact(&mut frame).await.unwrap();
    assert_eq!(frame, [0, 1, 2]);
    drop(client);
    listeners
        .apply::<WaitingAnswer>(HashMap::new())
        .await
        .unwrap();
}

#[tokio::test]
async fn removed_listener_retires_without_blocking_on_inflight_query() {
    let key = ListenerKey {
        transport: Transport::Dns,
        address: "127.0.0.1:0".parse().unwrap(),
    };
    let entered = std::sync::Arc::new(Notify::new());
    let resume = std::sync::Arc::new(Notify::new());
    let mut listeners = ListenerRegistry::default();
    listeners
        .apply(HashMap::from([(
            key,
            WaitingAnswer {
                value: 1,
                entered: entered.clone(),
                resume: resume.clone(),
                wait: true,
            },
        )]))
        .await
        .unwrap();
    let address = listeners.get(&key).unwrap().local_addr();
    let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
    client.write_all(&[0, 1, 42]).await.unwrap();
    entered.notified().await;
    let retired = tokio::time::timeout(
        Duration::from_millis(500),
        listeners.apply_with_keys::<WaitingAnswer>(HashMap::new()),
    )
    .await
    .expect("removal blocked on an in-flight Query")
    .unwrap();
    assert_eq!(retired[0].key.address, address);
    resume.notify_one();
    let mut response = [0; 3];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0, 1, 1]);
    drop(client);
    for entry in retired {
        if let Some(task) = entry.shutdown {
            task.await.unwrap().unwrap();
        }
    }
}
