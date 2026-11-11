#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-shed", feature = "plugin-whoami"))]
#![recursion_limit = "512"]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_proto::Message;
use pharos_server::{Listener, ListenerRegistry};
use tokio::{
    net::UdpSocket,
    time::{Duration, timeout},
};

#[tokio::test]
async fn shed_listener_returns_normal_udp_responses_and_metrics() {
    let text = ".:0 {\n shed\n whoami\n}";
    let blocks = configure::<Chain>(&parse("Corefile", text).unwrap(), directives()).unwrap();
    let (mut servers, _) = servers(blocks).unwrap();
    let (_, mut server) = servers.drain().next().unwrap();
    server.udp_workers = 1;
    let registry = server.metrics().clone();
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), server)
        .await
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";
    socket.send_to(query, listener.local_addr()).await.unwrap();
    let mut response = [0; 512];
    let (length, _) = timeout(Duration::from_secs(3), socket.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(Message::parse(&response[..length]).unwrap().id(), 0x1234);
    let mut metrics = String::new();
    registry.encode(&mut metrics);
    assert!(
        metrics.contains("pharos_shed_dropped_total{reason=\"query\",server=\"dns://:0\"} 0"),
        "{metrics}"
    );
    assert!(
        metrics.contains("pharos_shed_dropped_total{reason=\"response\",server=\"dns://:0\"} 0"),
        "{metrics}"
    );
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn reload_replaces_udp_workers_when_shed_changes() {
    let make_servers = |directive: &str| {
        let text = format!(".:0 {{\n {directive}\n whoami\n}}");
        let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
        let (mut servers, _) = servers(blocks).unwrap();
        for server in servers.values_mut() {
            server.udp_workers = 1;
        }
        servers
    };
    let initial = make_servers("");
    let key = *initial.keys().next().unwrap();
    let mut listeners = ListenerRegistry::default();
    listeners.apply(initial).await.unwrap();
    let port = listeners.get(&key).unwrap().local_addr().port();
    let destination = format!("127.0.0.1:{port}");
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";
    for directive in ["shed", ""] {
        listeners.apply(make_servers(directive)).await.unwrap();
        let mut response = [0; 512];
        let (length, _) = timeout(Duration::from_secs(3), async {
            loop {
                socket.send_to(query, &destination).await.unwrap();
                if let Ok(result) =
                    timeout(Duration::from_millis(50), socket.recv_from(&mut response)).await
                {
                    break result.unwrap();
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(Message::parse(&response[..length]).unwrap().id(), 0x1234);
    }
    listeners.shutdown().await.unwrap();
}
