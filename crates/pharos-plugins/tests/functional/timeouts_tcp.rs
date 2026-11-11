#![forbid(unsafe_code)]
#![cfg(all(feature = "plugin-timeouts", feature = "plugin-whoami"))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::Listener;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Duration, timeout},
};

async fn listener(options: &str) -> Listener {
    let corefile = format!(".:0 {{\n timeouts {{\n {options}\n }}\n whoami\n}}");
    let blocks = parse("Corefile", &corefile).unwrap();
    let (servers, _) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let (_, server) = servers.into_iter().next().unwrap();
    Listener::bind("127.0.0.1:0".parse().unwrap(), server)
        .await
        .unwrap()
}

#[tokio::test]
async fn first_query_read_timeout_closes_idle_connection() {
    let listener = listener("read 1s\n idle 10s").await;
    let mut tcp = TcpStream::connect(listener.local_addr()).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(3), tcp.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn maximum_queries_closes_after_last_response() {
    let listener = listener("maxtcpqueries 1").await;
    let mut tcp = TcpStream::connect(listener.local_addr()).await.unwrap();
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";
    tcp.write_u16(query.len() as u16).await.unwrap();
    tcp.write_all(query).await.unwrap();
    let len = timeout(Duration::from_secs(3), tcp.read_u16())
        .await
        .unwrap()
        .unwrap();
    let mut wire = vec![0; usize::from(len)];
    tcp.read_exact(&mut wire).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(3), tcp.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    listener.shutdown().await.unwrap();
}

#[tokio::test]
async fn idle_timeout_applies_after_first_query() {
    let listener = listener("read 10s\n idle 1s").await;
    let mut tcp = TcpStream::connect(listener.local_addr()).await.unwrap();
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x03www\x07example\x03com\0\0\x01\0\x01";
    tcp.write_u16(query.len() as u16).await.unwrap();
    tcp.write_all(query).await.unwrap();
    let len = timeout(Duration::from_secs(3), tcp.read_u16())
        .await
        .unwrap()
        .unwrap();
    let mut wire = vec![0; usize::from(len)];
    tcp.read_exact(&mut wire).await.unwrap();
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(3), tcp.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    listener.shutdown().await.unwrap();
}
