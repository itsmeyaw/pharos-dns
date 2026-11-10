#![cfg(feature = "plugin-ready")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::Phase;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn shared_address_serves_ready() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let input = format!("a.:0 {{\n ready {address}\n}}\nb.:0 {{\n ready {address}\n}}");
    let blocks = parse("Corefile", &input).unwrap();
    let (_, lifecycle) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.ends_with("\r\n\r\nOK"), "{response}");
    lifecycle.run(Phase::Shutdown).await.unwrap();
}
