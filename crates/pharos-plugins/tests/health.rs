#![cfg(feature = "plugin-health")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::Phase;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn request(address: std::net::SocketAddr, method: &str, path: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

// Derived from CoreDNS v1.15.0 plugin/health/health_test.go.
#[tokio::test]
async fn health_answers_all_methods_and_only_its_path() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let input = format!(".:0 {{\n health {address}\n}}");
    let blocks = parse("Corefile", &input).unwrap();
    let (_, lifecycle) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    for method in ["GET", "POST", "PUT"] {
        let response = request(address, method, "/health?check=1").await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.ends_with("\r\n\r\nOK"), "{response}");
    }
    let response = request(address, "HEAD", "/health").await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.ends_with("\r\n\r\n"), "{response}");
    let response = request(address, "GET", "/other").await;
    assert!(
        response.starts_with("HTTP/1.1 404 Not Found\r\n"),
        "{response}"
    );
    assert!(
        response.ends_with("\r\n\r\n404 page not found\n"),
        "{response}"
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
}
