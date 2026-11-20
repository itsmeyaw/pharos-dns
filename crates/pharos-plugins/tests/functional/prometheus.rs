#![cfg(all(feature = "plugin-prometheus", feature = "plugin-whoami"))]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::{Listener, Phase};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn scrape_counts_only_blocks_with_prometheus() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let corefile = format!(
        "example.org:0 {{\n prometheus :{}\n whoami\n}}\nsecond.org:0 {{\n prometheus :{}\n whoami\n}}\nother.org:0 {{\n whoami\n}}",
        address.port(),
        address.port()
    );
    let blocks = parse("Corefile", &corefile).unwrap();
    let (mut servers, lifecycle) =
        servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (key, server) = servers.drain().next().unwrap();
    let listener = Listener::bind(key.address, server).await.unwrap();
    let dns_address = std::net::SocketAddr::from(([127, 0, 0, 1], listener.local_addr().port()));
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(dns_address).await.unwrap();
    for name in [
        b"example".as_slice(),
        b"second".as_slice(),
        b"other".as_slice(),
    ] {
        let mut query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, name.len() as u8];
        query.extend_from_slice(name);
        query.extend_from_slice(b"\x03org\0\0\x01\0\x01");
        udp.send(&query).await.unwrap();
        let mut response = [0; 512];
        tokio::time::timeout(std::time::Duration::from_secs(2), udp.recv(&mut response))
            .await
            .unwrap()
            .unwrap();
    }
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(!response.contains("\netag: "), "{response}");
    assert!(response.contains("pharos_dns_requests_total{family=\"1\",proto=\"udp\",server=\"dns://:0\",type=\"A\",view=\"\",zone=\"example.org.\"} 1"), "{response}");
    assert!(response.contains("pharos_dns_responses_total{plugin=\"whoami\",rcode=\"NOERROR\",server=\"dns://:0\",view=\"\",zone=\"example.org.\"} 1"), "{response}");
    assert!(
        response.contains("pharos_plugin_enabled{name=\"prometheus\","),
        "{response}"
    );
    assert!(response.contains("pharos_build_info{"), "{response}");
    #[cfg(feature = "plugin-forward")]
    {
        assert!(
            response.contains("pharos_forward_healthcheck_broken_total 0\n"),
            "{response}"
        );
        assert!(
            response.contains("pharos_forward_max_concurrent_rejects_total 0\n"),
            "{response}"
        );
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert!(response.contains("process_open_fds "), "{response}");
    assert!(response.contains("zone=\"example.org.\""), "{response}");
    assert!(response.contains("zone=\"second.org.\""), "{response}");
    assert!(!response.contains("zone=\"other.org.\""), "{response}");
    assert!(
        !response.lines().any(|line| line.starts_with("go_")),
        "{response}"
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
    listener.shutdown().await.unwrap();
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn metrics_head_uses_get_metadata_and_post_is_not_allowed() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let input = format!(".:0 {{\n prometheus {address}\n whoami\n}}");
    let blocks = parse("Corefile", &input).unwrap();
    let (_, lifecycle) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();

    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"HEAD /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut head = String::new();
    stream.read_to_string(&mut head).await.unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert!(!head.contains("\netag: "), "{head}");
    assert!(
        head.contains("content-type: text/plain; version=0.0.4; charset=utf-8\r\n"),
        "{head}"
    );
    assert!(head.ends_with("\r\n\r\n"), "{head}");

    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"HEAD /metrics HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: *\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut conditional_head = String::new();
    stream.read_to_string(&mut conditional_head).await.unwrap();
    assert!(
        conditional_head.starts_with("HTTP/1.1 304 Not Modified\r\n"),
        "{conditional_head}"
    );
    assert!(
        conditional_head.contains("\netag: \""),
        "{conditional_head}"
    );
    assert!(conditional_head.ends_with("\r\n\r\n"), "{conditional_head}");

    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"POST /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut method_error = String::new();
    stream.read_to_string(&mut method_error).await.unwrap();
    assert!(
        method_error.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
        "{method_error}"
    );
    assert!(
        method_error.contains("allow: GET, HEAD\r\n"),
        "{method_error}"
    );
    assert!(
        method_error.ends_with("Method Not Allowed\n"),
        "{method_error}"
    );

    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn metrics_bind_failure_is_reported() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let input = format!(
        ".:1053 {{\n prometheus {}\n whoami\n}}",
        occupied.local_addr().unwrap()
    );
    let blocks = parse("Corefile", &input).unwrap();
    let (_, lifecycle) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    assert!(lifecycle.run(Phase::Startup).await.is_err());
}

#[tokio::test]
async fn empty_metrics_port_uses_ephemeral_port() {
    let input = ".:0 {\n prometheus localhost:\n whoami\n}";
    let blocks = parse("Corefile", input).unwrap();
    let (_, lifecycle) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[test]
fn conflicting_tls_configs_are_rejected_for_a_shared_address() {
    let input = "a.:0 {\n prometheus 127.0.0.1:0\n whoami\n}\nb.:0 {\n prometheus 127.0.0.1:0 {\n tls config.yml\n}\n whoami\n}";
    let blocks = parse("Corefile", input).unwrap();
    let error = match servers(configure::<Chain>(&blocks, directives()).unwrap()) {
        Ok(_) => panic!("conflicting TLS configurations accepted"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}
