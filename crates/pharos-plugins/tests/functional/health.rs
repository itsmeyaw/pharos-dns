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
        // RFC 9110 §15.3.1: 200 indicates that the request succeeded.
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.ends_with("\r\n\r\nOK"), "{response}");
    }
    // RFC 9110 §9.3.2: HEAD responses omit representation content.
    let response = request(address, "HEAD", "/health").await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.ends_with("\r\n\r\n"), "{response}");
    let response = request(address, "GET", "/other").await;
    // RFC 9110 §15.5.5: 404 means no current representation exists for the target resource.
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

#[tokio::test]
async fn server_blocks_share_a_health_address() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let input = format!("a.:0 {{\n health {address}\n}}\nb.:0 {{\n health {address}\n}}");
    let blocks = parse("Corefile", &input).unwrap();
    let (_, lifecycle) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let response = request(address, "GET", "/health").await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n") && response.ends_with("\r\n\r\nOK"));
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn health_shutdown_follows_server_block_order() {
    let sockets: Vec<_> = (0..2)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let mut addresses: Vec<_> = sockets.iter().map(|s| s.local_addr().unwrap()).collect();
    addresses.sort_by_key(|address| address.to_string());
    let (second, first) = (addresses[0], addresses[1]);
    drop(sockets);
    let input = format!(
        "a.:0 {{\n health {first} {{\n lameduck 500ms\n }}\n}}\nb.:0 {{\n health {second}\n}}\n"
    );
    let blocks = parse("Corefile", &input).unwrap();
    let (_, lifecycle) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (started, starting) = tokio::sync::oneshot::channel();
    let shutdown = tokio::spawn(async move {
        let _ = started.send(());
        lifecycle.run(Phase::Shutdown).await
    });
    starting.await.unwrap();
    assert!(!shutdown.is_finished());
    assert!(
        request(second, "GET", "/health")
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(!shutdown.is_finished());
    shutdown.await.unwrap().unwrap();
}

#[cfg(feature = "plugin-prometheus")]
#[tokio::test]
async fn health_self_probes_export_unlabelled_histogram_and_failures() {
    let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let health = first.local_addr().unwrap();
    let metrics = second.local_addr().unwrap();
    drop((first, second));
    let input = format!(
        "a.:0 {{\n health {health}\n prometheus {metrics}\n}}\nb.:0 {{\n health 127.0.0.1:0\n}}\n"
    );
    let blocks = parse("Corefile", &input).unwrap();
    let (_, lifecycle) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let response = request(metrics, "GET", "/metrics").await;
            let value = |name: &str| {
                response
                    .lines()
                    .find_map(|line| line.strip_prefix(name))
                    .and_then(|value| value.trim().parse::<u64>().ok())
                    .unwrap_or(0)
            };
            if value("pharos_health_request_duration_seconds_count ") >= 2
                && value("pharos_health_request_failures_total ") >= 1
            {
                break response;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("health probes did not update metrics");
    for bucket in ["0.00025", "0.0025", "0.025", "0.25", "2.5", "+Inf"] {
        assert!(
            response.contains(&format!(
                "pharos_health_request_duration_seconds_bucket{{le=\"{bucket}\"}}"
            )),
            "{response}"
        );
    }
    let value = |name: &str| {
        response
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap()
    };
    assert!(
        value("pharos_health_request_duration_seconds_count ") >= 2,
        "{response}"
    );
    assert!(
        value("pharos_health_request_failures_total ") >= 1,
        "{response}"
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
}
