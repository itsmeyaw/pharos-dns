#![cfg(feature = "plugin-ready")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::Phase;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn request(address: std::net::SocketAddr, method: &str) -> String {
    request_with_headers(address, method, "").await
}

async fn request_with_headers(
    address: std::net::SocketAddr,
    method: &str,
    headers: &str,
) -> String {
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!(
                "{method} /ready HTTP/1.1\r\nHost: localhost\r\n{headers}Connection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn shared_address_serves_ready() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let input = format!("a.:0 {{\n ready {address}\n}}\nb.:0 {{\n ready {address}\n}}");
    let blocks = parse("Corefile", &input).unwrap();
    let (_, lifecycle) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let response = request(address, "GET").await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.ends_with("\r\n\r\nOK"), "{response}");
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn ready_head_and_if_match_preconditions_use_get_representation() {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let input = format!(".:0 {{\n ready {address}\n}}");
    let blocks = parse("Corefile", &input).unwrap();
    let (_, lifecycle) = servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();

    let response = request_with_headers(address, "GET", "If-None-Match: \"stale\"\r\n").await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    let etag = response
        .lines()
        .find_map(|line| line.strip_prefix("etag: "))
        .unwrap();

    let head = request_with_headers(address, "HEAD", "If-None-Match: *\r\n").await;
    assert!(head.starts_with("HTTP/1.1 304 Not Modified\r\n"), "{head}");
    assert!(head.contains(&format!("etag: {etag}\r\n")), "{head}");
    assert!(head.ends_with("\r\n\r\n"), "{head}");

    let failed = request_with_headers(address, "GET", "If-Match: \"stale\"\r\n").await;
    assert!(
        failed.starts_with("HTTP/1.1 412 Precondition Failed\r\n"),
        "{failed}"
    );
    assert!(failed.contains(&format!("etag: {etag}\r\n")), "{failed}");

    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn shutdown_is_visible_during_block_shutdown_hooks() {
    use std::sync::Arc;
    use tokio::sync::Notify;

    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let input = format!(".:0 {{\n ready {address}\n}}");
    let blocks = parse("Corefile", &input).unwrap();
    let mut blocks = configure::<Chain>(&blocks, directives()).unwrap();
    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let (signal, wait) = (Arc::clone(&entered), Arc::clone(&resume));
    blocks[0]
        .config
        .lifecycle
        .register(Phase::Shutdown, move || {
            let (signal, wait) = (Arc::clone(&signal), Arc::clone(&wait));
            async move {
                signal.notify_one();
                wait.notified().await;
                Ok(())
            }
        });
    let (_, lifecycle) = servers(blocks).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let task = tokio::spawn(async move { lifecycle.run(Phase::Shutdown).await });
    entered.notified().await;
    let response = request(address, "GET").await;
    assert!(
        response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "{response}"
    );
    assert!(response.ends_with("Shutting down"), "{response}");
    assert!(
        response.contains("Service temporarily unavailable"),
        "{response}"
    );
    let head = request(address, "HEAD").await;
    assert!(
        head.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
        "{head}"
    );
    assert!(
        head.contains("content-type: text/plain; charset=utf-8\r\n"),
        "{head}"
    );
    assert!(head.ends_with("\r\n\r\n"), "{head}");
    resume.notify_one();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn http_reports_unready_names_and_monitor_transitions() {
    use pharos_plugins::ready::State;
    use pharos_server::http::Listener;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    for continuous in [false, true] {
        let state = Arc::new(State::default());
        state.set_continuous(continuous);
        let ready = Arc::new(AtomicBool::new(false));
        for name in ["zebra", "alpha"] {
            let ready = Arc::clone(&ready);
            state.append(name, move || ready.load(Ordering::SeqCst));
        }
        let check = Arc::clone(&state);
        let listener = Listener::bind_with_methods("127.0.0.1:0", move |method, path| {
            if path != "/ready" {
                return None;
            }
            if method != "GET" {
                return Some((
                    405,
                    "text/plain; charset=utf-8",
                    "Method Not Allowed\n".into(),
                ));
            }
            let (status, body) = check.response();
            Some((status, "text/plain; charset=utf-8", body))
        })
        .await
        .unwrap();
        let address = listener.local_addr();
        ready.store(true, Ordering::SeqCst);
        let response = request(address, "POST").await;
        assert!(
            response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
            "{response}"
        );
        assert!(response.contains("allow: GET, HEAD\r\n"), "{response}");
        ready.store(false, Ordering::SeqCst);
        let response = request(address, "GET").await;
        assert!(
            response.starts_with("HTTP/1.1 503 ")
                && response.ends_with("Service temporarily unavailable: alpha,zebra"),
            "{response}"
        );
        ready.store(true, Ordering::SeqCst);
        let response = request(address, "GET").await;
        assert!(
            response.starts_with("HTTP/1.1 200 ") && response.ends_with("\r\n\r\nOK"),
            "{response}"
        );
        ready.store(false, Ordering::SeqCst);
        let response = request(address, "GET").await;
        if continuous {
            assert!(
                response.starts_with("HTTP/1.1 503 ")
                    && response.ends_with("Service temporarily unavailable: alpha,zebra"),
                "{response}"
            );
        } else {
            assert!(
                response.starts_with("HTTP/1.1 200 ") && response.ends_with("\r\n\r\nOK"),
                "{response}"
            );
        }
        listener.shutdown().await.unwrap();
    }
}
