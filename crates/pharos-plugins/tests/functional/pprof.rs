#![cfg(feature = "plugin-pprof")]

use std::{net::SocketAddr, time::Duration};

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives, servers};
use pharos_server::{Action, Handler, Lifecycle, Phase, Protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The CPU profiler is process-wide, so tests that start one must not overlap.
static PROFILER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn free_address() -> SocketAddr {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap()
}

fn lifecycle(corefile: &str) -> Lifecycle {
    let blocks = parse("Corefile", corefile).unwrap();
    servers(configure::<Chain>(&blocks, directives()).unwrap())
        .unwrap()
        .1
}

async fn started(address: SocketAddr) -> Lifecycle {
    let lifecycle = lifecycle(&format!(".:0 {{\n pprof {address}\n}}"));
    lifecycle.run(Phase::Startup).await.unwrap();
    lifecycle
}

struct Response {
    head: String,
    body: Vec<u8>,
}

impl Response {
    fn status(&self) -> &str {
        self.head.lines().next().unwrap()
    }

    fn text(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap()
    }
}

async fn request(address: SocketAddr, method: &str, target: &str) -> Response {
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!("{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = String::from_utf8(raw[..split].to_vec())
        .unwrap()
        .to_ascii_lowercase();
    let mut body = raw[split + 4..].to_vec();
    if head.contains("transfer-encoding: chunked") {
        body = dechunk(&body);
    }
    Response { head, body }
}

fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let line_end = raw.windows(2).position(|window| window == b"\r\n").unwrap();
        let size =
            usize::from_str_radix(std::str::from_utf8(&raw[..line_end]).unwrap(), 16).unwrap();
        if size == 0 {
            return body;
        }
        body.extend_from_slice(&raw[line_end + 2..line_end + 2 + size]);
        raw = &raw[line_end + 2 + size + 2..];
    }
}

/// Spends CPU on another thread until dropped, so samples exist however long the profiler takes to start.
struct Burner(
    std::sync::Arc<std::sync::atomic::AtomicBool>,
    Option<std::thread::JoinHandle<()>>,
);

impl Burner {
    fn start() -> Self {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let mut value = 1u64;
            while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                value =
                    std::hint::black_box(value.wrapping_mul(6364136223846793005).wrapping_add(1));
            }
        });
        Self(stop, Some(thread))
    }
}

impl Drop for Burner {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
        self.1.take().unwrap().join().unwrap();
    }
}

#[tokio::test]
async fn index_redirect_and_unsupported_endpoints_follow_go_net_http_pprof() {
    let address = free_address();
    let lifecycle = started(address).await;

    // CoreDNS v1.15.0 plugin/pprof/pprof.go: /debug/pprof redirects to /debug/pprof/.
    let response = request(address, "GET", "/debug/pprof").await;
    assert_eq!(response.status(), "http/1.1 302 found", "{}", response.head);
    assert!(
        response.head.contains("\r\nlocation: /debug/pprof/"),
        "{}",
        response.head
    );

    let response = request(address, "GET", "/debug/pprof/").await;
    assert_eq!(response.status(), "http/1.1 200 ok");
    assert!(
        response
            .head
            .contains("content-type: text/html; charset=utf-8"),
        "{}",
        response.head
    );
    assert!(response.head.contains("x-content-type-options: nosniff"));
    for profile in ["profile", "cmdline", "symbol"] {
        assert!(
            response.text().contains(&format!("href=\"{profile}")),
            "{profile}"
        );
    }
    for profile in [
        "heap",
        "goroutine",
        "allocs",
        "block",
        "mutex",
        "threadcreate",
    ] {
        assert!(
            !response.text().contains(&format!("href=\"{profile}")),
            "{profile}"
        );
    }

    // Go net/http/pprof Index: unsupported and unknown profiles answer 404 "Unknown profile".
    for profile in [
        "allocs",
        "block",
        "goroutine",
        "heap",
        "mutex",
        "threadcreate",
        "nope",
    ] {
        let response = request(address, "GET", &format!("/debug/pprof/{profile}")).await;
        assert_eq!(response.status(), "http/1.1 404 not found", "{profile}");
        assert_eq!(response.text(), "Unknown profile\n", "{profile}");
        assert!(response.head.contains("x-content-type-options: nosniff"));
    }
    let response = request(address, "GET", "/debug/pprof/trace?seconds=1").await;
    assert_eq!(response.status(), "http/1.1 404 not found");
    assert!(
        response.text().contains("not supported"),
        "{}",
        response.text()
    );

    // Go net/http ServeMux: paths outside /debug/pprof are not registered.
    for target in ["/", "/debug/pprofx", "/debug"] {
        let response = request(address, "GET", target).await;
        assert_eq!(response.status(), "http/1.1 404 not found", "{target}");
    }
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn cmdline_symbol_and_methods() {
    let address = free_address();
    let lifecycle = started(address).await;

    // Go net/http/pprof Cmdline: process arguments joined by NUL bytes.
    let response = request(address, "GET", "/debug/pprof/cmdline").await;
    assert_eq!(response.status(), "http/1.1 200 ok");
    assert!(
        response
            .head
            .contains("content-type: text/plain; charset=utf-8")
    );
    let expected: Vec<u8> = std::env::args_os()
        .map(|argument| std::os::unix::ffi::OsStrExt::as_bytes(argument.as_os_str()).to_vec())
        .collect::<Vec<_>>()
        .join(&0);
    assert_eq!(response.body, expected);

    let response = request(address, "GET", "/debug/pprof/symbol").await;
    assert_eq!(response.status(), "http/1.1 200 ok");
    assert_eq!(response.text(), "num_symbols: 0\n");

    // RFC 9110 §9.3.2: HEAD returns the GET headers without content.
    let response = request(address, "HEAD", "/debug/pprof/cmdline").await;
    assert_eq!(response.status(), "http/1.1 200 ok");
    assert!(response.body.is_empty());

    // RFC 9110 §9.1: recognized other methods get 405 with Allow; unknown tokens get 501.
    for method in ["POST", "PUT", "DELETE"] {
        for target in [
            "/debug/pprof/symbol",
            "/debug/pprof/profile?seconds=1",
            "/debug/pprof/",
        ] {
            let response = request(address, method, target).await;
            assert_eq!(
                response.status(),
                "http/1.1 405 method not allowed",
                "{method} {target}"
            );
            assert!(
                response.head.contains("allow: get, head"),
                "{}",
                response.head
            );
        }
    }
    let response = request(address, "FROB", "/debug/pprof/").await;
    assert_eq!(response.status(), "http/1.1 501 not implemented");
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn cpu_profile_decodes_as_pprof_protobuf() {
    use ::pprof::protos::{Message, Profile};

    let _profiler = PROFILER.lock().await;
    let address = free_address();
    let lifecycle = started(address).await;
    let _burner = Burner::start();
    let start = std::time::Instant::now();
    // `%31` is the percent-encoded digit 1.
    let response = request(address, "GET", "/debug/pprof/profile?seconds=%31").await;
    assert!(start.elapsed() >= Duration::from_secs(1));
    assert_eq!(response.status(), "http/1.1 200 ok", "{}", response.text());
    assert!(
        response
            .head
            .contains("content-type: application/octet-stream"),
        "{}",
        response.head
    );
    assert!(
        response
            .head
            .contains("content-disposition: attachment; filename=\"profile\""),
        "{}",
        response.head
    );
    let profile = Profile::parse_from_bytes(&response.body).unwrap();
    assert!(!profile.sample_type.is_empty());
    assert!(!profile.string_table.is_empty());
    assert!(!profile.sample.is_empty(), "no samples from a busy thread");
    // The profile measures CPU time sampled at 100 Hz, which is a 10 ms period.
    assert_eq!(profile.period, 10_000_000);
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn invalid_and_excessive_seconds_are_rejected() {
    let address = free_address();
    let lifecycle = started(address).await;
    // Pharos rule: a present `seconds` that is unparsable or at most zero is 400, where Go silently uses 30.
    for query in [
        "?seconds=abc",
        "?seconds=0",
        "?seconds=-3",
        "?seconds=",
        "?seconds=%zz",
        "?seconds=99999999999999999999",
    ] {
        let response = request(address, "GET", &format!("/debug/pprof/profile{query}")).await;
        assert_eq!(response.status(), "http/1.1 400 bad request", "{query}");
        assert_eq!(response.text(), "invalid seconds\n", "{query}");
    }
    // Pharos rule: the documented cap is 300 s, which Go does not have.
    for query in ["?seconds=301", "?seconds=%33%30%31"] {
        let response = request(address, "GET", &format!("/debug/pprof/profile{query}")).await;
        assert_eq!(response.status(), "http/1.1 400 bad request", "{query}");
        assert_eq!(response.text(), "profile duration too long\n", "{query}");
    }
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn cancelled_profile_request_never_frees_the_slot_early_or_blocks_later_ones() {
    let _profiler = PROFILER.lock().await;
    let address = free_address();
    let lifecycle = started(address).await;
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"GET /debug/pprof/profile?seconds=1 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The client goes away mid-profile.
    drop(stream);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    // Go runtime/pprof StartCPUProfile: a request is either refused as in use or profiles successfully.
    let status = loop {
        let response = request(address, "GET", "/debug/pprof/profile?seconds=1").await;
        match response.status() {
            "http/1.1 200 ok" => break response.status().to_owned(),
            "http/1.1 500 internal server error" => {
                assert_eq!(
                    response.text(),
                    "Could not enable CPU profiling: cpu profiling already in use\n"
                );
                assert!(std::time::Instant::now() < deadline, "slot never freed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            other => panic!("{other}: {}", response.text()),
        }
    };
    assert_eq!(status, "http/1.1 200 ok");
    let later = request(address, "GET", "/debug/pprof/profile?seconds=1").await;
    assert_eq!(later.status(), "http/1.1 200 ok", "{}", later.text());
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn concurrent_second_profile_is_rejected_and_other_requests_are_served() {
    let _profiler = PROFILER.lock().await;
    let address = free_address();
    let lifecycle = started(address).await;
    let first = tokio::spawn(request(address, "GET", "/debug/pprof/profile?seconds=1"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Go runtime/pprof StartCPUProfile: only one CPU profile at a time.
    let second = request(address, "GET", "/debug/pprof/profile?seconds=1").await;
    assert_eq!(second.status(), "http/1.1 500 internal server error");
    assert_eq!(
        second.text(),
        "Could not enable CPU profiling: cpu profiling already in use\n"
    );
    // The profile in flight does not stall other requests.
    let start = std::time::Instant::now();
    let index = request(address, "GET", "/debug/pprof/").await;
    assert_eq!(index.status(), "http/1.1 200 ok");
    assert!(start.elapsed() < Duration::from_millis(500));
    let first = first.await.unwrap();
    assert_eq!(first.status(), "http/1.1 200 ok");
    // The profiler is released once the first profile is done.
    let third = request(address, "GET", "/debug/pprof/profile?seconds=1").await;
    assert_eq!(third.status(), "http/1.1 200 ok", "{}", third.text());
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profile_in_flight_does_not_stall_dns_queries() {
    let _profiler = PROFILER.lock().await;
    let address = free_address();
    let blocks = parse(
        "Corefile",
        &format!(".:0 {{\n whoami\n pprof {address}\n}}"),
    )
    .unwrap();
    let (mut servers, lifecycle) =
        servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    lifecycle.run(Phase::Startup).await.unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let profile = tokio::spawn(request(address, "GET", "/debug/pprof/profile?seconds=1"));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let query = b"\x12\x34\x01\0\0\x01\0\0\0\0\0\0\x07example\x03org\0\0\x01\0\x01";
    let mut response = Vec::with_capacity(65535);
    let client = "127.0.0.1:1234".parse().unwrap();
    let start = std::time::Instant::now();
    assert_eq!(
        server
            .handle(query, client, Protocol::Udp, &mut response)
            .await,
        Action::Respond
    );
    assert!(
        start.elapsed() < Duration::from_millis(200),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(profile.await.unwrap().status(), "http/1.1 200 ok");
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn restart_stops_listener_and_reload_rebinds_the_same_address() {
    let address = free_address();
    let lifecycle = started(address).await;
    assert_eq!(
        request(address, "GET", "/debug/pprof/").await.status(),
        "http/1.1 200 ok"
    );
    // Restart tears the old Listener down, so the address no longer answers.
    lifecycle.run(Phase::Restart).await.unwrap();
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    // A failed reload brings the old Listener back.
    lifecycle.run(Phase::RestartFailed).await.unwrap();
    assert_eq!(
        request(address, "GET", "/debug/pprof/").await.status(),
        "http/1.1 200 ok"
    );
    // A successful reload binds the same address from a new configuration.
    lifecycle.run(Phase::Restart).await.unwrap();
    let reloaded = started(address).await;
    assert_eq!(
        request(address, "GET", "/debug/pprof/").await.status(),
        "http/1.1 200 ok"
    );
    reloaded.run(Phase::Shutdown).await.unwrap();
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    // Shutdown after Restart has no Listener left to stop.
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn server_blocks_share_an_address_and_block_property_is_accepted() {
    let address = free_address();
    let input =
        format!("a.:0 {{\n pprof {address} {{\n block 5\n }}\n}}\nb.:0 {{\n pprof {address}\n}}");
    let lifecycle = lifecycle(&input);
    lifecycle.run(Phase::Startup).await.unwrap();
    assert_eq!(
        request(address, "GET", "/debug/pprof/").await.status(),
        "http/1.1 200 ok"
    );
    lifecycle.run(Phase::Shutdown).await.unwrap();
}

#[tokio::test]
async fn occupied_address_fails_startup() {
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let lifecycle = lifecycle(&format!(
        ".:0 {{\n pprof {}\n}}",
        occupied.local_addr().unwrap()
    ));
    assert!(lifecycle.run(Phase::Startup).await.is_err());
}

#[tokio::test]
async fn shutdown_does_not_hang_on_a_profile_in_flight() {
    let _profiler = PROFILER.lock().await;
    let address = free_address();
    let lifecycle = started(address).await;
    let profile = tokio::spawn(request(address, "GET", "/debug/pprof/profile?seconds=1"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The Listener drains for at most five seconds, enough for a profile below five seconds.
    tokio::time::timeout(Duration::from_secs(6), lifecycle.run(Phase::Shutdown))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(profile.await.unwrap().status(), "http/1.1 200 ok");
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}
