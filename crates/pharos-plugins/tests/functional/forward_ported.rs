#![forbid(unsafe_code)]
#![cfg(feature = "plugin-forward")]

use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Message, Name, Rcode};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};

const QUERY: &[u8] = b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0\x07example\x03org\0\0\x01\0\x01";

fn configure_chain(directives_text: &str) -> Result<Chain, String> {
    let text = format!(".:0 {{\n{directives_text}\n}}");
    let blocks = parse("Corefile", &text).map_err(|e| e.to_string())?;
    configure::<Chain>(&blocks, directives())
        .map(|mut servers| servers.remove(0).config)
        .map_err(|e| e.to_string())
}

async fn query(chain: &Chain) -> (Outcome, Vec<u8>) {
    let domain: Name = ".".parse().unwrap();
    let mut response = Vec::new();
    let mut slots = [];
    let mut context = Context {
        query: Message::parse(QUERY).unwrap(),
        client: "127.0.0.1:1000".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    let outcome = tokio::time::timeout(Duration::from_secs(2), chain.serve(&mut context))
        .await
        .expect("forward query timed out");
    (outcome, response)
}

struct Fake {
    addr: SocketAddr,
    count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn udp_fake(rcode: u8, answer: Option<u8>) -> Fake {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let task = tokio::spawn(async move {
        let mut wire = [0; 512];
        loop {
            let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
            seen.fetch_add(1, Ordering::SeqCst);
            let mut reply = wire[..len].to_vec();
            reply[2] |= 0x80;
            reply[3] = rcode;
            if let Some(last) = answer {
                reply[6..8].copy_from_slice(&1_u16.to_be_bytes());
                reply.extend_from_slice(&[
                    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, last,
                ]);
            }
            socket.send_to(&reply, peer).await.unwrap();
        }
    });
    Fake { addr, count, task }
}

async fn tcp_fake(fail_first: usize) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let attempt = seen.fetch_add(1, Ordering::SeqCst) + 1;
            let len = stream.read_u16().await.unwrap() as usize;
            let mut wire = vec![0; len];
            stream.read_exact(&mut wire).await.unwrap();
            if attempt <= fail_first {
                continue;
            }
            wire[2] |= 0x80;
            stream.write_u16(len as u16).await.unwrap();
            stream.write_all(&wire).await.unwrap();
        }
    });
    Fake { addr, count, task }
}

fn counts(fakes: &[&Fake]) -> Vec<usize> {
    fakes
        .iter()
        .map(|f| f.count.load(Ordering::SeqCst))
        .collect()
}

// Adapted from CoreDNS setup_test.go and setup_policy_test.go.
#[test]
fn setup_accepts_and_rejects_coredns_options() {
    let cases = [
        ("forward . 127.0.0.1", true),
        ("forward . 127.0.0.1:8080", true),
        ("forward . [::1]:53", true),
        ("forward 10.9.3.0/18 127.0.0.1", true),
        ("forward . 127.0.0.1 {\nexcept miek.nl\n}", true),
        ("forward . 127.0.0.1 {\nforce_tcp\nprefer_udp\n}", true),
        ("forward . 127.0.0.1 {\npolicy random\n}", true),
        ("forward . 127.0.0.1 {\npolicy round_robin\n}", true),
        ("forward . 127.0.0.1 {\npolicy sequential\n}", true),
        ("forward . 127.0.0.1 {\npolicy random2\n}", false),
        ("forward . 127.0.0.1 {\nblaatl\n}", false),
        (
            "forward . 127.0.0.1 {\nhealth_check 0.5s no_rec domain example.org\n}",
            true,
        ),
        ("forward . 127.0.0.1 {\nhealth_check 0.5s domain\n}", false),
        ("forward . 127.0.0.1 {\nhealth_check 0.5s rec\n}", false),
        (
            "forward . 127.0.0.1 {\nhealth_check 0.5s domain example..org\n}",
            false,
        ),
        ("forward . 127.0.0.1 {\nmax_concurrent 1000\n}", true),
        ("forward . 127.0.0.1 {\nmax_concurrent many\n}", false),
        ("forward . 127.0.0.1 {\nmax_concurrent -4\n}", false),
        ("forward . 127.0.0.1 {\nmax_connect_attempts 0\n}", true),
        ("forward . 127.0.0.1 {\nmax_connect_attempts 5\n}", true),
        ("forward . 127.0.0.1 {\nmax_connect_attempts -4\n}", false),
        ("forward . 127.0.0.1 {\nmax_idle_conns 0\n}", true),
        ("forward . 127.0.0.1 {\nmax_idle_conns -1\n}", false),
        ("forward . 127.0.0.1 {\nsource_address 192.0.2.1\n}", true),
        ("forward . 127.0.0.1 {\nsource_address not-an-ip\n}", false),
        (
            "forward . 127.0.0.1 {\nnext NXDOMAIN SERVFAIL REFUSED\n}",
            true,
        ),
        ("forward . 127.0.0.1 {\nnext\n}", false),
        ("forward . 127.0.0.1 {\nnext NXDOMAIN INVALID\n}", false),
        ("forward . 127.0.0.1 {\nfailover NOERROR\n}", false),
        (
            "forward . 127.0.0.1 {\nfailover NOT_A_VALID_RCODE\n}",
            false,
        ),
        (
            "forward . 127.0.0.1 {\nfailfast_all_unhealthy_upstreams\n}",
            true,
        ),
        (
            "forward . 127.0.0.1 {\nfailfast_all_unhealthy_upstreams false\n}",
            false,
        ),
        ("forward . 127.0.0.1 {\nexpire 10s\nmax_age 10s\n}", true),
        ("forward . 127.0.0.1 {\nexpire 30s\nmax_age 10s\n}", false),
        ("forward . 127.0.0.1 {\nread_timeout 500ms\n}", true),
        ("forward . 127.0.0.1 {\nread_timeout 0s\n}", false),
        ("forward . 127.0.0.1 {\nresolver 127.0.0.1 ::1\n}", true),
        ("forward . 127.0.0.1 {\nresolver dns.example.com\n}", false),
        ("forward . 127.0.0.1 {\nresolver\n}", false),
    ];
    let mut failures = Vec::new();
    for (input, expected) in cases {
        let result = configure_chain(input);
        if result.is_ok() != expected {
            failures.push(format!(
                "{input:?}: expected success={expected}, got {result:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// CoreDNS forward_test.go TestList, tested through queries instead of private state.
#[tokio::test]
async fn sequential_and_round_robin_select_expected_upstreams() {
    for (policy, expected) in [
        ("sequential", vec![1, 1, 1, 1]),
        ("round_robin", vec![2, 3, 1, 2]),
    ] {
        let a = udp_fake(0, Some(1)).await;
        let b = udp_fake(0, Some(2)).await;
        let c = udp_fake(0, Some(3)).await;
        let chain = configure_chain(&format!(
            "forward . {} {} {} {{\npolicy {policy}\n}}",
            a.addr, b.addr, c.addr
        ))
        .unwrap();
        for last in expected {
            let (outcome, wire) = query(&chain).await;
            assert_eq!(outcome, Outcome::Response, "{policy}");
            let response = Message::parse(&wire).unwrap();
            assert_eq!(
                response.answers().next().unwrap().rdata,
                &[127, 0, 0, last],
                "{policy}"
            );
        }
        let want = if policy == "sequential" {
            vec![4, 0, 0]
        } else {
            vec![1, 2, 1]
        };
        assert_eq!(counts(&[&a, &b, &c]), want, "{policy}");
    }
}

#[tokio::test]
async fn random_policy_selects_all_upstreams() {
    let a = udp_fake(0, Some(1)).await;
    let b = udp_fake(0, Some(2)).await;
    let c = udp_fake(0, Some(3)).await;
    let chain = configure_chain(&format!(
        "forward . {} {} {} {{\npolicy random\n}}",
        a.addr, b.addr, c.addr
    ))
    .unwrap();
    for _ in 0..128 {
        assert_eq!(query(&chain).await.0, Outcome::Response);
    }
    assert!(counts(&[&a, &b, &c]).iter().all(|&count| count > 0));
}

// CoreDNS forward_test.go TestForward_NextOnNodata plus non-NODATA boundaries.
#[tokio::test]
async fn next_on_nodata_only_advances_for_empty_noerror() {
    for (enabled, rcode, answer, expected_rcode, expected_answer, second_count) in [
        (false, 0, None, 0, None, 0),
        (true, 0, None, 0, Some(2), 1),
        (true, 0, Some(1), 0, Some(1), 0),
        (true, 3, None, 3, None, 0),
    ] {
        let first = udp_fake(rcode, answer).await;
        let second = udp_fake(0, Some(2)).await;
        let option = if enabled { " {\nnext_on_nodata\n}" } else { "" };
        let chain = configure_chain(&format!(
            "forward . {}{option}\nforward . {}",
            first.addr, second.addr
        ))
        .unwrap();
        let (outcome, wire) = query(&chain).await;
        assert_eq!(outcome, Outcome::Response);
        let response = Message::parse(&wire).unwrap();
        assert_eq!(response.rcode().0, expected_rcode);
        assert_eq!(
            response.answers().next().map(|rr| rr.rdata[3]),
            expected_answer
        );
        assert_eq!(counts(&[&first, &second]), vec![1, second_count]);
    }
}

// CoreDNS setup_test.go TestFailover and forward_test.go TestForwardFailoverStopsAfterAllUpstreams.
#[tokio::test]
async fn failover_returns_first_nonmatching_or_last_matching_response() {
    for (rcodes, failover, expected_rcode, expected_counts) in [
        ([2, 5, 0], "failover SERVFAIL REFUSED", 0, [1, 1, 1]),
        ([2, 5, 0], "", 2, [1, 0, 0]),
        ([0, 2, 5], "", 0, [1, 0, 0]),
        ([2, 2, 5], "failover SERVFAIL REFUSED", 5, [1, 1, 1]),
        ([2, 5, 0], "failover SERVFAIL", 5, [1, 1, 0]),
    ] {
        let a = udp_fake(rcodes[0], None).await;
        let b = udp_fake(rcodes[1], None).await;
        let c = udp_fake(rcodes[2], None).await;
        let chain = configure_chain(&format!(
            "forward . {} {} {} {{\npolicy sequential\n{failover}\n}}",
            a.addr, b.addr, c.addr
        ))
        .unwrap();
        let (outcome, wire) = query(&chain).await;
        assert_eq!(outcome, Outcome::Response, "{rcodes:?} {failover}");
        assert_eq!(Message::parse(&wire).unwrap().rcode().0, expected_rcode);
        assert_eq!(counts(&[&a, &b, &c]), expected_counts);
    }
}

// CoreDNS forward_test.go TestForward_Regression_NoBusyLoop and default cap.
#[tokio::test]
async fn max_connect_attempts_caps_failed_exchanges_and_zero_is_unbounded() {
    for (setting, failed_before_success, expected_attempts, success) in [
        ("max_connect_attempts 1", 10, 1, false),
        ("max_connect_attempts 2", 10, 2, false),
        ("max_connect_attempts 5", 10, 5, false),
        ("", 10, 2, false),
        ("max_connect_attempts 0", 3, 4, true),
        ("max_connect_attempts 5", 3, 4, true),
    ] {
        let fake = tcp_fake(failed_before_success).await;
        let chain = configure_chain(&format!(
            "forward . {} {{\nforce_tcp\nmax_fails 0\n{setting}\n}}",
            fake.addr
        ))
        .unwrap();
        let (outcome, wire) = query(&chain).await;
        assert_eq!(
            outcome,
            if success {
                Outcome::Response
            } else {
                Outcome::Unanswered(Rcode::SERVFAIL)
            },
            "{setting}"
        );
        if success {
            assert_eq!(Message::parse(&wire).unwrap().rcode(), Rcode::NOERROR);
        }
        assert_eq!(counts(&[&fake]), vec![expected_attempts], "{setting}");
    }
}

// CoreDNS forward_test.go TestForward_DefaultConnectAttemptCap.
#[tokio::test]
async fn default_connect_attempt_cap_is_twice_the_number_of_upstreams() {
    let a = tcp_fake(10).await;
    let b = tcp_fake(10).await;
    let c = tcp_fake(10).await;
    let chain = configure_chain(&format!(
        "forward . {} {} {} {{\npolicy sequential\nforce_tcp\nmax_fails 0\n}}",
        a.addr, b.addr, c.addr
    ))
    .unwrap();
    assert_eq!(query(&chain).await.0, Outcome::Unanswered(Rcode::SERVFAIL));
    assert_eq!(counts(&[&a, &b, &c]), vec![2, 2, 2]);
}

// CoreDNS setup_test.go TestNextAlternate, exercised with actual responses.
#[tokio::test]
async fn next_rcodes_only_pass_matching_responses_to_the_next_forward() {
    for (rcode, expected_rcode, second_count) in [(3, 0, 1), (2, 0, 1), (5, 5, 0)] {
        let first = udp_fake(rcode, None).await;
        let second = udp_fake(0, Some(2)).await;
        let chain = configure_chain(&format!(
            "forward . {} {{\nnext NXDOMAIN SERVFAIL\n}}\nforward . {}",
            first.addr, second.addr
        ))
        .unwrap();
        let (outcome, wire) = query(&chain).await;
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(Message::parse(&wire).unwrap().rcode().0, expected_rcode);
        assert_eq!(counts(&[&first, &second]), vec![1, second_count]);
    }
}

// CoreDNS resolve_test.go TestSetupWithHostnameTO and TestExpandAndDedup.
#[tokio::test]
async fn resolver_expands_hostname_and_deduplicates_numeric_address() {
    let first = udp_fake(0, Some(1)).await;
    let second = udp_fake(0, Some(2)).await;
    let resolver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    resolver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let resolver_addr = resolver.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let mut wire = [0; 512];
        for qtype in [1, 28] {
            let (len, peer) = resolver.recv_from(&mut wire).unwrap();
            let message = Message::parse(&wire[..len]).unwrap();
            let question = message.questions().next().unwrap();
            assert_eq!(question.name.to_string(), "upstream.example.");
            assert_eq!(question.qtype.0, qtype);
            let mut reply = wire[..len].to_vec();
            reply[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            if qtype == 1 {
                reply[6..8].copy_from_slice(&1_u16.to_be_bytes());
                reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
            }
            resolver.send_to(&reply, peer).unwrap();
        }
    });
    let chain = configure_chain(&format!(
        "forward . upstream.example:{} dns://{} {} {{\nresolver {resolver_addr}\npolicy round_robin\n}}",
        first.addr.port(), first.addr, second.addr
    )).unwrap();
    worker.join().unwrap();
    for expected in [2, 1, 2] {
        let (outcome, wire) = query(&chain).await;
        assert_eq!(outcome, Outcome::Response);
        assert_eq!(
            Message::parse(&wire)
                .unwrap()
                .answers()
                .next()
                .unwrap()
                .rdata[3],
            expected
        );
    }
    assert_eq!(counts(&[&first, &second]), vec![1, 2]);
}

// CoreDNS health_test.go TestHealth, TestHealthNoRecursion, TestHealthDomain and TestHealthNoMaxFails.
#[tokio::test]
async fn failed_query_triggers_configured_health_probe_unless_disabled() {
    for (health_options, max_fails, expected_name, expected_rd) in [
        ("", 2, ".", true),
        ("health_check 10ms no_rec", 2, ".", false),
        (
            "health_check 10ms domain example.org",
            2,
            "example.org.",
            true,
        ),
        ("health_check 10ms", 0, ".", true),
    ] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let (probe_tx, probe_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut wire = [0; 512];
            let _ = socket.recv_from(&mut wire).await.unwrap();
            let (len, peer) = socket.recv_from(&mut wire).await.unwrap();
            let probe = Message::parse(&wire[..len]).unwrap();
            let question = probe.questions().next().unwrap();
            let details = (question.name.to_string(), question.qtype.0, probe.rd());
            wire[2] |= 0x80;
            socket.send_to(&wire[..len], peer).await.unwrap();
            let _ = probe_tx.send(details);
        });
        let chain = configure_chain(&format!(
            "forward . {addr} {{\nread_timeout 10ms\nmax_connect_attempts 1\nmax_fails {max_fails}\n{health_options}\n}}"
        )).unwrap();
        assert_eq!(query(&chain).await.0, Outcome::Unanswered(Rcode::SERVFAIL));
        let probe = tokio::time::timeout(Duration::from_millis(200), probe_rx).await;
        if max_fails == 0 {
            assert!(probe.is_err(), "health checks must be disabled");
        } else {
            assert_eq!(
                probe.unwrap().unwrap(),
                (expected_name.to_owned(), 2, expected_rd)
            );
        }
        task.abort();
    }
}
