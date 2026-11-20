use super::*;
use pharos_proto::{Class, Message, Type};
use tokio::io::AsyncWriteExt;
use tokio::{
    net::{TcpListener, UdpSocket},
    time::timeout,
};

#[test]
fn down_state_expires_after_five_minutes() {
    assert!(!down_expired(10, 309));
    assert!(down_expired(10, 310));
    assert!(!down_expired(310, 10));
    let fails = AtomicU32::new(4);
    let down_since = AtomicU64::new(10);
    reset_expired_down_window(&fails, &down_since, 3, 310);
    assert_eq!(fails.load(Ordering::Relaxed), 0);
    assert_eq!(down_since.load(Ordering::Relaxed), u64::MAX);
}

#[test]
fn health_down_rearms_after_expiry_and_fresh_failures() {
    let mut health = Health::new("127.0.0.1:53".parse().unwrap(), 1);
    {
        let shared = Arc::get_mut(&mut health.shared).unwrap();
        shared.started = Instant::now() - Duration::from_secs(DOWN_TTL_SECS + 1);
        shared.fails.store(2, Ordering::Relaxed);
        shared.down_since_secs.store(0, Ordering::Relaxed);
    }
    assert!(!health.down());
    record_failure(Arc::get_mut(&mut health.shared).unwrap());
    assert!(!health.down());
    record_failure(Arc::get_mut(&mut health.shared).unwrap());
    assert!(health.down());
}

#[test]
fn matching_health_question_survives_malformed_answer_rdata() {
    let response = [
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0,
        0, 0, 30, 0, 4, 127,
    ];
    assert!(response_matches_query(
        &response,
        [0x12, 0x34],
        &".".parse().unwrap()
    ));
}

#[tokio::test]
async fn rejects_response_with_a_different_question() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = HealthConfig::new(server.local_addr().unwrap(), 1);
    config.domain = "example.org.".parse().unwrap();
    let check = tokio::spawn(async move { check(&config).await });
    let mut wire = [0; 512];
    let (len, peer) = timeout(Duration::from_secs(1), server.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    wire[2] |= 0x80;
    wire[len - 4..len - 2].copy_from_slice(&Type::A.0.to_be_bytes());
    server.send_to(&wire[..len], peer).await.unwrap();
    assert!(check.await.unwrap().is_err());
}

#[tokio::test]
async fn default_probe_sends_recursive_root_ns_over_udp() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let health = Health::new(server.local_addr().unwrap(), 2);
    health.start();
    let mut wire = [0; 512];
    let (len, peer) = timeout(Duration::from_secs(1), server.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    let message = Message::parse(&wire[..len]).unwrap();
    let question = message.questions().next().unwrap();
    assert_eq!(question.name.to_string(), ".");
    assert_eq!(question.qtype, Type::NS);
    assert_eq!(question.qclass, Class::IN);
    assert!(message.rd());
    wire[2] |= 0x80;
    server.send_to(&wire[..len], peer).await.unwrap();
}

#[tokio::test]
async fn failed_probe_updates_injected_metric_and_recovery_resets_fails() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let registry = pharos_server::metrics::Registry::new("test", "test", "test");
    let mut config = HealthConfig::new(server.local_addr().unwrap(), 1);
    config.metrics = Some(registry.proxy("forward", "test-upstream"));
    config.interval = Duration::from_millis(25);
    let health = Health::with_config(config);
    health.start();
    let mut wire = [0; 512];
    let (_, peer) = timeout(Duration::from_secs(1), server.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    server.send_to(&[0, 1], peer).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while health.fails() < 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!health.down());
    let (len, peer) = timeout(Duration::from_secs(1), server.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    server.send_to(&[0, 1], peer).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while !health.down() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (len2, peer) = timeout(Duration::from_secs(1), server.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(len, len2);
    wire[2] |= 0x80;
    wire[3] = 2; // SERVFAIL is still a response from a live upstream.
    server.send_to(&wire[..len2], peer).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while health.fails() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut text = String::new();
    registry.encode(&mut text);
    assert!(text.contains(
        "pharos_proxy_healthcheck_failures_total{proxy_name=\"forward\",to=\"test-upstream\"} 2"
    ));
    assert!(!health.down());
}

#[tokio::test]
async fn configured_probe_sends_nonrecursive_name_over_tcp() {
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = HealthConfig::new(server.local_addr().unwrap(), 2);
    config.domain = "example.org.".parse().unwrap();
    config.recursive = false;
    config.force_tcp = true;
    let health = Health::with_config(config);
    health.start();
    let (mut stream, _) = timeout(Duration::from_secs(1), server.accept())
        .await
        .unwrap()
        .unwrap();
    let len = stream.read_u16().await.unwrap();
    let mut wire = vec![0; usize::from(len)];
    stream.read_exact(&mut wire).await.unwrap();
    let message = Message::parse(&wire).unwrap();
    let question = message.questions().next().unwrap();
    assert_eq!(question.name.to_string(), "example.org.");
    assert_eq!(question.qtype, Type::NS);
    assert_eq!(question.qclass, Class::IN);
    assert!(!message.rd());
    wire[2] |= 0x80;
    wire[3] = 5;
    stream.write_u16(len).await.unwrap();
    stream.write_all(&wire).await.unwrap();
}

#[tokio::test]
async fn repeated_starts_share_one_probe_and_stop_closes_it() {
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = HealthConfig::new(server.local_addr().unwrap(), 1);
    config.force_tcp = true;
    let health = Health::with_config(config);
    health.start();
    let (mut stream, _) = timeout(Duration::from_secs(1), server.accept())
        .await
        .unwrap()
        .unwrap();
    let len = stream.read_u16().await.unwrap();
    let mut wire = vec![0; usize::from(len)];
    stream.read_exact(&mut wire).await.unwrap();
    for _ in 0..10 {
        health.start();
    }
    assert!(
        timeout(Duration::from_millis(50), server.accept())
            .await
            .is_err()
    );
    health.stop();
    assert_eq!(
        timeout(Duration::from_secs(1), stream.read(&mut wire))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    health.start();
    timeout(Duration::from_secs(1), server.accept())
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn zero_max_fails_disables_checks() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let health = Health::new(server.local_addr().unwrap(), 0);
    health.start();
    let mut wire = [0; 512];
    assert!(
        timeout(Duration::from_millis(50), server.recv_from(&mut wire))
            .await
            .is_err()
    );
    assert_eq!(health.fails(), 0);
    assert!(!health.down());
}

#[tokio::test]
async fn tcp_read_timeout_counts_as_a_failed_probe() {
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = HealthConfig::new(server.local_addr().unwrap(), 1);
    config.force_tcp = true;
    let health = Health::with_config(config);
    health.start();
    let (_stream, _) = timeout(Duration::from_secs(1), server.accept())
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), async {
        while health.fails() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(health.fails(), 1);
    assert!(!health.down());
}
