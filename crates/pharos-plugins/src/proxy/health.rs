//! On-demand upstream health checks, independent of the forwarding transport.

use pharos_proto::{Class, Name, NameRef, Opcode, Type};
use pharos_server::metrics::ProxyMetrics;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::UdpSocket,
    task::JoinHandle,
    time::{sleep, timeout},
};

const DIAL_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_secs(1);
// RFC 2308 §7.2: Dead-server state expires after five minutes.
const DOWN_TTL_SECS: u64 = 300;

/// Settings for on-demand checks of one upstream.
#[derive(Clone)]
pub struct HealthConfig {
    pub address: SocketAddr,
    pub domain: Name,
    pub recursive: bool,
    pub force_tcp: bool,
    pub source_address: Option<IpAddr>,
    /// Probe over DNS-over-TLS instead of UDP or TCP.
    pub tls: Option<super::Tls>,
    /// Probe over DNS-over-QUIC, sharing the Upstream's connection.
    pub doq: Option<std::sync::Arc<super::Doq>>,
    /// Probe over DNS-over-HTTPS instead of UDP or TCP.
    pub https: Option<super::Https>,
    pub max_fails: u32,
    pub interval: Duration,
    pub metrics: Option<ProxyMetrics>,
}

impl HealthConfig {
    /// Defaults to recursive `. IN NS` checks over UDP every 500ms.
    #[must_use]
    pub fn new(address: SocketAddr, max_fails: u32) -> Self {
        Self {
            address,
            // RFC 1035 §4.1.2: The default health query asks about the root domain.
            domain: ".".parse().expect("root is a valid DNS name"),
            recursive: true,
            force_tcp: false,
            source_address: None,
            tls: None,
            doq: None,
            https: None,
            max_fails,
            interval: Duration::from_millis(500),
            metrics: None,
        }
    }
}

#[derive(Default)]
struct State {
    running: bool,
    shutdown: bool,
    generation: u64,
    task: Option<JoinHandle<()>>,
}

struct Shared {
    config: HealthConfig,
    state: Mutex<State>,
    fails: AtomicU32,
    started: Instant,
    down_since_secs: AtomicU64,
}

/// A single upstream's on-demand probe and consecutive failed-check count.
pub struct Health {
    shared: Arc<Shared>,
}

impl Health {
    pub(super) fn config(&self) -> HealthConfig {
        self.shared.config.clone()
    }
    #[must_use]
    pub fn new(address: SocketAddr, max_fails: u32) -> Self {
        Self::with_config(HealthConfig::new(address, max_fails))
    }

    #[must_use]
    pub fn with_config(config: HealthConfig) -> Self {
        Self {
            shared: Arc::new(Shared {
                config,
                state: Mutex::new(State::default()),
                fails: AtomicU32::new(0),
                started: Instant::now(),
                down_since_secs: AtomicU64::new(u64::MAX),
            }),
        }
    }

    /// Starts one probe loop after an exchange error; concurrent calls are coalesced.
    /// Must be called from a Tokio runtime. `max_fails == 0` disables probing.
    pub fn start(&self) {
        if self.shared.config.max_fails == 0 {
            return;
        }
        let mut state = self.shared.state.lock().unwrap();
        if state.shutdown {
            return;
        }
        if state.running && state.task.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        state.running = true;
        state.generation = state.generation.wrapping_add(1);
        let generation = state.generation;
        let shared = Arc::clone(&self.shared);
        state.task = Some(tokio::spawn(async move {
            loop {
                let healthy = check(&shared.config).await.is_ok();
                {
                    let mut state = shared.state.lock().unwrap();
                    if state.generation != generation {
                        return;
                    }
                    if healthy {
                        shared.fails.store(0, Ordering::Relaxed);
                        shared.down_since_secs.store(u64::MAX, Ordering::Relaxed);
                        state.running = false;
                        return;
                    }
                    record_failure(&shared);
                }
                sleep(shared.config.interval).await;
            }
        }));
    }

    /// Whether failed checks strictly exceed the configured threshold.
    #[must_use]
    pub fn down(&self) -> bool {
        let since = self.shared.down_since_secs.load(Ordering::Relaxed);
        let max_fails = self.shared.config.max_fails;
        if max_fails == 0 || self.fails() <= max_fails || since == u64::MAX {
            return false;
        }
        !down_expired(since, self.shared.started.elapsed().as_secs())
    }

    /// Consecutive failed checks, reset to zero by a successful check.
    #[must_use]
    pub fn fails(&self) -> u32 {
        self.shared.fails.load(Ordering::Relaxed)
    }

    /// Cancels any current probe and closes its socket on cancellation.
    pub fn stop(&self) {
        let mut state = self.shared.state.lock().unwrap();
        if let Some(task) = state.task.take() {
            task.abort();
        }
        state.running = false;
        state.generation = state.generation.wrapping_add(1);
    }

    pub(super) fn shutdown(&self) {
        let mut state = self.shared.state.lock().unwrap();
        state.shutdown = true;
        if let Some(task) = state.task.take() {
            task.abort();
        }
        state.running = false;
        state.generation = state.generation.wrapping_add(1);
    }
}

fn down_expired(since_secs: u64, now_secs: u64) -> bool {
    // RFC 2308 §7.2: Dead-server indications expire no later than five minutes.
    now_secs.saturating_sub(since_secs) >= DOWN_TTL_SECS
}

fn record_failure(shared: &Shared) {
    let elapsed = shared.started.elapsed().as_secs();
    // RFC 2308 §7.2: Expire old dead-server state before recording this failure.
    reset_expired_down_window(
        &shared.fails,
        &shared.down_since_secs,
        shared.config.max_fails,
        elapsed,
    );
    let _ = shared
        .fails
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |fails| {
            Some(fails.saturating_add(1))
        });
    if shared.fails.load(Ordering::Relaxed) > shared.config.max_fails {
        let _ = shared.down_since_secs.compare_exchange(
            u64::MAX,
            elapsed,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
    if let Some(metrics) = &shared.config.metrics {
        metrics.healthcheck_failure();
    }
}

fn reset_expired_down_window(
    fails: &AtomicU32,
    down_since_secs: &AtomicU64,
    max_fails: u32,
    now_secs: u64,
) {
    let since = down_since_secs.load(Ordering::Relaxed);
    if fails.load(Ordering::Relaxed) > max_fails
        && since != u64::MAX
        && down_expired(since, now_secs)
    {
        // RFC 2308 §7.2: Re-arm the five-minute dead-server expiry after it elapses.
        fails.store(0, Ordering::Relaxed);
        down_since_secs.store(u64::MAX, Ordering::Relaxed);
    }
}

impl Drop for Health {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn check(config: &HealthConfig) -> io::Result<()> {
    // RFC 5452 §9.2: outgoing queries use unpredictable IDs.
    let mut id = [0; 2];
    // RFC 9250 §4.2.1: DoQ Queries carry Message ID zero.
    if config.doq.is_none() {
        getrandom::getrandom(&mut id)
            .map_err(|_| io::Error::other("random ID generation failed"))?;
    }
    let mut query = Vec::with_capacity(12 + config.domain.as_wire().len() + 4);
    query.extend_from_slice(&id);
    // RFC 1035 §4.1.1: RD requests recursive query processing.
    // RFC 9619 §4: A QUERY message contains no more than one question.
    query.extend_from_slice(&[u8::from(config.recursive), 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    // RFC 1035 §4.1.2: Encode the configured domain as the DNS QNAME.
    query.extend_from_slice(config.domain.as_wire());
    // RFC 1035 §3.2.2: NS has type 2.
    // RFC 1035 §3.2.4: IN has class 1.
    query.extend_from_slice(&[0, 2, 0, 1]);

    let response = if let Some(doq) = &config.doq {
        // CoreDNS v1.15.0 plugin/pkg/proxy/health.go doqHc: retry once when the peer closed a cached connection.
        let mut wire = vec![0; usize::from(u16::MAX)];
        wire[..query.len()].copy_from_slice(&query);
        let mut attempts = 0;
        let len = loop {
            match doq.exchange(&mut wire, query.len(), Some(IO_TIMEOUT)).await {
                Ok(reply) => break reply.len,
                Err(super::Error::CachedClosed) if attempts < 1 => attempts += 1,
                Err(super::Error::Io(error)) => return Err(error),
                Err(error) => return Err(io::Error::other(error)),
            }
        };
        wire.truncate(len);
        wire
    } else if let Some(https) = &config.https {
        let mut response = super::doh::probe(
            config.address,
            config.source_address,
            https,
            &query,
            DIAL_TIMEOUT,
            IO_TIMEOUT,
        )
        .await?;
        // RFC 8484 §4.1: the HTTP exchange, not the Message ID, ties the Response to the Query.
        if let Some(field) = response.get_mut(..2) {
            field.copy_from_slice(&id);
        }
        response
    } else if let Some(tls) = &config.tls {
        // CoreDNS v1.15.0 plugin/pkg/proxy/health.go: a DoT probe's dial timeout covers the handshake; force_tcp is moot.
        let mut stream = timeout(
            DIAL_TIMEOUT,
            super::connect_tls(config.address, config.source_address, tls),
        )
        .await??;
        framed_exchange(&mut stream, &query).await?
    } else if config.force_tcp {
        let mut stream = timeout(
            DIAL_TIMEOUT,
            super::connect_tcp(config.address, config.source_address),
        )
        .await??;
        framed_exchange(&mut stream, &query).await?
    } else {
        let ip = if config.address.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let socket = timeout(DIAL_TIMEOUT, async {
            let socket =
                // RFC 5452 §9.2: Bind port 0 for an ephemeral UDP source port.
                UdpSocket::bind(SocketAddr::new(config.source_address.unwrap_or(ip), 0)).await?;
            super::enable_recv_err(&socket, config.address);
            socket.connect(config.address).await?;
            Ok::<_, io::Error>(socket)
        })
        .await??;
        timeout(IO_TIMEOUT, socket.send(&query)).await??;
        let mut response = vec![0; usize::from(u16::MAX)];
        let len = timeout(IO_TIMEOUT, socket.recv(&mut response)).await??;
        response.truncate(len);
        response
    };

    if response_matches_query(&response, id, &config.domain) {
        Ok(())
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}

async fn framed_exchange(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    query: &[u8],
) -> io::Result<Vec<u8>> {
    timeout(IO_TIMEOUT, async {
        // RFC 1035 §4.2.2: TCP DNS messages have a two-octet length prefix.
        super::write_tcp_frame(stream, query).await
    })
    .await??;
    timeout(IO_TIMEOUT, async {
        // RFC 1035 §4.2.2: TCP DNS messages have a two-octet length prefix.
        let len = stream.read_u16().await?;
        let mut response = vec![0; usize::from(len)];
        stream.read_exact(&mut response).await?;
        Ok::<_, io::Error>(response)
    })
    .await?
}

fn response_matches_query(response: &[u8], id: [u8; 2], domain: &Name) -> bool {
    // RFC 5452 §4.2: Match response ID, QR, opcode, and Question without decoding answer RDATA.
    if response.len() < 12
        || response[..2] != id
        || response[2] & 0x80 == 0
        || response[2] & 0x78 != Opcode::QUERY.0 << 3
        || response[4..6] != [0, 1]
    {
        return false;
    }
    let Ok(name) = NameRef::parse(response, 12) else {
        return false;
    };
    let question_offset = 12 + name.wire_len();
    let Some(question) = response.get(question_offset..question_offset + 4) else {
        return false;
    };
    name == NameRef::parse(domain.as_wire(), 0).expect("valid health name")
        && u16::from_be_bytes([question[0], question[1]]) == Type::NS.0
        && u16::from_be_bytes([question[2], question[3]]) == Class::IN.0
}

#[cfg(test)]
mod tests {
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
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1,
            0, 0, 0, 30, 0, 4, 127,
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
}
