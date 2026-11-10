//! On-demand upstream health checks, independent of the forwarding transport.

use pharos_proto::{Message, Name, Opcode};
use pharos_server::metrics::ProxyMetrics;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    task::JoinHandle,
    time::{sleep, timeout},
};

const DIAL_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_secs(1);

/// Settings for on-demand checks of one upstream.
#[derive(Clone)]
pub struct HealthConfig {
    pub address: SocketAddr,
    pub domain: Name,
    pub recursive: bool,
    pub force_tcp: bool,
    pub source_address: Option<IpAddr>,
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
            domain: ".".parse().expect("root is a valid DNS name"),
            recursive: true,
            force_tcp: false,
            source_address: None,
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
                        state.running = false;
                        return;
                    }
                    let _ =
                        shared
                            .fails
                            .try_update(Ordering::Relaxed, Ordering::Relaxed, |fails| {
                                Some(fails.saturating_add(1))
                            });
                    if let Some(metrics) = &shared.config.metrics {
                        metrics.healthcheck_failure();
                    }
                }
                sleep(shared.config.interval).await;
            }
        }));
    }

    /// Whether failed checks strictly exceed the configured threshold.
    #[must_use]
    pub fn down(&self) -> bool {
        self.shared.config.max_fails != 0 && self.fails() > self.shared.config.max_fails
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

impl Drop for Health {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn check(config: &HealthConfig) -> io::Result<()> {
    let mut id = [0; 2];
    getrandom::getrandom(&mut id).map_err(|_| io::Error::other("random ID generation failed"))?;
    let mut query = Vec::with_capacity(12 + config.domain.as_wire().len() + 4);
    query.extend_from_slice(&id);
    query.extend_from_slice(&[u8::from(config.recursive), 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    query.extend_from_slice(config.domain.as_wire());
    query.extend_from_slice(&[0, 2, 0, 1]);

    let response = if config.force_tcp {
        let mut stream = timeout(
            DIAL_TIMEOUT,
            super::connect_tcp(config.address, config.source_address),
        )
        .await??;
        timeout(IO_TIMEOUT, async {
            stream
                .write_all(&(query.len() as u16).to_be_bytes())
                .await?;
            stream.write_all(&query).await
        })
        .await??;
        timeout(IO_TIMEOUT, async {
            let len = stream.read_u16().await?;
            let mut response = vec![0; usize::from(len)];
            stream.read_exact(&mut response).await?;
            Ok::<_, io::Error>(response)
        })
        .await??
    } else {
        let ip = if config.address.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let socket = timeout(DIAL_TIMEOUT, async {
            let socket =
                UdpSocket::bind(SocketAddr::new(config.source_address.unwrap_or(ip), 0)).await?;
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

    // CoreDNS treats even a partially decoded response as healthy if its header is sane.
    if Message::parse(&response).is_ok()
        || (response.len() >= 12
            && (response[2] & 0x80 != 0 || (response[2] >> 3) & 15 == Opcode::QUERY.0))
    {
        Ok(())
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_proto::{Class, Message, Type};
    use tokio::{
        net::{TcpListener, UdpSocket},
        time::timeout,
    };

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
