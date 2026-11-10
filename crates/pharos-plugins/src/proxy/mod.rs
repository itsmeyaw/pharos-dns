//! Upstream DNS exchange. Independent cache shards hold idle connections only;
//! no lock or manager task is held while a Query waits for its Response.
//! DNS-over-TLS is deferred to M3.
//! CoreDNS's `forward` performs the `prefer_udp` TC retry; Pharos does it here,
//! so a `forward` caller must not retry the same truncated Response again.

pub mod health;
pub use health::{Health, HealthConfig};

use pharos_proto::{Message, MessageError, NameError, Rcode, Type};
use pharos_server::metrics::{ProxyConnectionCache, ProxyMetrics, ProxyRequestDuration, Registry};
use std::{
    collections::VecDeque,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream, UdpSocket},
    time::timeout,
};

const SHARDS: usize = 32;
static NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);
thread_local! { static SHARD: usize = NEXT_SHARD.fetch_add(1, Ordering::Relaxed) % SHARDS; }
const EXPIRE: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(target_os = "linux")]
fn enable_recv_err(socket: &UdpSocket, address: SocketAddr) {
    use nix::sys::socket::{
        setsockopt,
        sockopt::{Ipv4RecvErr, Ipv6RecvErr},
    };
    let result = if address.is_ipv4() {
        setsockopt(socket, Ipv4RecvErr, &true)
    } else {
        setsockopt(socket, Ipv6RecvErr, &true)
    };
    if let Err(error) = result {
        pharos_server::logging::log(
            "WARN",
            "proxy",
            &format!("failed to enable UDP error queue: {error}"),
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn enable_recv_err(_: &UdpSocket, _: SocketAddr) {}

async fn connect_tcp(address: SocketAddr, source: Option<IpAddr>) -> io::Result<TcpStream> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(source) = source {
        socket.bind(SocketAddr::new(source, 0))?;
    }
    socket.connect(address).await
}

fn is_overflow(error: &MessageError) -> bool {
    matches!(
        error,
        MessageError::Truncated | MessageError::Name(NameError::Truncated)
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub force_tcp: bool,
    pub prefer_udp: bool,
}

#[derive(Debug)]
pub enum Error {
    InvalidRequest,
    UnsupportedRequest,
    NoHealthy,
    NoForward,
    Stopped,
    Mismatch,
    CachedClosed,
    Io(io::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => f.write_str("invalid Query"),
            Self::UnsupportedRequest => f.write_str("unsupported Query"),
            Self::NoHealthy => f.write_str("no healthy Upstreams"),
            Self::NoForward => f.write_str("no Upstream configured"),
            Self::Stopped => f.write_str("proxy: transport stopped"),
            Self::Mismatch => f.write_str("Upstream Response does not match Query"),
            Self::CachedClosed => f.write_str("cached connection was closed by peer"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug)]
pub struct Exchange {
    pub len: usize,
    pub local_addr: SocketAddr,
    pub transport: Transport,
}

struct Cached {
    socket: Socket,
    created: Instant,
    used: Instant,
}

enum Socket {
    Udp(UdpSocket),
    Tcp(TcpStream),
}

impl Socket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Udp(s) => s.local_addr(),
            Self::Tcp(s) => s.local_addr(),
        }
    }
    async fn send(&mut self, wire: &[u8]) -> io::Result<()> {
        match self {
            Self::Udp(s) => {
                s.send(wire).await?;
                Ok(())
            }
            Self::Tcp(s) => {
                s.write_all(&(wire.len() as u16).to_be_bytes()).await?;
                s.write_all(wire).await
            }
        }
    }
    async fn receive(&mut self, wire: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Udp(s) => s.recv(wire).await,
            Self::Tcp(s) => {
                let len = usize::from(s.read_u16().await?);
                if len > wire.len() {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                s.read_exact(&mut wire[..len]).await?;
                Ok(len)
            }
        }
    }
}

pub struct Proxy {
    address: SocketAddr,
    shards: [[Mutex<VecDeque<Cached>>; SHARDS]; 2],
    expire: Duration,
    max_age: Duration,
    max_idle_conns: usize,
    idle: [AtomicUsize; 2],
    stopped: AtomicBool,
    started: Instant,
    next_sweep: AtomicU64,
    read_timeout: Duration,
    average_dial_nanos: AtomicI64,
    source_address: Option<IpAddr>,
    metrics: Option<Metrics>,
    health: Health,
}

struct Metrics {
    proxy: ProxyMetrics,
    cache: [ProxyConnectionCache; 2],
    durations: Box<[OnceLock<ProxyRequestDuration>]>,
}

impl Proxy {
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            shards: std::array::from_fn(|_| std::array::from_fn(|_| Mutex::new(VecDeque::new()))),
            expire: EXPIRE,
            max_age: Duration::ZERO,
            max_idle_conns: 0,
            idle: [AtomicUsize::new(0), AtomicUsize::new(0)],
            stopped: AtomicBool::new(false),
            started: Instant::now(),
            next_sweep: AtomicU64::new(EXPIRE.as_nanos() as u64),
            read_timeout: READ_TIMEOUT,
            average_dial_nanos: AtomicI64::new(15_000_000_000),
            source_address: None,
            metrics: None,
            health: Health::new(address, 2),
        }
    }

    /// Set the maximum idle time before an Upstream connection is discarded.
    pub fn set_expire(&mut self, expire: Duration) {
        self.expire = expire;
        self.next_sweep
            .store(self.sweep_deadline(), Ordering::Relaxed);
    }

    fn sweep_deadline(&self) -> u64 {
        self.started
            .elapsed()
            .as_nanos()
            .saturating_add(self.expire.as_nanos())
            .min(u128::from(u64::MAX)) as u64
    }

    fn sweep(&self) {
        let now = self.started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
        let next = self.next_sweep.load(Ordering::Relaxed);
        if now < next
            || self
                .next_sweep
                .compare_exchange(
                    next,
                    self.sweep_deadline(),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return;
        }
        // shortcut: without traffic expired sockets remain until stop; add a timer if idle cleanup is required.
        for (protocol, shard) in self
            .shards
            .iter()
            .enumerate()
            .flat_map(|(p, s)| s.iter().map(move |s| (p, s)))
        {
            let mut queue = shard.lock().unwrap();
            let before = queue.len();
            queue.retain(|conn| {
                conn.used.elapsed() <= self.expire
                    && (self.max_age.is_zero() || conn.created.elapsed() <= self.max_age)
            });
            self.idle[protocol].fetch_sub(before - queue.len(), Ordering::Relaxed);
        }
    }

    /// Stop probes and close all idle Upstream connections.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.health.shutdown();
        for (protocol, shard) in self
            .shards
            .iter()
            .enumerate()
            .flat_map(|(p, s)| s.iter().map(move |s| (p, s)))
        {
            let mut queue = shard.lock().unwrap();
            self.idle[protocol].fetch_sub(queue.len(), Ordering::Relaxed);
            queue.clear();
        }
    }

    /// Limit idle connections per Transport for this Upstream; zero means unlimited.
    pub fn set_max_idle_conns(&mut self, max: usize) {
        self.max_idle_conns = max;
    }

    /// Set maximum connection age from creation; zero means unlimited.
    pub fn set_max_age(&mut self, max_age: Duration) {
        self.max_age = max_age;
    }

    /// Set the Response read timeout (two seconds by default).
    pub fn set_read_timeout(&mut self, read_timeout: Duration) {
        self.read_timeout = read_timeout;
    }

    fn dial_timeout(&self) -> Duration {
        let average = self.average_dial_nanos.load(Ordering::Relaxed);
        Duration::from_nanos(if average < 1_000_000_000 {
            1_000_000_000
        } else if average < 15_000_000_000 {
            (2 * average) as u64
        } else {
            30_000_000_000
        })
    }

    fn update_dial_timeout(&self, duration: Duration) {
        let average = self.average_dial_nanos.load(Ordering::Relaxed);
        let observed = duration.as_nanos().min(i64::MAX as u128) as i64;
        self.average_dial_nanos
            .fetch_add((observed - average) / 4, Ordering::Relaxed);
    }

    async fn dial(&self, transport: Transport) -> io::Result<Socket> {
        let start = Instant::now();
        let result = timeout(self.dial_timeout(), async {
            if transport == Transport::Tcp {
                Ok(Socket::Tcp(
                    connect_tcp(self.address, self.source_address).await?,
                ))
            } else {
                let ip = if self.address.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                };
                let socket =
                    UdpSocket::bind(SocketAddr::new(self.source_address.unwrap_or(ip), 0)).await?;
                enable_recv_err(&socket, self.address);
                socket.connect(self.address).await?;
                Ok(Socket::Udp(socket))
            }
        })
        .await;
        self.update_dial_timeout(start.elapsed());
        result.map_err(|_| io::ErrorKind::TimedOut)?
    }

    /// Bind new Upstream and health-check connections to this local IP.
    pub fn set_source_address(&mut self, source: Option<IpAddr>) {
        if source == self.source_address {
            return;
        }
        for shard in self.shards.iter_mut().flatten() {
            shard.get_mut().unwrap().clear();
        }
        for idle in &self.idle {
            idle.store(0, Ordering::Relaxed);
        }
        self.source_address = source;
        let mut config = self.health.config();
        config.source_address = source;
        self.health = Health::with_config(config);
    }

    /// Register the Upstream's metrics with the server's exporter.
    pub fn set_metrics(&mut self, registry: &Registry, name: &str) {
        let proxy = registry.proxy(name, &self.address.to_string());
        let mut config = self.health.config();
        config.metrics = Some(proxy.clone());
        self.health = Health::with_config(config);
        self.metrics = Some(Metrics {
            cache: [proxy.connection_cache("udp"), proxy.connection_cache("tcp")],
            durations: (0..4096).map(|_| OnceLock::new()).collect(),
            proxy,
        });
    }

    /// Configure health checks before starting exchanges.
    pub fn set_health_config(&mut self, mut config: HealthConfig) {
        assert_eq!(config.address, self.address);
        if config.source_address.is_none() {
            config.source_address = self.source_address;
        }
        if let Some(metrics) = &self.metrics {
            config.metrics = Some(metrics.proxy.clone());
        }
        self.health = Health::with_config(config);
    }

    #[must_use]
    pub fn down(&self) -> bool {
        self.health.down()
    }
    pub async fn exchange(
        &self,
        query: &[u8],
        response: &mut [u8],
        transport: Transport,
        options: Options,
    ) -> Result<Exchange, Error> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(Error::Stopped);
        }
        self.sweep();
        let selected = if options.force_tcp {
            Transport::Tcp
        } else if options.prefer_udp {
            Transport::Udp
        } else {
            transport
        };
        let result = self.exchange_once(query, response, selected).await;
        let result = match result {
            Ok(_result)
                if selected == Transport::Udp
                    && options.prefer_udp
                    && !options.force_tcp
                    && response[2] & 0x02 != 0 =>
            {
                self.exchange_once(query, response, Transport::Tcp).await
            }
            other => other,
        };
        if matches!(result, Err(Error::Io(_))) {
            self.health.start();
        }
        result
    }

    async fn exchange_once(
        &self,
        query: &[u8],
        response: &mut [u8],
        transport: Transport,
    ) -> Result<Exchange, Error> {
        let start = Instant::now();
        let request = Message::parse(query).map_err(|_| Error::InvalidRequest)?;
        if query.len() > response.len() || query.len() > u16::MAX as usize {
            return Err(Error::InvalidRequest);
        }
        let protocol = usize::from(transport == Transport::Tcp);
        let shard = SHARD.with(|index| *index);
        let cached = {
            let mut queue = self.shards[protocol][shard].lock().unwrap();
            loop {
                match queue.pop_front() {
                    Some(cached) => {
                        self.idle[protocol].fetch_sub(1, Ordering::Relaxed);
                        if cached.used.elapsed() <= self.expire
                            && (self.max_age.is_zero() || cached.created.elapsed() <= self.max_age)
                        {
                            break Some(cached);
                        }
                    }
                    None => break None,
                }
            }
        };
        let reused = cached.is_some();
        if let Some(metrics) = &self.metrics {
            if reused {
                metrics.cache[protocol].hit();
            } else {
                metrics.cache[protocol].miss();
            }
        }
        let (mut socket, created) = if let Some(cached) = cached {
            (cached.socket, cached.created)
        } else {
            (self.dial(transport).await?, Instant::now())
        };
        let mut id = [0; 2];
        if request
            .additionals()
            .any(|record| record.rtype == Type::TSIG)
        {
            id.copy_from_slice(&query[..2]);
        } else {
            getrandom::getrandom(&mut id)
                .map_err(|_| Error::Io(io::Error::other("random ID generation failed")))?;
        }
        response[..query.len()].copy_from_slice(query);
        response[..2].copy_from_slice(&id);
        let local_addr = socket.local_addr()?;
        let sent = timeout(READ_TIMEOUT, socket.send(&response[..query.len()]))
            .await
            .map_err(|_| Error::Io(io::ErrorKind::TimedOut.into()))?;
        if let Err(err) = sent {
            return Err(if reused && err.kind() == io::ErrorKind::UnexpectedEof {
                Error::CachedClosed
            } else {
                Error::Io(err)
            });
        }
        let received = timeout(self.read_timeout, async {
            loop {
                let len = socket.receive(response).await?;
                if len < 12 && transport == Transport::Tcp {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                if len >= 12 && response[..2] == id {
                    return Ok::<_, io::Error>(len);
                }
            }
        })
        .await
        .map_err(|_| Error::Io(io::ErrorKind::TimedOut.into()))?;
        let mut length = received.map_err(|err| {
            if reused && err.kind() == io::ErrorKind::UnexpectedEof {
                Error::CachedClosed
            } else {
                Error::Io(err)
            }
        })?;
        if let Err(error) = Message::parse(&response[..length]) {
            if transport != Transport::Udp || !is_overflow(&error) {
                return Err(Error::Io(io::ErrorKind::InvalidData.into()));
            }
            let counts: [u8; 6] = response[6..12].try_into().unwrap();
            response[6..12].fill(0);
            let question_matches = Message::parse(&response[..length]).is_ok_and(|answer| {
                answer.qr()
                    && request.question_count() == answer.question_count()
                    && request.questions().zip(answer.questions()).all(|(a, b)| {
                        a.name == b.name && a.qtype == b.qtype && a.qclass == b.qclass
                    })
            });
            response[6..12].copy_from_slice(&counts);
            if !question_matches {
                return Err(Error::Io(io::ErrorKind::InvalidData.into()));
            }
            length = 12
                + request
                    .questions()
                    .map(|q| q.name.wire_len() + 4)
                    .sum::<usize>();
            let flags = [response[2], response[3]];
            response[..length].copy_from_slice(&query[..length]);
            response[2] = flags[0] | 0x02;
            response[3] = flags[1];
            response[6..12].fill(0);
        }
        let answer = Message::parse(&response[..length])
            .map_err(|_| Error::Io(io::ErrorKind::InvalidData.into()))?;
        if let Some(metrics) = &self.metrics {
            let code = answer.rcode().0;
            // shortcut: first observation of an RCODE allocates; pre-register codes if cold traffic matters.
            metrics.durations[usize::from(code)]
                .get_or_init(|| metrics.proxy.request_duration(&Rcode(code).to_string()))
                .observe(start.elapsed().as_secs_f64());
        }
        let same_questions = request.question_count() == answer.question_count()
            && request
                .questions()
                .zip(answer.questions())
                .all(|(a, b)| a.name == b.name && a.qtype == b.qtype && a.qclass == b.qclass);
        if !answer.qr() || !same_questions {
            return Err(Error::Mismatch);
        }
        response[..2].copy_from_slice(&query[..2]);
        {
            let mut queue = self.shards[protocol][shard].lock().unwrap();
            if !self.stopped.load(Ordering::Acquire)
                && self.idle[protocol]
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                        (self.max_idle_conns == 0 || count < self.max_idle_conns).then(|| count + 1)
                    })
                    .is_ok()
            {
                queue.push_back(Cached {
                    socket,
                    created,
                    used: Instant::now(),
                });
            }
        }
        Ok(Exchange {
            len: length,
            local_addr,
            transport,
        })
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn udp_sockets_enable_error_queues_for_both_families() {
        use nix::sys::socket::{
            getsockopt,
            sockopt::{Ipv4RecvErr, Ipv6RecvErr},
        };
        let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        enable_recv_err(&v4, v4.local_addr().unwrap());
        assert!(getsockopt(&v4, Ipv4RecvErr).unwrap());
        let v6 = UdpSocket::bind("[::1]:0").await.unwrap();
        enable_recv_err(&v6, v6.local_addr().unwrap());
        assert!(getsockopt(&v6, Ipv6RecvErr).unwrap());
    }

    #[test]
    fn adaptive_dial_timeout_uses_weighted_average_and_bounds() {
        let proxy = Proxy::new("127.0.0.1:53".parse().unwrap());
        assert_eq!(proxy.dial_timeout(), Duration::from_secs(30));
        proxy.update_dial_timeout(Duration::from_secs(3));
        assert_eq!(proxy.dial_timeout(), Duration::from_secs(24));
        for _ in 0..40 {
            proxy.update_dial_timeout(Duration::ZERO);
        }
        assert_eq!(proxy.dial_timeout(), Duration::from_secs(1));
        proxy.update_dial_timeout(Duration::from_secs(120));
        assert_eq!(proxy.dial_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn only_truncated_message_and_name_errors_are_overflows() {
        for (error, expected) in [
            (MessageError::Truncated, true),
            (MessageError::Name(NameError::Truncated), true),
            (MessageError::Name(NameError::InvalidLabelType), false),
            (MessageError::Name(NameError::PointerNotBackwards), false),
            (MessageError::InvalidOpt, false),
        ] {
            assert_eq!(is_overflow(&error), expected, "{error:?}");
        }
    }
}
