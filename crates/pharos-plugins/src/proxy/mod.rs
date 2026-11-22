//! Upstream DNS exchange. Independent cache shards hold idle connections only;
//! no lock or manager task is held while a Query waits for its Response.
//! DNS-over-TLS Upstreams keep one idle connection cache like TCP; the dial
//! timeout bounds the TCP dial plus the TLS handshake. DNS-over-QUIC Upstreams
//! share one QUIC connection and open a stream per Query (see [`doq`]).
//! DNS-over-HTTPS Upstreams keep one multiplexed HTTP/2 connection, or idle
//! HTTP/1.1 connections when the server does not offer `h2`.
//! CoreDNS's `forward` performs the `prefer_udp` TC retry; Pharos does it here,
//! so a `forward` caller must not retry the same truncated Response again.
//! UDP source ports: the OS picks a random port for each new socket, a socket
//! serves at most `UDP_MAX_USES` Queries before it closes, and at most
//! `UDP_MAX_IDLE` idle UDP sockets are retained per Upstream. Sockets in flight
//! are bounded only by concurrent Queries, never by a per-Query allocation.

pub mod doq;
pub use doq::Doq;
mod doh;
pub use doh::Https;
pub mod health;
pub use health::{Health, HealthConfig};

use pharos_proto::{
    ClientSubnet, EdnsOption, EdnsOptions, Message, MessageError, NameError, NameRef, Rcode, Type,
};
use pharos_server::{
    metrics::{ProxyConnectionCache, ProxyMetrics, ProxyRequestDuration, Registry},
    tls::{ClientConfig, ClientStream, ServerName, TlsConnector},
    write_tcp_frame,
};
use std::{
    cell::RefCell,
    collections::VecDeque,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::{TcpSocket, TcpStream, UdpSocket},
    time::{timeout, timeout_at},
};

const SHARDS: usize = 32;
static NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);
thread_local! { static SHARD: usize = NEXT_SHARD.fetch_add(1, Ordering::Relaxed) % SHARDS; }
const EXPIRE: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(2);
thread_local! { static RRSET_SCRATCH: RefCell<Vec<RecordIndex>> = const { RefCell::new(Vec::new()) }; }
// RFC 5452 §9.2: limit how many Queries share one unpredictable UDP source port.
const UDP_MAX_USES: u32 = 8;
const UDP_MAX_IDLE: usize = 256;

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

// RFC 5625 §4.4.1: Connect to DNS upstreams over TCP when TCP is selected.
async fn connect_tcp(address: SocketAddr, source: Option<IpAddr>) -> io::Result<TcpStream> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if let Some(source) = source {
        socket.bind(SocketAddr::new(source, 0))?;
    }
    // RFC 5452 §9.1: The connected TCP stream accepts responses only from this upstream.
    let stream = socket.connect(address).await?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// How an Upstream's DNS-over-TLS connections verify the server.
#[derive(Clone, Debug)]
pub struct Tls {
    pub config: Arc<ClientConfig>,
    /// Name the certificate must match, and the SNI sent.
    pub server_name: ServerName<'static>,
}

// RFC 7858 §3.1: DoT clients authenticate the server before sending Queries.
async fn connect_tls(
    address: SocketAddr,
    source: Option<IpAddr>,
    tls: &Tls,
) -> io::Result<ClientStream<TcpStream>> {
    let tcp = connect_tcp(address, source).await?;
    TlsConnector::from(Arc::clone(&tls.config))
        .connect(tls.server_name.clone(), tcp)
        .await
}

// RFC 1035 §4.2.2: TCP DNS messages have a two-octet length prefix.
async fn read_framed(stream: &mut (impl AsyncRead + Unpin), wire: &mut [u8]) -> io::Result<usize> {
    let len = usize::from(stream.read_u16().await?);
    if len > wire.len() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    stream.read_exact(&mut wire[..len]).await?;
    Ok(len)
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
    /// DNS over TLS (RFC 7858); chosen by the Upstream, never by `force_tcp` or `prefer_udp`.
    Tls,
    /// DNS over HTTPS (RFC 8484); chosen by the Upstream, never by `force_tcp` or `prefer_udp`.
    Https,
    /// DNS over QUIC (RFC 9250); chosen by the Upstream and never pooled like the others.
    Quic,
}

impl Transport {
    /// Transports with a metrics label; `Quic` counts its reuse in its own `Doq` cache.
    const COUNT: usize = 4;
    /// Transports that keep raw sockets in the per-shard caches.
    const SOCKETS: usize = 3;

    const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub force_tcp: bool,
    pub prefer_udp: bool,
    /// Latest moment a new DoT connection (TCP dial plus handshake) may still be completing.
    pub tls_connect_deadline: Option<tokio::time::Instant>,
}

#[derive(Debug)]
pub enum Error {
    InvalidRequest,
    UnsupportedRequest,
    Stopped,
    /// The Upstream reply (of this length, left in the Response buffer) does not match the Query.
    Mismatch(usize),
    CachedClosed,
    Io(io::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest => f.write_str("invalid Query"),
            Self::UnsupportedRequest => f.write_str("unsupported Query"),
            Self::Stopped => f.write_str("proxy: transport stopped"),
            Self::Mismatch(_) => f.write_str("Upstream Response does not match Query"),
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
    uses: u32,
}

fn next_use_count(transport: Transport, uses: u32) -> u32 {
    // RFC 5452 §9.2: Count UDP source-port reuse only; TCP sockets have no UDP budget.
    if transport == Transport::Udp {
        uses.saturating_add(1)
    } else {
        0
    }
}

enum Socket {
    Udp(UdpSocket),
    Tcp(TcpStream),
    Tls(Box<ClientStream<TcpStream>>),
}

fn ecs_option(message: &Message<'_>) -> Result<Option<ClientSubnet>, ()> {
    // RFC 7871 §6: Read ECS fields from the validated option view.
    let mut ecs = None;
    for option in message
        .opt()
        .into_iter()
        .flat_map(|opt| opt.options().iter())
    {
        if let EdnsOption::ClientSubnet(subnet) = option
            && ecs.replace(subnet).is_some()
        {
            return Err(());
        }
    }
    Ok(ecs)
}

pub(crate) fn has_ecs(message: &Message<'_>) -> bool {
    // RFC 7871 §6: Presence of ECS selects subnet-aware forwarding.
    message.opt().is_some_and(|opt| {
        opt.options()
            .iter()
            .any(|option| matches!(option, EdnsOption::ClientSubnet(_)))
    })
}

pub(crate) fn has_unsigned_ecs_message(message: &Message<'_>) -> bool {
    // RFC 7871 §6 and RFC 8945 §5.5: Detect rewritable ECS in one Additional scan.
    let mut has_ecs = false;
    for record in message.additionals() {
        if record.rtype == Type::TSIG {
            return false;
        }
        if record.rtype == Type::OPT {
            // Untrusted wire data: malformed options carry no ECS instead of panicking the worker.
            if let Ok(options) = EdnsOptions::parse(record.rdata) {
                has_ecs |= options
                    .iter()
                    .any(|option| matches!(option, EdnsOption::ClientSubnet(_)));
            }
        }
    }
    has_ecs
}

pub(crate) fn has_unsigned_ecs(query: &[u8]) -> bool {
    Message::parse(query).is_ok_and(|message| has_unsigned_ecs_message(&message))
}

fn keepalive_zero(message: &Message<'_>) -> bool {
    // RFC 7828 §3.2.2: A zero TIMEOUT asks the client to close after this response.
    message
        .opt()
        .into_iter()
        .flat_map(|opt| opt.options().iter())
        .any(|option| matches!(option, EdnsOption::TcpKeepalive(Some(0))))
}

fn same_ecs(request: &Message<'_>, response: &Message<'_>) -> bool {
    if request.opt().is_none() {
        return !has_ecs(response);
    }
    match (ecs_option(request), ecs_option(response)) {
        (Ok(Some(query)), Ok(Some(answer))) => {
            // RFC 7871 §7.3: Responses echo ECS family, source prefix, and address.
            query.family() == answer.family()
                && query.source_prefix() == answer.source_prefix()
                && query.address() == answer.address()
        }
        (Ok(Some(_)), Ok(None)) => true,
        (Ok(None), Ok(None)) => true,
        _ => false,
    }
}

#[derive(Clone, Copy)]
struct RecordIndex {
    name_hash: u32,
    ttl: u32,
    name_offset: u16,
    ttl_offset: u16,
    rtype: u16,
    class: u16,
}

#[derive(Clone, Copy)]
struct TtlNormalization {
    records: usize,
    changed: bool,
}

fn name_hash(name: NameRef<'_>) -> u32 {
    // RFC 4343 §3: Hash DNS labels without regard to ASCII letter case.
    let mut hash = 0x811c_9dc5_u32;
    for label in name.labels() {
        hash = (hash ^ label.len() as u32).wrapping_mul(0x0100_0193);
        for byte in label {
            hash = (hash ^ u32::from(byte.to_ascii_lowercase())).wrapping_mul(0x0100_0193);
        }
    }
    hash
}

fn compare_names(left: NameRef<'_>, right: NameRef<'_>) -> std::cmp::Ordering {
    // RFC 4343 §3: DNS label comparison ignores ASCII letter case.
    let mut left_labels = left.labels();
    let mut right_labels = right.labels();
    loop {
        match (left_labels.next(), right_labels.next()) {
            (Some(left), Some(right)) => {
                let order = left
                    .iter()
                    .map(|byte| byte.to_ascii_lowercase())
                    .cmp(right.iter().map(|byte| byte.to_ascii_lowercase()));
                if order != std::cmp::Ordering::Equal {
                    return order;
                }
            }
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
        }
    }
}

fn rrsets_ttl_normalization(message: &Message<'_>, wire: &[u8]) -> Result<TtlNormalization, ()> {
    // RFC 2181 §5.2: Treat each RRset's TTLs as its lowest received TTL.
    let mut ordinary = message
        .answers()
        .chain(message.authorities())
        .chain(message.additionals())
        .filter(|record| !matches!(record.rtype, Type::OPT | Type::TSIG));
    if ordinary.next().is_none() || ordinary.next().is_none() {
        return Ok(TtlNormalization {
            records: 0,
            changed: false,
        });
    }
    RRSET_SCRATCH.with(|scratch| {
        let Ok(mut indexes) = scratch.try_borrow_mut() else {
            return Err(());
        };
        indexes.clear();
        for records in [
            message.answers(),
            message.authorities(),
            message.additionals(),
        ] {
            for record in records {
                if matches!(record.rtype, Type::OPT | Type::TSIG) {
                    continue;
                }
                let name_offset = u16::try_from(record.name.offset()).map_err(|_| ())?;
                let ttl_offset = u16::try_from(record.ttl_offset).map_err(|_| ())?;
                indexes.push(RecordIndex {
                    name_hash: name_hash(record.name),
                    ttl: record.ttl,
                    name_offset,
                    ttl_offset,
                    rtype: record.rtype.0,
                    class: record.class.0,
                });
            }
        }
        indexes.sort_unstable_by(|left, right| {
            left.name_hash
                .cmp(&right.name_hash)
                .then(left.rtype.cmp(&right.rtype))
                .then(left.class.cmp(&right.class))
                .then_with(|| {
                    let same_name = NameRef::parse(wire, usize::from(left.name_offset))
                        .expect("Message validated RR owner");
                    let other_name = NameRef::parse(wire, usize::from(right.name_offset))
                        .expect("Message validated RR owner");
                    compare_names(same_name, other_name)
                })
                .then(left.ttl.cmp(&right.ttl))
        });
        let mut changed = false;
        let mut start = 0;
        while start < indexes.len() {
            let first = indexes[start];
            let mut end = start + 1;
            while end < indexes.len() {
                let next = indexes[end];
                if first.name_hash != next.name_hash
                    || first.rtype != next.rtype
                    || first.class != next.class
                {
                    break;
                }
                let first_name = NameRef::parse(wire, usize::from(first.name_offset))
                    .expect("Message validated RR owner");
                let next_name = NameRef::parse(wire, usize::from(next.name_offset))
                    .expect("Message validated RR owner");
                if compare_names(first_name, next_name) != std::cmp::Ordering::Equal {
                    break;
                }
                end += 1;
            }
            let lowest_ttl = indexes[start..end]
                .iter()
                .map(|record| record.ttl)
                .min()
                .expect("RRset group is non-empty");
            changed |= indexes[start..end]
                .iter()
                .any(|record| record.ttl != lowest_ttl);
            for record in &mut indexes[start..end] {
                record.ttl = lowest_ttl;
            }
            start = end;
        }
        Ok(TtlNormalization {
            records: indexes.len(),
            changed,
        })
    })
}

fn apply_rrset_ttl_normalization(wire: &mut [u8], records: usize) -> bool {
    RRSET_SCRATCH.with(|scratch| {
        let Ok(indexes) = scratch.try_borrow() else {
            return false;
        };
        let Some(indexes) = indexes.get(..records) else {
            return false;
        };
        for record in indexes {
            let offset = usize::from(record.ttl_offset);
            let Some(ttl) = wire.get_mut(offset..offset + 4) else {
                return false;
            };
            ttl.copy_from_slice(&record.ttl.to_be_bytes());
        }
        true
    })
}

fn opt_rdata_range(message: &Message<'_>, wire: &[u8]) -> Option<(usize, usize)> {
    let record = message
        .additionals()
        .find(|record| record.rtype == Type::OPT)?;
    // RFC 6891 §6.1.2: Parsed OPT RDATA borrows from this validated wire slice.
    Some((
        record.rdata.as_ptr() as usize - wire.as_ptr() as usize,
        record.rdata.len(),
    ))
}

fn sanitize_edns(
    wire: &mut [u8],
    length: usize,
    transport: Transport,
    remove_ecs: bool,
    opt_range: Option<(usize, usize)>,
) -> usize {
    let Some((start, old_len)) = opt_range else {
        return length;
    };
    let old_end = start + old_len;
    let mut read = start;
    let mut write = start;
    while read < old_end {
        let code = u16::from_be_bytes([wire[read], wire[read + 1]]);
        let data_len = usize::from(u16::from_be_bytes([wire[read + 2], wire[read + 3]]));
        let option_len = 4 + data_len;
        if code == 11
            && matches!(
                transport,
                Transport::Udp | Transport::Https | Transport::Quic
            )
        {
            // RFC 7828 §3.2.1: Never send TCP keepalive over UDP; HTTP manages its own connections (RFC 9113 §9.1).
            // RFC 9250 §5.5.2: DoQ Queries carry no edns-tcp-keepalive option.
            read += option_len;
            continue;
        }
        if code == 8 && remove_ecs {
            // RFC 7871 §7.1.3: Retry REFUSED Queries without ECS.
            read += option_len;
            continue;
        }
        if code == 11 {
            // RFC 7828 §3.2.1: TCP Queries carry a zero-length TIMEOUT option.
            wire.copy_within(read..read + 4, write);
            wire[write + 2..write + 4].fill(0);
            write += 4;
        } else {
            wire.copy_within(read..read + option_len, write);
            if code == 8 {
                // RFC 7871 §6: ECS queries use SCOPE PREFIX-LENGTH zero.
                wire[write + 7] = 0;
            }
            write += option_len;
        }
        read += option_len;
    }
    let new_len = write - start;
    wire.copy_within(old_end..length, write);
    wire[start - 2..start].copy_from_slice(&(new_len as u16).to_be_bytes());
    length - old_len + new_len
}

/// Build one reusable retry Query without the client's ECS option.
pub(crate) fn without_ecs(
    query: &[u8],
    output: &mut Vec<u8>,
    transport: Transport,
) -> Result<Option<usize>, Error> {
    let message = Message::parse(query).map_err(|_| Error::InvalidRequest)?;
    // RFC 8945 §5.5: An ECS-free retry cannot rewrite a signed Query.
    if message
        .additionals()
        .any(|record| record.rtype == Type::TSIG)
        || ecs_option(&message)
            .map_err(|_| Error::InvalidRequest)?
            .is_none()
    {
        return Ok(None);
    }
    let opt_range = opt_rdata_range(&message, query);
    output.clear();
    output.extend_from_slice(query);
    let len = sanitize_edns(output, query.len(), transport, true, opt_range);
    Ok(Some(len))
}

impl Socket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Udp(s) => s.local_addr(),
            Self::Tcp(s) => s.local_addr(),
            Self::Tls(s) => s.get_ref().0.local_addr(),
        }
    }
    async fn send(&mut self, wire: &[u8]) -> io::Result<()> {
        match self {
            // RFC 1035 §4.2.1: UDP DNS messages are carried in datagrams.
            Self::Udp(s) => {
                s.send(wire).await?;
                Ok(())
            }
            // RFC 1035 §4.2.2: TCP DNS messages have a two-octet length prefix.
            Self::Tcp(s) => write_tcp_frame(s, wire).await,
            // RFC 7858 §3.3: DoT frames Messages like TCP inside the TLS stream.
            Self::Tls(s) => write_tcp_frame(s, wire).await,
        }
    }
    async fn receive(&mut self, wire: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Udp(s) => s.recv(wire).await,
            // RFC 1035 §4.2.2: TCP DNS messages have a two-octet length prefix.
            Self::Tcp(s) => read_framed(s, wire).await,
            // RFC 7858 §3.3: DoT frames Messages like TCP inside the TLS stream.
            Self::Tls(s) => read_framed(s, wire).await,
        }
    }
}

pub struct Proxy {
    address: SocketAddr,
    shards: [[Mutex<VecDeque<Cached>>; SHARDS]; Transport::SOCKETS],
    expire: Duration,
    max_age: Duration,
    max_idle_conns: usize,
    udp_max_uses: u32,
    idle: [AtomicUsize; Transport::SOCKETS],
    stopped: AtomicBool,
    started: Instant,
    next_sweep: AtomicU64,
    read_timeout: Duration,
    average_dial_nanos: AtomicI64,
    source_address: Option<IpAddr>,
    tls: Option<Tls>,
    quic: Option<Arc<Doq>>,
    https: Option<Https>,
    https_pool: doh::Pool,
    metrics: Option<Metrics>,
    health: Health,
}

struct Metrics {
    proxy: ProxyMetrics,
    // Only the protocols this Upstream uses are registered, as in CoreDNS.
    cache: [Option<ProxyConnectionCache>; Transport::COUNT],
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
            udp_max_uses: UDP_MAX_USES,
            idle: std::array::from_fn(|_| AtomicUsize::new(0)),
            stopped: AtomicBool::new(false),
            started: Instant::now(),
            next_sweep: AtomicU64::new(EXPIRE.as_nanos() as u64),
            read_timeout: READ_TIMEOUT,
            average_dial_nanos: AtomicI64::new(15_000_000_000),
            source_address: None,
            tls: None,
            quic: None,
            https: None,
            https_pool: doh::Pool::default(),
            metrics: None,
            health: Health::new(address, 2),
        }
    }

    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Set the maximum idle time before an Upstream connection is discarded.
    pub fn set_expire(&mut self, expire: Duration) {
        self.expire = expire;
        if let Some(doq) = &self.quic {
            doq.set_expire(expire);
        }
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
        self.https_pool.retain(self.expire, self.max_age);
    }

    /// Stop probes and close all idle Upstream connections.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.health.shutdown();
        if let Some(doq) = &self.quic {
            doq.stop();
        }
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
        self.https_pool.clear();
    }

    /// Limit idle connections per Transport for this Upstream; zero means unlimited.
    pub fn set_max_idle_conns(&mut self, max: usize) {
        self.max_idle_conns = max;
    }

    /// Set how many Queries one UDP socket (and so one source port) serves; at least one.
    pub fn set_udp_max_uses(&mut self, max: u32) {
        self.udp_max_uses = max.max(1);
    }

    /// Set maximum connection age from creation; zero means unlimited.
    pub fn set_max_age(&mut self, max_age: Duration) {
        self.max_age = max_age;
        if let Some(doq) = &self.quic {
            doq.set_max_age(max_age);
        }
    }

    /// Set the Response read timeout (two seconds by default).
    pub fn set_read_timeout(&mut self, read_timeout: Duration) {
        self.read_timeout = read_timeout;
        if let Some(doq) = &self.quic {
            doq.set_read_timeout(read_timeout);
        }
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

    async fn dial(
        &self,
        transport: Transport,
        tls_connect_deadline: Option<tokio::time::Instant>,
    ) -> io::Result<Socket> {
        let start = Instant::now();
        let mut limit = tokio::time::Instant::now() + self.dial_timeout();
        if let (Transport::Tls, Some(deadline)) = (transport, tls_connect_deadline) {
            // CoreDNS v1.15.0 plugin/pkg/proxy/connect.go: the TLS connect deadline caps the TCP dial plus handshake.
            limit = limit.min(deadline);
        }
        let result = timeout_at(limit, async {
            if transport == Transport::Tls {
                let Some(tls) = &self.tls else {
                    return Err(io::Error::other("no TLS configuration for Upstream"));
                };
                Ok(Socket::Tls(Box::new(
                    connect_tls(self.address, self.source_address, tls).await?,
                )))
            } else if transport == Transport::Tcp {
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
                    // RFC 5625 §6.1: Let the OS select an ephemeral source port for DNS queries.
                    UdpSocket::bind(SocketAddr::new(self.source_address.unwrap_or(ip), 0)).await?;
                enable_recv_err(&socket, self.address);
                // RFC 5452 §9.1: Accept responses only from the queried upstream address and port.
                socket.connect(self.address).await?;
                Ok(Socket::Udp(socket))
            }
        })
        .await;
        self.update_dial_timeout(start.elapsed());
        result.map_err(|_| io::ErrorKind::TimedOut)?
    }

    /// Reach this Upstream over DNS-over-TLS, whatever Transport a Query asks for.
    /// Call before `set_metrics` so the connection cache is labelled `tcp-tls`.
    pub fn set_tls(&mut self, tls: Tls) {
        let mut config = self.health.config();
        config.tls = Some(tls.clone());
        self.health = Health::with_config(config);
        self.tls = Some(tls);
    }

    /// Reach this Upstream over DNS-over-HTTPS, whatever Transport a Query asks for.
    /// Call before `set_metrics` so the connection cache is labelled `https`.
    pub fn set_https(&mut self, https: Https) {
        let mut config = self.health.config();
        config.https = Some(https.clone());
        self.health = Health::with_config(config);
        self.https = Some(https);
    }

    /// Whether Queries to this Upstream travel over DNS-over-TLS.
    #[must_use]
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }

    /// Reach this Upstream over DNS-over-QUIC, whatever Transport a Query asks for.
    /// Call before `set_metrics` so connection reuse is counted under `quic`.
    pub fn set_quic(&mut self, tls: Tls) {
        let doq = Doq::new(self.address, tls);
        doq.set_expire(self.expire);
        doq.set_max_age(self.max_age);
        doq.set_read_timeout(self.read_timeout);
        doq.set_source_address(self.source_address);
        let mut config = self.health.config();
        config.doq = Some(Arc::clone(&doq));
        self.health = Health::with_config(config);
        self.quic = Some(doq);
    }

    /// Whether Queries to this Upstream travel over DNS-over-QUIC.
    #[must_use]
    pub fn is_quic(&self) -> bool {
        self.quic.is_some()
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
        self.https_pool.clear();
        self.source_address = source;
        if let Some(doq) = &self.quic {
            doq.set_source_address(source);
        }
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
        if let Some(doq) = &self.quic {
            // CoreDNS v1.15.0 plugin/pkg/proxy/doq.go acquire: DoQ connection reuse counts as `quic`.
            doq.set_cache(proxy.connection_cache("quic"));
        }
        self.metrics = Some(Metrics {
            cache: [
                (
                    "udp",
                    self.tls.is_none() && self.https.is_none() && self.quic.is_none(),
                ),
                (
                    "tcp",
                    self.tls.is_none() && self.https.is_none() && self.quic.is_none(),
                ),
                // CoreDNS v1.15.0 plugin/pkg/proxy/connect.go: DoT connections count as `tcp-tls`.
                ("tcp-tls", self.tls.is_some() && self.quic.is_none()),
                ("https", self.https.is_some() && self.quic.is_none()),
            ]
            .map(|(proto, used)| used.then(|| proxy.connection_cache(proto))),
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
        if config.tls.is_none() {
            config.tls.clone_from(&self.tls);
        }
        if config.doq.is_none() {
            config.doq.clone_from(&self.quic);
        }
        if config.https.is_none() {
            config.https.clone_from(&self.https);
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
        if let Some(doq) = &self.quic {
            // CoreDNS v1.15.0 plugin/pkg/proxy/connect.go Connect: a DoQ Upstream always uses DoQ.
            let result = self.exchange_quic(doq, query, response).await;
            if matches!(result, Err(Error::Io(_))) {
                self.health.start();
            }
            return result;
        }
        // RFC 7766 §5: DNS forwarders must support both UDP and TCP transport.
        // CoreDNS v1.15.0 plugin/pkg/proxy/connect.go: a TLS-configured Upstream always uses TLS.
        let selected = if self.https.is_some() {
            Transport::Https
        } else if self.tls.is_some() {
            Transport::Tls
        } else if options.force_tcp {
            Transport::Tcp
        } else if options.prefer_udp {
            Transport::Udp
        } else {
            transport
        };
        let result = self
            .exchange_once(query, response, selected, options.tls_connect_deadline)
            .await;
        // RFC 2181 §9: a client can retry a truncated response over TCP.
        // RFC 9520 §3.1: Retry a truncated UDP response over TCP to the same server.
        let result = match result {
            Ok(_result)
                if selected == Transport::Udp
                    && options.prefer_udp
                    && !options.force_tcp
                    && response[2] & 0x02 != 0 =>
            {
                self.exchange_once(query, response, Transport::Tcp, None)
                    .await
            }
            other => other,
        };
        if matches!(result, Err(Error::Io(_))) {
            self.health.start();
        }
        result
    }

    /// Validate an Upstream Response and normalize it for the client; returns its length and whether the Upstream asked to close.
    fn finish_response(
        &self,
        request: &Message<'_>,
        query: &[u8],
        response: &mut [u8],
        mut length: usize,
        transport: Transport,
        start: Instant,
    ) -> Result<(usize, bool), Error> {
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
            // RFC 5625 §4.4: a proxy that truncates a response must set TC.
            // RFC 1035 §4.2.1: Set TC when truncating a UDP response.
            response[2] = flags[0] | 0x02;
            response[3] = flags[1];
            response[6..12].fill(0);
        }
        let (close_after, ttl_normalization) = {
            let answer = Message::parse(&response[..length])
                .map_err(|_| Error::Io(io::ErrorKind::InvalidData.into()))?;
            if let Some(metrics) = &self.metrics {
                let code = answer.rcode().0;
                // shortcut: first observation of an RCODE allocates; pre-register codes if cold traffic matters.
                metrics.durations[usize::from(code)]
                    .get_or_init(|| metrics.proxy.request_duration(&Rcode(code).to_string()))
                    .observe(start.elapsed().as_secs_f64());
            }
            // RFC 5452 §4.2: Response Question must match the outstanding Query.
            let same_questions = request.question_count() == answer.question_count()
                && request
                    .questions()
                    .zip(answer.questions())
                    .all(|(a, b)| a.name == b.name && a.qtype == b.qtype && a.qclass == b.qclass);
            if !answer.qr() || !same_questions || !same_ecs(request, &answer) {
                return Err(Error::Mismatch(length));
            }
            let ttl_normalization = rrsets_ttl_normalization(&answer, &response[..length])
                .map_err(|_| Error::Io(io::ErrorKind::InvalidData.into()))?;
            (keepalive_zero(&answer), ttl_normalization)
        };
        if ttl_normalization.changed
            && !apply_rrset_ttl_normalization(&mut response[..length], ttl_normalization.records)
        {
            return Err(Error::Io(io::ErrorKind::InvalidData.into()));
        }
        // RFC 1035 §4.1.1: the response ID matches the original query ID.
        response[..2].copy_from_slice(&query[..2]);
        Ok((length, close_after))
    }

    async fn exchange_once(
        &self,
        query: &[u8],
        response: &mut [u8],
        transport: Transport,
        tls_connect_deadline: Option<tokio::time::Instant>,
    ) -> Result<Exchange, Error> {
        if transport == Transport::Https {
            return self
                .exchange_https(query, response, tls_connect_deadline)
                .await;
        }
        let start = Instant::now();
        // RFC 5625 §4.1: Accept packets with unknown DNS flags for proxying.
        let request = Message::parse(query).map_err(|_| Error::InvalidRequest)?;
        if query.len() > response.len() || query.len() > u16::MAX as usize {
            return Err(Error::InvalidRequest);
        }
        let protocol = transport.index();
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
        if let Some(metrics) = &self.metrics
            && let Some(cache) = &metrics.cache[protocol]
        {
            if reused {
                cache.hit();
            } else {
                cache.miss();
            }
        }
        // RFC 7766 §6.2.1: DNS clients should reuse persistent TCP connections.
        let (mut socket, created, uses) = if let Some(cached) = cached {
            (cached.socket, cached.created, cached.uses)
        } else {
            (
                self.dial(transport, tls_connect_deadline).await?,
                Instant::now(),
                0,
            )
        };
        let mut id = [0; 2];
        // RFC 8945 §5.5: forward messages with unshared TSIG keys unchanged.
        let signed = request
            .additionals()
            .any(|record| record.rtype == Type::TSIG);
        if signed {
            // RFC 8945 §5.5: Keep signed Queries unchanged; shortcut: skip EDNS edits until TSIG re-signing exists.
            id.copy_from_slice(&query[..2]);
        } else {
            // RFC 5452 §9.2: outgoing queries use unpredictable IDs.
            // RFC 5625 §6.1: Use unpredictable full-range IDs for queries without unshared TSIG.
            getrandom::getrandom(&mut id)
                .map_err(|_| Error::Io(io::Error::other("random ID generation failed")))?;
        }
        // RFC 5625 §4.3: Proxy Queries regardless of QTYPE and QCLASS.
        response[..query.len()].copy_from_slice(query);
        response[..2].copy_from_slice(&id);
        let opt_range = opt_rdata_range(&request, query);
        let outgoing_len = if signed {
            query.len()
        } else {
            sanitize_edns(response, query.len(), transport, false, opt_range)
        };
        let local_addr = socket.local_addr()?;
        let sent = timeout(READ_TIMEOUT, socket.send(&response[..outgoing_len]))
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
                if len < 12 && transport != Transport::Udp {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                // RFC 5452 §9.1: match response IDs to outstanding queries.
                // RFC 7766 §7: Match TCP Responses to outstanding Queries by Message ID.
                if len >= 12 && response[..2] == id {
                    return Ok::<_, io::Error>(len);
                }
            }
        })
        .await
        .map_err(|_| Error::Io(io::ErrorKind::TimedOut.into()))?;
        let length = received.map_err(|err| {
            if reused && err.kind() == io::ErrorKind::UnexpectedEof {
                Error::CachedClosed
            } else {
                Error::Io(err)
            }
        })?;
        let (length, close_after) =
            self.finish_response(&request, query, response, length, transport, start)?;
        // RFC 5452 §9.2: retire a UDP socket after its use budget so its source port changes.
        let next_uses = next_use_count(transport, uses);
        let spent = transport == Transport::Udp && next_uses >= self.udp_max_uses;
        let max_idle = match (transport, self.max_idle_conns) {
            (Transport::Udp, 0) => UDP_MAX_IDLE,
            (Transport::Udp, max) => max.min(UDP_MAX_IDLE),
            (Transport::Tcp | Transport::Tls | Transport::Https | Transport::Quic, max) => max,
        };
        if !spent {
            let mut queue = self.shards[protocol][shard].lock().unwrap();
            // RFC 7828 §3.2.2: TIMEOUT zero forbids reusing this TCP connection.
            if (transport == Transport::Udp || !close_after)
                && !self.stopped.load(Ordering::Acquire)
                && self.idle[protocol]
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                        (max_idle == 0 || count < max_idle).then(|| count + 1)
                    })
                    .is_ok()
            {
                queue.push_back(Cached {
                    socket,
                    created,
                    used: Instant::now(),
                    uses: next_uses,
                });
            }
        }
        Ok(Exchange {
            len: length,
            local_addr,
            transport,
        })
    }

    // RFC 9250 §4.2: DoQ sends one Query on its own stream and reads one Response from it.
    async fn exchange_quic(
        &self,
        doq: &Doq,
        query: &[u8],
        response: &mut [u8],
    ) -> Result<Exchange, Error> {
        let start = Instant::now();
        let request = Message::parse(query).map_err(|_| Error::InvalidRequest)?;
        if query.len() > response.len() || query.len() > u16::MAX as usize {
            return Err(Error::InvalidRequest);
        }
        // CoreDNS v1.15.0 plugin/pkg/proxy/doq.go exchange: zone transfers need a multi-message Response DoQ here lacks.
        if request.question_count() == 1
            && request
                .questions()
                .any(|question| matches!(question.qtype, Type::AXFR | Type::IXFR))
        {
            return Err(Error::UnsupportedRequest);
        }
        response[..query.len()].copy_from_slice(query);
        // RFC 9250 §4.2.1: the DoQ Message ID is zero.
        response[..2].fill(0);
        let opt_range = opt_rdata_range(&request, query);
        let outgoing_len = sanitize_edns(response, query.len(), Transport::Quic, false, opt_range);
        let reply = doq.exchange(response, outgoing_len, None).await?;
        let (length, _) =
            self.finish_response(&request, query, response, reply.len, Transport::Quic, start)?;
        Ok(Exchange {
            len: length,
            local_addr: reply.local_addr,
            transport: Transport::Quic,
        })
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests;
