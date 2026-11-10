//! Upstream DNS exchange. Independent cache shards hold idle connections only;
//! no lock or manager task is held while a Query waits for its Response.
//! DNS-over-TLS is deferred to M3.

use pharos_proto::{Message, Rcode};
use pharos_server::metrics::{ProxyConnectionCache, ProxyMetrics, ProxyRequestDuration, Registry};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};

const SHARDS: usize = 32;
static NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);
thread_local! { static SHARD: usize = NEXT_SHARD.fetch_add(1, Ordering::Relaxed) % SHARDS; }
const EXPIRE: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(2);

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
    Mismatch,
    CachedClosed,
    Io(io::Error),
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
    metrics: Option<Metrics>,
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
            metrics: None,
        }
    }

    /// Set the maximum idle time before an Upstream connection is discarded.
    pub fn set_expire(&mut self, expire: Duration) {
        self.expire = expire;
    }

    /// Register the Upstream's metrics with the server's exporter.
    pub fn set_metrics(&mut self, registry: &Registry, name: &str) {
        let proxy = registry.proxy(name, &self.address.to_string());
        self.metrics = Some(Metrics {
            cache: [proxy.connection_cache("udp"), proxy.connection_cache("tcp")],
            durations: (0..4096).map(|_| OnceLock::new()).collect(),
            proxy,
        });
    }
    pub async fn exchange(
        &self,
        query: &[u8],
        response: &mut [u8],
        transport: Transport,
        options: Options,
    ) -> Result<Exchange, Error> {
        let selected = if options.force_tcp {
            Transport::Tcp
        } else if options.prefer_udp {
            Transport::Udp
        } else {
            transport
        };
        let result = self.exchange_once(query, response, selected).await?;
        if selected == Transport::Udp
            && options.prefer_udp
            && !options.force_tcp
            && response[2] & 0x02 != 0
        {
            return self.exchange_once(query, response, Transport::Tcp).await;
        }
        Ok(result)
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
                    Some(cached) if cached.used.elapsed() <= self.expire => break Some(cached),
                    Some(_) => continue,
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
        let mut socket = if let Some(cached) = cached {
            cached.socket
        } else if transport == Transport::Tcp {
            Socket::Tcp(
                timeout(Duration::from_secs(30), TcpStream::connect(self.address))
                    .await
                    .map_err(|_| Error::Io(io::ErrorKind::TimedOut.into()))??,
            )
        } else {
            let ip = if self.address.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            };
            let socket = UdpSocket::bind(SocketAddr::new(ip, 0)).await?;
            socket.connect(self.address).await?;
            Socket::Udp(socket)
        };
        let mut id = [0; 2];
        getrandom::getrandom(&mut id)
            .map_err(|_| Error::Io(io::Error::other("random ID generation failed")))?;
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
        let received = timeout(READ_TIMEOUT, async {
            loop {
                let len = socket.receive(response).await?;
                if len >= 2 && response[..2] == id {
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
        let answer = Message::parse(&response[..length]).map_err(|_| Error::Mismatch)?;
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
        self.shards[protocol][shard]
            .lock()
            .unwrap()
            .push_back(Cached {
                socket,
                used: Instant::now(),
            });
        Ok(Exchange {
            len: length,
            local_addr,
            transport,
        })
    }
}
