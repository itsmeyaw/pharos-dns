//! Upstream DNS exchange. Independent cache shards hold idle connections only;
//! no lock or manager task is held while a Query waits for its Response.
//! DNS-over-TLS is deferred to M3.

use pharos_proto::Message;
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, time::timeout};

const SHARDS: usize = 32;
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
    socket: UdpSocket,
    used: Instant,
}

pub struct Proxy {
    address: SocketAddr,
    shards: [Mutex<VecDeque<Cached>>; SHARDS],
    next: AtomicUsize,
    expire: Duration,
}

impl Proxy {
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            shards: std::array::from_fn(|_| Mutex::new(VecDeque::new())),
            next: AtomicUsize::new(0),
            expire: EXPIRE,
        }
    }
    pub async fn exchange(
        &self,
        query: &[u8],
        response: &mut [u8],
        transport: Transport,
        options: Options,
    ) -> Result<Exchange, Error> {
        let request = Message::parse(query).map_err(|_| Error::InvalidRequest)?;
        if query.len() > response.len() {
            return Err(Error::InvalidRequest);
        }
        let transport = if options.force_tcp {
            Transport::Tcp
        } else if options.prefer_udp {
            Transport::Udp
        } else {
            transport
        };
        if transport != Transport::Udp {
            return Err(Error::Io(io::ErrorKind::Unsupported.into()));
        }
        let shard = self.next.fetch_add(1, Ordering::Relaxed) % SHARDS;
        let cached = {
            let mut queue = self.shards[shard].lock().unwrap();
            loop {
                match queue.pop_front() {
                    Some(cached) if cached.used.elapsed() <= self.expire => break Some(cached),
                    Some(_) => continue,
                    None => break None,
                }
            }
        };
        let socket = if let Some(cached) = cached {
            cached.socket
        } else {
            let ip = if self.address.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            };
            let socket = UdpSocket::bind(SocketAddr::new(ip, 0)).await?;
            socket.connect(self.address).await?;
            socket
        };
        let mut id = [0; 2];
        getrandom::getrandom(&mut id)
            .map_err(|_| Error::Io(io::Error::other("random ID generation failed")))?;
        response[..query.len()].copy_from_slice(query);
        response[..2].copy_from_slice(&id);
        let local_addr = socket.local_addr()?;
        timeout(READ_TIMEOUT, socket.send(&response[..query.len()]))
            .await
            .map_err(|_| Error::Io(io::ErrorKind::TimedOut.into()))??;
        let length = timeout(READ_TIMEOUT, async {
            loop {
                let len = socket.recv(response).await?;
                if len >= 2 && response[..2] == id {
                    return Ok::<_, io::Error>(len);
                }
            }
        })
        .await
        .map_err(|_| Error::Io(io::ErrorKind::TimedOut.into()))??;
        let answer = Message::parse(&response[..length]).map_err(|_| Error::Mismatch)?;
        let same_questions = request.question_count() == answer.question_count()
            && request
                .questions()
                .zip(answer.questions())
                .all(|(a, b)| a.name == b.name && a.qtype == b.qtype && a.qclass == b.qclass);
        if !answer.qr() || !same_questions {
            return Err(Error::Mismatch);
        }
        response[..2].copy_from_slice(&query[..2]);
        self.shards[shard].lock().unwrap().push_back(Cached {
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
