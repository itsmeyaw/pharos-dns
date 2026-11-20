//! DNS-over-HTTPS Upstream exchange (RFC 8484) over hyper: one multiplexed HTTP/2 connection,
//! or idle HTTP/1.1 connections when the server does not negotiate `h2`.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard, PoisonError, atomic::Ordering},
    time::{Duration, Instant},
};

use bytes::Buf;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, StatusCode,
    client::conn::{http1, http2},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pharos_proto::{Message, Type};
use pharos_server::{
    doh,
    pool::{MESSAGE_CAPACITY, Stash},
    tls::{ServerName, TlsConnector},
};
use tokio::time::{timeout, timeout_at};

use super::{Error, Exchange, Proxy, Tls, Transport, connect_tcp, opt_rdata_range, sanitize_edns};

/// How an Upstream's DNS-over-HTTPS requests are made and its server verified.
#[derive(Clone, Debug)]
pub struct Https {
    tls: Tls,
    method: Method,
    endpoint: Option<doh::Endpoint>,
}

impl Https {
    /// `tls` verifies the server at `address`; `method` is GET or POST (RFC 8484 §4.1).
    #[must_use]
    pub fn new(address: SocketAddr, tls: Tls, method: Method) -> Self {
        // RFC 7301 §3.1: offer h2 first; a server that selects nothing is spoken to in HTTP/1.1.
        let mut config = (*tls.config).clone();
        config.alpn_protocols = doh::ALPN.iter().map(|protocol| protocol.to_vec()).collect();
        // RFC 9110 §7.2: the Host is the name the Corefile gives, else the Upstream's IP address.
        let authority = match &tls.server_name {
            ServerName::DnsName(name) => name.as_ref().to_owned(),
            ServerName::IpAddress(ip) if IpAddr::from(*ip) == address.ip() => host(address),
            other => other.to_str().into_owned(),
        };
        Self {
            tls: Tls {
                config: config.into(),
                server_name: tls.server_name,
            },
            method,
            endpoint: doh::Endpoint::new(&authority),
        }
    }
}

// CoreDNS v1.15.0 plugin/pkg/doh NewRequestWithContext: the Host of `https://IP:PORT`; 443 is left out.
fn host(address: SocketAddr) -> String {
    match (address.ip(), address.port()) {
        (IpAddr::V6(ip), 443) => format!("[{ip}]"),
        (ip, 443) => ip.to_string(),
        _ => address.to_string(),
    }
}

/// The most request buffers a [`Pool`] keeps, and the most memory they hold in all.
const POOL_BUFFERS: usize = 64;
const POOL_BYTES: usize = POOL_BUFFERS * 4096;

/// A request body in a pooled buffer, which goes back to its pool when hyper drops the body.
pub(super) struct Body {
    buffer: Vec<u8>,
    position: usize,
    pool: Arc<Stash<Vec<u8>>>,
}

impl Buf for Body {
    fn remaining(&self) -> usize {
        self.buffer.len() - self.position
    }

    fn chunk(&self) -> &[u8] {
        &self.buffer[self.position..]
    }

    fn advance(&mut self, count: usize) {
        assert!(count <= self.remaining(), "advance past the end");
        self.position += count;
    }
}

impl Drop for Body {
    fn drop(&mut self) {
        let mut buffer = std::mem::take(&mut self.buffer);
        buffer.clear();
        let size = buffer.capacity();
        self.pool.put(buffer, size);
    }
}

enum Sender {
    H2(http2::SendRequest<Full<Body>>),
    H1(http1::SendRequest<Full<Body>>),
}

impl Sender {
    fn is_closed(&self) -> bool {
        match self {
            Self::H2(sender) => sender.is_closed(),
            Self::H1(sender) => sender.is_closed(),
        }
    }

    fn is_h2(&self) -> bool {
        matches!(self, Self::H2(_))
    }
}

pub(super) struct Connection {
    sender: Sender,
    local_addr: SocketAddr,
    created: Instant,
    used: Instant,
}

impl Connection {
    // CoreDNS v1.15.0 plugin/pkg/proxy/persistent.go: idle past `expire` or older than `max_age` is dropped.
    fn fresh(&self, expire: Duration, max_age: Duration) -> bool {
        !self.sender.is_closed()
            && self.used.elapsed() <= expire
            && (max_age.is_zero() || self.created.elapsed() <= max_age)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Upstream connections kept for reuse, and the buffers of requests: one shared HTTP/2 connection, or
/// idle HTTP/1.1 ones.
pub(super) struct Pool {
    h2: Mutex<Option<Connection>>,
    h1: Mutex<Vec<Connection>>,
    // shortcut: HTTP/1.1 Upstreams dial one at a time too; split per protocol if cold-start latency there matters.
    dial: tokio::sync::Mutex<()>,
    buffers: Arc<Stash<Vec<u8>>>,
}

impl Default for Pool {
    fn default() -> Self {
        Self {
            h2: Mutex::default(),
            h1: Mutex::default(),
            dial: tokio::sync::Mutex::default(),
            buffers: Arc::new(Stash::new(POOL_BUFFERS, MESSAGE_CAPACITY, POOL_BYTES)),
        }
    }
}

impl Pool {
    fn body(&self) -> Body {
        Body {
            buffer: self.buffers.take().unwrap_or_default(),
            position: 0,
            pool: Arc::clone(&self.buffers),
        }
    }

    pub(super) fn clear(&self) {
        lock(&self.h2).take();
        lock(&self.h1).clear();
    }

    pub(super) fn retain(&self, expire: Duration, max_age: Duration) {
        let mut h2 = lock(&self.h2);
        if h2.as_ref().is_some_and(|c| !c.fresh(expire, max_age)) {
            *h2 = None;
        }
        lock(&self.h1).retain(|c| c.fresh(expire, max_age));
    }

    fn checkout(&self, expire: Duration, max_age: Duration) -> Option<Connection> {
        let mut h2 = lock(&self.h2);
        if let Some(connection) = h2.as_mut() {
            if let (Sender::H2(sender), true) =
                (&connection.sender, connection.fresh(expire, max_age))
            {
                // RFC 9113 §5.1.2: concurrent Queries share one connection as separate streams.
                connection.used = Instant::now();
                return Some(Connection {
                    sender: Sender::H2(sender.clone()),
                    ..*connection
                });
            }
            *h2 = None;
        }
        drop(h2);
        // RFC 9112 §9.3: an HTTP/1.1 connection carries one request at a time, so it leaves the pool while in use.
        let mut h1 = lock(&self.h1);
        while let Some(connection) = h1.pop() {
            if connection.fresh(expire, max_age) {
                return Some(connection);
            }
        }
        None
    }
}

/// Why a DoH request produced no Response.
#[derive(Debug)]
pub(super) enum Failure {
    Http(hyper::Error),
    Status(StatusCode),
    TooLarge,
}

impl Failure {
    fn into_io(self) -> io::Error {
        match self {
            Self::Http(error) => io::Error::other(error),
            Self::Status(status) => io::Error::new(
                io::ErrorKind::InvalidData,
                format!("DoH Upstream answered HTTP {status}"),
            ),
            Self::TooLarge => io::ErrorKind::InvalidData.into(),
        }
    }

    fn into_error(self, reused: bool) -> Error {
        match &self {
            // RFC 9112 §9.3.1: a request that never reached a closed idle connection is safe to resend.
            Self::Http(error) if reused && (error.is_canceled() || error.is_closed()) => {
                Error::CachedClosed
            }
            _ => Error::Io(self.into_io()),
        }
    }
}

/// Dial, verify the server and start HTTP in whichever version ALPN selected.
pub(super) async fn connect(
    address: SocketAddr,
    source: Option<IpAddr>,
    https: &Https,
) -> io::Result<Connection> {
    let tcp = connect_tcp(address, source).await?;
    let local_addr = tcp.local_addr()?;
    // RFC 8484 §5: DoH clients authenticate the server before sending Queries.
    let tls = TlsConnector::from(https.tls.config.clone())
        .connect(https.tls.server_name.clone(), tcp)
        .await?;
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    let io = TokioIo::new(tls);
    let sender = if h2 {
        let (sender, connection) = http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(io::Error::other)?;
        tokio::spawn(connection);
        Sender::H2(sender)
    } else {
        let (sender, connection) = http1::handshake(io).await.map_err(io::Error::other)?;
        tokio::spawn(connection);
        Sender::H1(sender)
    };
    let now = Instant::now();
    Ok(Connection {
        sender,
        local_addr,
        created: now,
        used: now,
    })
}

/// Send `request` and copy the Response Message into `out`, returning its length.
async fn round_trip(
    sender: &mut Sender,
    request: Request<Full<Body>>,
    out: &mut [u8],
) -> Result<usize, Failure> {
    let response = match sender {
        Sender::H2(sender) => {
            sender.ready().await.map_err(Failure::Http)?;
            sender.send_request(request).await
        }
        Sender::H1(sender) => {
            sender.ready().await.map_err(Failure::Http)?;
            sender.send_request(request).await
        }
    }
    .map_err(Failure::Http)?;
    // RFC 8484 §4.2.1: only a 2xx response carries the Response Message.
    if !response.status().is_success() {
        return Err(Failure::Status(response.status()));
    }
    let mut body = response.into_body();
    let mut len = 0;
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.map_err(Failure::Http)?.into_data() {
            let end = len + data.len();
            out.get_mut(len..end)
                .ok_or(Failure::TooLarge)?
                .copy_from_slice(&data);
            len = end;
        }
    }
    Ok(len)
}

/// One health-check Query over a fresh connection, so a stale pooled connection cannot mask an outage.
pub(super) async fn probe(
    address: SocketAddr,
    source: Option<IpAddr>,
    https: &Https,
    query: &[u8],
    dial: Duration,
    exchange: Duration,
) -> io::Result<Vec<u8>> {
    let mut connection = timeout(dial, connect(address, source, https)).await??;
    // CoreDNS v1.15.0 plugin/pkg/proxy/health.go dohHc.send: health checks always POST.
    let mut body = Pool::default().body();
    let request = https
        .endpoint
        .as_ref()
        .and_then(|endpoint| {
            endpoint.request(
                &Method::POST,
                connection.sender.is_h2(),
                query,
                &mut body.buffer,
            )
        })
        .ok_or(io::ErrorKind::InvalidInput)?
        .map(|()| Full::new(body));
    let mut response = vec![0; usize::from(u16::MAX)];
    let len = timeout(
        exchange,
        round_trip(&mut connection.sender, request, &mut response),
    )
    .await?
    .map_err(Failure::into_io)?;
    response.truncate(len);
    Ok(response)
}

impl Proxy {
    async fn dial_https(
        &self,
        https: &Https,
        tls_connect_deadline: Option<tokio::time::Instant>,
    ) -> io::Result<Connection> {
        let start = Instant::now();
        let mut limit = tokio::time::Instant::now() + self.dial_timeout();
        if let Some(deadline) = tls_connect_deadline {
            // CoreDNS v1.15.0 plugin/pkg/proxy/connect.go: the connect deadline caps the TCP dial plus handshake.
            limit = limit.min(deadline);
        }
        let result = timeout_at(limit, connect(self.address, self.source_address, https)).await;
        self.update_dial_timeout(start.elapsed());
        result.map_err(|_| io::ErrorKind::TimedOut)?
    }

    pub(super) async fn exchange_https(
        &self,
        query: &[u8],
        response: &mut [u8],
        tls_connect_deadline: Option<tokio::time::Instant>,
    ) -> Result<Exchange, Error> {
        let start = Instant::now();
        let Some(https) = &self.https else {
            return Err(Error::Io(io::Error::other(
                "no HTTPS configuration for Upstream",
            )));
        };
        // RFC 5625 §4.1: Accept packets with unknown DNS flags for proxying.
        let message = Message::parse(query).map_err(|_| Error::InvalidRequest)?;
        if query.len() > response.len() || query.len() > usize::from(u16::MAX) {
            return Err(Error::InvalidRequest);
        }
        response[..query.len()].copy_from_slice(query);
        let outgoing_len = if message
            .additionals()
            .any(|record| record.rtype == Type::TSIG)
        {
            // RFC 8945 §5.5: Keep signed Queries unchanged.
            query.len()
        } else {
            // RFC 8484 §4.1: DoH clients use Message ID 0 so identical Queries are cacheable.
            response[..2].fill(0);
            let opt_range = opt_rdata_range(&message, query);
            sanitize_edns(response, query.len(), Transport::Https, false, opt_range)
        };
        let cached = self.https_pool.checkout(self.expire, self.max_age);
        let mut reused = cached.is_some();
        if let Some(metrics) = &self.metrics
            && let Some(cache) = &metrics.cache[Transport::Https.index()]
        {
            if reused {
                cache.hit();
            } else {
                cache.miss();
            }
        }
        let mut connection = match cached {
            Some(connection) => connection,
            None => {
                // RFC 9113 §9.1: a burst of cold Queries shares the connection the first one opens.
                let _dialing = self.https_pool.dial.lock().await;
                if let Some(connection) = self.https_pool.checkout(self.expire, self.max_age) {
                    reused = true;
                    connection
                } else {
                    let connection = self.dial_https(https, tls_connect_deadline).await?;
                    if let Sender::H2(sender) = &connection.sender {
                        let mut slot = lock(&self.https_pool.h2);
                        // `stop` clears the pool after setting the flag, so a check under the lock leaves no stray connection.
                        if !self.stopped.load(Ordering::Acquire) {
                            *slot = Some(Connection {
                                sender: Sender::H2(sender.clone()),
                                ..connection
                            });
                        }
                    }
                    connection
                }
            }
        };
        let mut body = self.https_pool.body();
        let request = https
            .endpoint
            .as_ref()
            .and_then(|endpoint| {
                endpoint.request(
                    &https.method,
                    connection.sender.is_h2(),
                    &response[..outgoing_len],
                    &mut body.buffer,
                )
            })
            .ok_or(Error::InvalidRequest)?
            .map(|()| Full::new(body));
        let length = timeout(
            self.read_timeout,
            round_trip(&mut connection.sender, request, response),
        )
        .await
        .map_err(|_| Error::Io(io::ErrorKind::TimedOut.into()))?
        .map_err(|failure| failure.into_error(reused))?;
        let (length, _) =
            self.finish_response(&message, query, response, length, Transport::Https, start)?;
        let exchange = Exchange {
            len: length,
            local_addr: connection.local_addr,
            transport: Transport::Https,
        };
        if !connection.sender.is_h2() {
            let mut idle = lock(&self.https_pool.h1);
            if !self.stopped.load(Ordering::Acquire)
                && (self.max_idle_conns == 0 || idle.len() < self.max_idle_conns)
            {
                connection.used = Instant::now();
                idle.push(connection);
            }
        }
        Ok(exchange)
    }
}
