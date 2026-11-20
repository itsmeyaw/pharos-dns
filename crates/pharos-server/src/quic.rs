//! DNS over QUIC (RFC 9250) Listener: one quinn endpoint per `quic://` Listener key.
//!
//! The endpoint and accept loop are generic over [`Handler`] and serve either DoQ or, through
//! [`Kind::Doh3`], the HTTP/3 connections of [`crate::https3`]; DoQ upstream forwarding shares
//! [`bind`] and [`QuicOptions`].

use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use pharos_proto::{EdnsOption, Message};
use quinn::{
    Connecting, Connection, Endpoint, EndpointConfig, IdleTimeout, ReadError, ReadExactError,
    RecvStream, SendStream, ServerConfig, TokioRuntime, TransportConfig, VarInt,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

use crate::{
    Action, Handler, Protocol, TcpOptions, conn::Pool, metrics::TransportStatus, tls::ServerTls,
};

// RFC 9250 §4.1.1: the ALPN token of DoQ is "doq".
pub(crate) const ALPN: &[u8] = b"doq";

// RFC 9250 §8.4: DOQ_NO_ERROR, DOQ_INTERNAL_ERROR and DOQ_PROTOCOL_ERROR.
pub(crate) const NO_ERROR: VarInt = VarInt::from_u32(0);
const INTERNAL_ERROR: VarInt = VarInt::from_u32(1);
pub(crate) const PROTOCOL_ERROR: VarInt = VarInt::from_u32(2);
// RFC 9114 §8.1: H3_EXCESSIVE_LOAD.
const H3_EXCESSIVE_LOAD: VarInt = VarInt::from_u32(0x107);

/// The application protocol a QUIC Listener serves.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Kind {
    /// DNS over QUIC (RFC 9250): one Query per bidirectional stream.
    Doq,
    /// DNS over HTTPS over HTTP/3 (RFC 8484, RFC 9114).
    Doh3,
}

/// Keep at most this many scratch buffer pairs, each no larger than `MAX_POOLED_CAPACITY`.
const MAX_POOLED: usize = 64;
const MAX_POOLED_CAPACITY: usize = 8192;

/// RFC 9114 §6.2.1, RFC 9204 §4.2: the control stream and the QPACK encoder and decoder streams.
const MIN_UNI_STREAMS: u64 = 3;

/// One DoQ Message is at most 65535 octets plus its two-octet length (RFC 9250 §4.2).
pub(crate) const STREAM_WINDOW: u32 = 66 * 1024;

/// Resource limits of a `quic://` Listener; defaults match CoreDNS v1.15.0.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuicOptions {
    /// Concurrent bidirectional streams per connection.
    pub max_streams: usize,
    /// Concurrent connections; zero removes the limit.
    pub max_connections: usize,
    /// Streams handled at once across every connection.
    pub worker_pool_size: usize,
}

impl Default for QuicOptions {
    fn default() -> Self {
        Self {
            max_streams: 256,
            max_connections: 200,
            worker_pool_size: 1024,
        }
    }
}

/// Response counters of one `quic://` Listener, labelled by DoQ error code.
#[derive(Clone)]
pub struct QuicMetrics {
    no_error: TransportStatus,
    internal_error: TransportStatus,
    protocol_error: TransportStatus,
}

impl QuicMetrics {
    /// Resolve the three counters of `server` (for example `quic://:853`).
    #[must_use]
    pub fn new(registry: &crate::metrics::Registry, server: &str) -> Self {
        Self {
            no_error: registry.transport_status("quic", server, "0x0"),
            internal_error: registry.transport_status("quic", server, "0x1"),
            protocol_error: registry.transport_status("quic", server, "0x2"),
        }
    }
}

/// Bind the Listener's UDP socket, dual-stack for an IPv6 wildcard.
pub fn bind(address: SocketAddr) -> io::Result<std::net::UdpSocket> {
    fn socket(address: SocketAddr, dual: bool) -> io::Result<std::net::UdpSocket> {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(address),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        if address.is_ipv6() {
            socket.set_only_v6(!dual)?;
        }
        // No SO_REUSEPORT: the kernel would split one connection's datagrams across sockets.
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        Ok(socket.into())
    }
    if address.is_ipv6() && address.ip().is_unspecified() {
        // A wildcard falls back to IPv4 where the host has no IPv6.
        if let Some(socket) = crate::optional_ipv6(socket(address, true))? {
            return Ok(socket);
        }
        return socket((Ipv4Addr::UNSPECIFIED, address.port()).into(), false);
    }
    socket(address, false)
}

/// The limits `handler` sets for a Listener of `kind`.
fn limits<H: Handler>(kind: Kind, handler: &H) -> QuicOptions {
    match kind {
        Kind::Doq => handler.quic_options(),
        Kind::Doh3 => {
            // CoreDNS v1.15.0 core/dnsserver/server_https3.go: the https3 limits are streams and connections.
            let https = handler.https();
            QuicOptions {
                max_streams: https.max_streams as usize,
                max_connections: https.max_connections,
                ..QuicOptions::default()
            }
        }
    }
}

/// Build the QUIC server configuration for `tls` and the limits in force.
fn server_config(
    kind: Kind,
    tls: &ServerTls,
    options: &QuicOptions,
    idle: Duration,
) -> ServerConfig {
    let mut config = ServerConfig::with_crypto(tls.quic());
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(IdleTimeout::try_from(idle).ok());
    // Zero keeps quinn's own stream credit (100), which CoreDNS calls the QUIC transport default.
    let streams = if options.max_streams == 0 {
        100
    } else {
        options.max_streams as u64
    };
    // RFC 9250 §5.8: bound what a connection can make the server buffer to its stream credit times one Message.
    let window = u64::from(STREAM_WINDOW) * streams;
    transport.stream_receive_window(VarInt::from_u32(STREAM_WINDOW));
    transport.receive_window(VarInt::from_u64(window).unwrap_or(VarInt::MAX));
    transport.send_window(window);
    // RFC 9250 §4.2, RFC 9114 §6.1: each Query or request uses its own client-initiated bidirectional stream.
    transport.max_concurrent_bidi_streams(VarInt::from_u64(streams).unwrap_or(VarInt::MAX));
    match kind {
        Kind::Doq => {
            // RFC 9250 §4.2: DoQ does not use unidirectional streams.
            transport.max_concurrent_uni_streams(VarInt::from_u32(0));
            // RFC 9250 §5.4: pad QUIC packets to the MTU against traffic analysis; quinn exposes this policy.
            transport.pad_to_mtu(true);
        }
        Kind::Doh3 => {
            // RFC 9114 §6.2: a client opens a control stream and two QPACK streams (RFC 9204 §4.2),
            // so fewer than three unidirectional streams would break every connection.
            transport.max_concurrent_uni_streams(
                VarInt::from_u64(streams.max(MIN_UNI_STREAMS)).unwrap_or(VarInt::MAX),
            );
        }
    }
    config.transport_config(Arc::new(transport));
    config
}

/// Open the endpoint of a `quic://` Listener; returns it with its bound address.
pub(crate) fn endpoint<H: Handler>(
    kind: Kind,
    address: SocketAddr,
    handler: &H,
) -> io::Result<(Endpoint, SocketAddr)> {
    let tls = handler.tls().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC Listener has no TLS identity",
        )
    })?;
    let config = server_config(
        kind,
        &tls,
        &limits(kind, handler),
        handler.tcp_options().idle,
    );
    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(config),
        bind(address)?,
        Arc::new(TokioRuntime),
    )?;
    let address = endpoint.local_addr()?;
    Ok((endpoint, address))
}

/// What a connection task needs, rebuilt when a Reload changes any input.
struct Shared {
    tls: Arc<crate::tls::QuicServerConfig>,
    options: QuicOptions,
    tcp: TcpOptions,
    config: ServerConfig,
    pool: Arc<Semaphore>,
}

/// Scratch buffers for a Query and its Response, reused across streams.
struct Buffers(Mutex<Vec<(Vec<u8>, Vec<u8>)>>);

impl Buffers {
    fn take(&self) -> (Vec<u8>, Vec<u8>) {
        self.0.lock().unwrap().pop().unwrap_or_default()
    }

    fn put(&self, mut pair: (Vec<u8>, Vec<u8>)) {
        if pair.0.capacity().max(pair.1.capacity()) > MAX_POOLED_CAPACITY {
            return;
        }
        pair.0.clear();
        pair.1.clear();
        let mut pool = self.0.lock().unwrap();
        if pool.len() < MAX_POOLED {
            pool.push(pair);
        }
    }
}

struct Connections {
    active: AtomicUsize,
    /// Handshakes in progress; they count against `max_connections` before a connection exists.
    pending: Arc<AtomicUsize>,
    buffers: Buffers,
    /// Query and Response buffers of HTTP/3 requests.
    pool: Arc<Pool>,
}

struct Pending(Arc<AtomicUsize>);

impl Pending {
    fn new(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(counter))
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

struct ActiveGuard<'a>(&'a AtomicUsize);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) fn spawn<H: Handler>(
    kind: Kind,
    endpoint: Endpoint,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<io::Result<()>> {
    tokio::spawn(async move {
        let state = Arc::new(Connections {
            active: AtomicUsize::new(0),
            pending: Arc::new(AtomicUsize::new(0)),
            buffers: Buffers(Mutex::new(Vec::new())),
            pool: Arc::default(),
        });
        let mut connections = JoinSet::new();
        let mut shared: Option<Arc<Shared>> = None;
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                _ = connections.join_next(), if !connections.is_empty() => {},
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    let Some(tls) = handler.tls() else {
                        incoming.refuse();
                        continue;
                    };
                    let (quic, options, tcp) =
                        (tls.quic(), limits(kind, &*handler), handler.tcp_options());
                    let current = match &shared {
                        Some(current)
                            if Arc::ptr_eq(&current.tls, &quic)
                                && current.options == options
                                && current.tcp == tcp => Arc::clone(current),
                        _ => {
                            let current = Arc::new(Shared {
                                config: server_config(kind, &tls, &options, tcp.idle),
                                // One pool per size, so a Reload that keeps it does not double the workers.
                                pool: match &shared {
                                    Some(old) if old.options.worker_pool_size == options.worker_pool_size => {
                                        Arc::clone(&old.pool)
                                    }
                                    _ => Arc::new(Semaphore::new(
                                        options.worker_pool_size.min(Semaphore::MAX_PERMITS),
                                    )),
                                },
                                tls: quic,
                                options,
                                tcp,
                            });
                            shared = Some(Arc::clone(&current));
                            current
                        }
                    };
                    // RFC 9250 §5.3, RFC 9000 §8.1.2: at the limit, make the client prove its address with Retry
                    // before it holds a handshake slot, then refuse.
                    if current.options.max_connections != 0
                        && state.pending.load(Ordering::Relaxed) >= current.options.max_connections
                    {
                        if incoming.may_retry() {
                            let _ = incoming.retry();
                        } else {
                            incoming.refuse();
                        }
                        continue;
                    }
                    let handshake = Pending::new(&state.pending);
                    // The identity is chosen per connection so a Reload applies to new connections.
                    let Ok(connecting) = incoming.accept_with(Arc::new(current.config.clone())) else {
                        continue;
                    };
                    connections.spawn(serve_connection(
                        kind,
                        connecting,
                        Arc::clone(&handler),
                        current,
                        Arc::clone(&state),
                        handshake,
                        shutdown.clone(),
                    ));
                }
            }
        }
        // Connections finish their in-flight streams and close; the Listener caps the wait.
        while connections.join_next().await.is_some() {}
        endpoint.close(NO_ERROR, b"");
        endpoint.wait_idle().await;
        Ok(())
    })
}

async fn serve_connection<H: Handler>(
    kind: Kind,
    connecting: Connecting,
    handler: Arc<H>,
    shared: Arc<Shared>,
    state: Arc<Connections>,
    handshake: Pending,
    mut shutdown: watch::Receiver<bool>,
) {
    let connection = tokio::select! {
        biased;
        _ = shutdown.changed() => return,
        connection = connecting => match connection {
            Ok(connection) => connection,
            Err(_) => return,
        },
    };
    drop(handshake);
    // CoreDNS v1.15.0 core/dnsserver/server_quic.go ServeQUIC: a connection over the limit is closed with code 0.
    // CoreDNS server_https3.go limitQUICListener.Accept: HTTP/3 closes it with H3_EXCESSIVE_LOAD instead.
    let count = state.active.fetch_add(1, Ordering::Relaxed) + 1;
    let _active = ActiveGuard(&state.active);
    if shared.options.max_connections != 0 && count > shared.options.max_connections {
        let code = match kind {
            Kind::Doq => NO_ERROR,
            Kind::Doh3 => H3_EXCESSIVE_LOAD,
        };
        connection.close(code, b"too many connections");
        return;
    }
    if kind == Kind::Doh3 {
        crate::https3::serve(
            connection,
            handler,
            Arc::clone(&state.pool),
            shared.tcp,
            shutdown,
        )
        .await;
        return;
    }
    let peer = crate::canonical_peer(connection.remote_address());
    let metrics = handler.quic_metrics();
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            _ = streams.join_next(), if !streams.is_empty() => {},
            accepted = connection.accept_bi() => {
                // A closed connection has nothing left to answer.
                let Ok((send, recv)) = accepted else { break };
                // CoreDNS: one pool bounds streams across connections; a full pool stalls this accept loop.
                let permit = tokio::select! {
                    biased;
                    _ = shutdown.changed() => break,
                    _ = connection.closed() => break,
                    permit = Arc::clone(&shared.pool).acquire_owned() => permit.expect("pool is never closed"),
                };
                streams.spawn(serve_stream(Stream {
                    handler: Arc::clone(&handler),
                    connection: connection.clone(),
                    send,
                    recv,
                    peer,
                    tcp: shared.tcp,
                    metrics: metrics.clone(),
                    state: Arc::clone(&state),
                    stop: shutdown.clone(),
                    _permit: permit,
                }));
            }
        }
    }
    while streams.join_next().await.is_some() {}
    connection.close(NO_ERROR, b"");
}

struct Stream<H> {
    handler: Arc<H>,
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    peer: SocketAddr,
    tcp: TcpOptions,
    metrics: Option<QuicMetrics>,
    state: Arc<Connections>,
    stop: watch::Receiver<bool>,
    _permit: OwnedSemaphorePermit,
}

enum Failure {
    /// Only this stream is abandoned.
    Stream,
    /// The peer violated DoQ and the connection is aborted.
    Protocol,
    /// The connection is already gone.
    Lost,
}

fn classify(error: &ReadError) -> Failure {
    match error {
        // RFC 9250 §4.3.1: a peer RESET_STREAM abandons only that transaction.
        ReadError::Reset(_) => Failure::Stream,
        _ => Failure::Lost,
    }
}

// RFC 9250 §4.2: a Query is a two-octet length and a Message, followed by STREAM FIN.
async fn read_query(recv: &mut RecvStream, query: &mut Vec<u8>) -> Result<(), Failure> {
    let early = |error: ReadExactError| match error {
        // RFC 9250 §4.3.3: STREAM FIN before the whole Message arrived is a protocol error.
        ReadExactError::FinishedEarly(_) => Failure::Protocol,
        ReadExactError::ReadError(error) => classify(&error),
    };
    let mut length = [0; 2];
    recv.read_exact(&mut length).await.map_err(early)?;
    let size = usize::from(u16::from_be_bytes(length));
    // RFC 9250 §4.2: DoQ v1 requires the length prefix; a zero length is a draft-version peer.
    if size == 0 {
        return Err(Failure::Protocol);
    }
    query.resize(size, 0);
    recv.read_exact(query).await.map_err(early)?;
    // RFC 9250 §4.2: the client indicates STREAM FIN after its Query; more data is a protocol error.
    // Reading to the end also keeps quinn from sending STOP_SENDING, which RFC 9250 §4.3.3 treats as a client error.
    match recv.read(&mut [0]).await {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err(Failure::Protocol),
        Err(error) => Err(classify(&error)),
    }
}

// RFC 9250 §4.3.3: a non-zero Message ID or an edns-tcp-keepalive option is a protocol error.
fn valid_request(query: &Message<'_>) -> bool {
    query.id() == 0
        && !query.opt().is_some_and(|opt| {
            opt.options()
                .iter()
                .any(|option| matches!(option, EdnsOption::TcpKeepalive(_)))
        })
}

fn count(metrics: Option<&QuicMetrics>, code: VarInt) {
    if let Some(metrics) = metrics {
        match code.into_inner() {
            0 => metrics.no_error.increment(),
            1 => metrics.internal_error.increment(),
            _ => metrics.protocol_error.increment(),
        }
    }
}

fn abort(connection: &Connection, metrics: Option<&QuicMetrics>) {
    // RFC 9250 §4.3.3: a protocol error SHOULD close the connection with DOQ_PROTOCOL_ERROR.
    connection.close(PROTOCOL_ERROR, b"");
    count(metrics, PROTOCOL_ERROR);
}

fn fail(send: &mut SendStream, metrics: Option<&QuicMetrics>) {
    // RFC 9250 §4.3.2: DOQ_INTERNAL_ERROR abandons the transaction with RESET_STREAM.
    let _ = send.reset(INTERNAL_ERROR);
    count(metrics, INTERNAL_ERROR);
}

async fn serve_stream<H: Handler>(mut stream: Stream<H>) {
    let mut buffers = stream.state.buffers.take();
    answer(&mut stream, &mut buffers).await;
    stream.state.buffers.put(buffers);
}

async fn answer<H: Handler>(stream: &mut Stream<H>, buffers: &mut (Vec<u8>, Vec<u8>)) {
    let metrics = stream.metrics.as_ref();
    // CoreDNS: the read timeout bounds a stalled stream so it cannot hold a worker.
    let read = timeout(
        stream.tcp.read,
        read_query(&mut stream.recv, &mut buffers.0),
    )
    .await
    .unwrap_or(Err(Failure::Stream));
    match read {
        Ok(()) => {}
        Err(Failure::Stream) => return fail(&mut stream.send, metrics),
        Err(Failure::Protocol) => return abort(&stream.connection, metrics),
        Err(Failure::Lost) => return,
    }
    // CoreDNS: an unparseable Message aborts the connection like any other protocol error.
    match Message::parse(&buffers.0) {
        Ok(query) if valid_request(&query) => {}
        _ => return abort(&stream.connection, metrics),
    }
    let (query, response) = buffers;
    response.clear();
    // RFC 9250 §4.2: DoQ Messages follow DNS over TCP rules, with no UDP size limit.
    let action =
        H::handle_shared(&stream.handler, query, stream.peer, Protocol::Tcp, response).await;
    // A dropped Query or a Zone Transfer has no DoQ Response here.
    let (Action::Respond, Ok(length)) = (action, u16::try_from(response.len())) else {
        return fail(&mut stream.send, metrics);
    };
    // RFC 9250 §4.2: Responses carry the same two-octet length prefix.
    response.extend_from_slice(&[0, 0]);
    response.rotate_right(2);
    response[..2].copy_from_slice(&length.to_be_bytes());
    let written = timeout(stream.tcp.write, async {
        stream.send.write_all(response).await.ok()?;
        // RFC 9250 §4.2: the server indicates STREAM FIN after the Response.
        stream.send.finish().ok()
    })
    .await;
    if !matches!(written, Ok(Some(()))) {
        return fail(&mut stream.send, metrics);
    }
    // A closing connection discards unacknowledged data, so a draining Listener waits for the ACK.
    if *stream.stop.borrow() {
        let _ = timeout(stream.tcp.write, stream.send.stopped()).await;
    }
    count(metrics, NO_ERROR);
}
