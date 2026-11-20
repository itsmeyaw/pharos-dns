//! DNS over QUIC (RFC 9250) client: one quinn endpoint and one connection per Upstream.
//!
//! The module hides quinn behind [`DoqClient`] and [`DoqConnection`], the way `tls` hides rustls.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use pharos_proto::Message;
use quinn::{
    ClientConfig, Connection, ConnectionError, Endpoint, EndpointConfig, IdleTimeout, ReadError,
    ReadExactError, RecvStream, SendStream, TokioRuntime, TransportConfig, VarInt,
    crypto::rustls::QuicClientConfig,
};

use crate::{
    quic::{ALPN, NO_ERROR, PROTOCOL_ERROR, STREAM_WINDOW, bind},
    tls::ClientConfig as TlsConfig,
};

// RFC 9250 §8.4: DOQ_REQUEST_CANCELLED tells the server a client abandoned its Query.
const REQUEST_CANCELLED: VarInt = VarInt::from_u32(3);

/// Why a DoQ exchange failed.
#[derive(Debug)]
pub enum DoqError {
    /// No stream could be opened; the connection is unusable.
    Open(io::Error),
    /// The server broke DoQ; the connection was closed with `DOQ_PROTOCOL_ERROR`.
    Protocol(&'static str),
    /// The stream failed; the connection may still serve other Queries.
    Stream(io::Error),
}

impl std::fmt::Display for DoqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open(error) | Self::Stream(error) => error.fmt(f),
            Self::Protocol(reason) => write!(f, "DNS-over-QUIC protocol error: {reason}"),
        }
    }
}

impl std::error::Error for DoqError {}

/// A QUIC client socket that dials one Upstream.
pub struct DoqClient {
    endpoint: Endpoint,
    config: ClientConfig,
    remote: SocketAddr,
}

impl DoqClient {
    /// Bind a client socket of `remote`'s family, optionally to `source`.
    ///
    /// `idle` is how long a silent connection lives before QUIC drops it.
    /// Must be called from a Tokio runtime.
    pub fn new(
        tls: &Arc<TlsConfig>,
        source: Option<IpAddr>,
        remote: SocketAddr,
        idle: Duration,
    ) -> io::Result<Self> {
        // RFC 9250 §4.1.1: DoQ negotiates ALPN "doq"; RFC 9001 §4.2 requires TLS 1.3, which QUIC enforces.
        let mut tls = TlsConfig::clone(tls);
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let crypto = QuicClientConfig::try_from(tls).map_err(io::Error::other)?;
        let mut config = ClientConfig::new(Arc::new(crypto));
        let mut transport = TransportConfig::default();
        // RFC 9250 §4.2: only the client opens streams; a server may not open any.
        transport.max_concurrent_bidi_streams(VarInt::from_u32(0));
        transport.max_concurrent_uni_streams(VarInt::from_u32(0));
        transport.datagram_receive_buffer_size(None);
        transport.max_idle_timeout(IdleTimeout::try_from(idle).ok());
        // RFC 9250 §5.8: one Response, at most 65535 octets plus its length, may be buffered per stream.
        transport.stream_receive_window(VarInt::from_u32(STREAM_WINDOW));
        config.transport_config(Arc::new(transport));
        let any = if remote.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let socket = bind(SocketAddr::new(source.unwrap_or(any), 0))?;
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )?;
        Ok(Self {
            endpoint,
            config,
            remote,
        })
    }

    /// Complete a handshake with the Upstream, verifying its certificate for `server_name`.
    /// The caller bounds the handshake with its own timeout.
    pub async fn connect(&self, server_name: &str) -> io::Result<DoqConnection> {
        let connection = self
            .endpoint
            .connect_with(self.config.clone(), self.remote, server_name)
            .map_err(io::Error::other)?
            .await
            .map_err(connection_error)?;
        let local = self.endpoint.local_addr()?;
        Ok(DoqConnection {
            local: SocketAddr::new(connection.local_ip().unwrap_or(local.ip()), local.port()),
            connection,
        })
    }

    /// Close every connection and the socket.
    pub fn close(&self) {
        // RFC 9250 §5.3: DOQ_NO_ERROR closes a connection that did nothing wrong.
        self.endpoint.close(NO_ERROR, b"");
    }
}

/// One QUIC connection that carries many Queries, each on its own stream.
pub struct DoqConnection {
    connection: Connection,
    local: SocketAddr,
}

impl DoqConnection {
    /// The client's own address on this connection.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Whether the connection ended, locally or by the peer.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    /// Send `wire[..query_len]` on a new stream and read the Response back into `wire`.
    ///
    /// The Query ID must be zero; the Response ID is zero too (RFC 9250 §4.2.1).
    /// Dropping the returned future abandons the stream with `DOQ_REQUEST_CANCELLED`.
    pub async fn exchange(&self, wire: &mut [u8], query_len: usize) -> Result<usize, DoqError> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|error| DoqError::Open(connection_error(error)))?;
        let mut stream = Stream {
            send,
            recv,
            done: false,
        };
        let failed = |error: quinn::WriteError| DoqError::Stream(io::Error::other(error));
        // RFC 9250 §4.2: a Query is a two-octet length and a Message, followed by STREAM FIN.
        let length = u16::try_from(query_len).expect("caller bounds the Query to 65535 octets");
        stream
            .send
            .write_all(&length.to_be_bytes())
            .await
            .map_err(failed)?;
        stream
            .send
            .write_all(&wire[..query_len])
            .await
            .map_err(failed)?;
        stream
            .send
            .finish()
            .map_err(|error| DoqError::Stream(io::Error::other(error)))?;
        let len = match self.read_response(&mut stream, wire).await {
            Ok(len) => len,
            Err(DoqError::Protocol(reason)) => {
                // RFC 9250 §4.3.3: a protocol error closes the connection with DOQ_PROTOCOL_ERROR.
                self.connection.close(PROTOCOL_ERROR, reason.as_bytes());
                return Err(DoqError::Protocol(reason));
            }
            Err(error) => return Err(error),
        };
        stream.done = true;
        Ok(len)
    }

    async fn read_response(&self, stream: &mut Stream, wire: &mut [u8]) -> Result<usize, DoqError> {
        let early = |reason| {
            move |error: ReadExactError| match error {
                // RFC 9250 §4.3.3: STREAM FIN before the whole Message arrived is a protocol error.
                ReadExactError::FinishedEarly(_) => DoqError::Protocol(reason),
                ReadExactError::ReadError(error) => read_error(error),
            }
        };
        let mut prefix = [0; 2];
        stream
            .recv
            .read_exact(&mut prefix)
            .await
            .map_err(early("incomplete message length"))?;
        let size = usize::from(u16::from_be_bytes(prefix));
        // RFC 9250 §4.2: DoQ v1 requires the length prefix; a zero length is a draft-version peer.
        if size == 0 {
            return Err(DoqError::Protocol("zero-length DNS message"));
        }
        let Some(message) = wire.get_mut(..size) else {
            return Err(DoqError::Stream(io::ErrorKind::InvalidData.into()));
        };
        stream
            .recv
            .read_exact(message)
            .await
            .map_err(early("message ended early"))?;
        // RFC 9250 §4.2: the server indicates STREAM FIN after its one Response.
        match stream.recv.read(&mut [0]).await {
            Ok(None) => {}
            Ok(Some(_)) => return Err(DoqError::Protocol("multiple responses on one stream")),
            Err(error) => return Err(read_error(error)),
        }
        // RFC 9250 §4.2.1: the Response must be a Message with ID zero.
        match Message::parse(&wire[..size]) {
            Ok(message) if message.id() == 0 => Ok(size),
            Ok(_) => Err(DoqError::Protocol("response message ID is not 0")),
            Err(_) => Err(DoqError::Protocol("invalid DNS response")),
        }
    }
}

impl Drop for DoqConnection {
    fn drop(&mut self) {
        // RFC 9250 §5.3: DOQ_NO_ERROR closes a connection that did nothing wrong.
        self.connection.close(NO_ERROR, b"");
    }
}

/// Abandons the transaction unless the Response arrived whole.
struct Stream {
    send: SendStream,
    recv: RecvStream,
    done: bool,
}

impl Drop for Stream {
    fn drop(&mut self) {
        if !self.done {
            // RFC 9250 §4.3.2: DOQ_REQUEST_CANCELLED abandons a transaction in both directions.
            let _ = self.send.reset(REQUEST_CANCELLED);
            let _ = self.recv.stop(REQUEST_CANCELLED);
        }
    }
}

fn read_error(error: ReadError) -> DoqError {
    DoqError::Stream(io::Error::other(error))
}

fn connection_error(error: ConnectionError) -> io::Error {
    match error {
        ConnectionError::TimedOut => io::ErrorKind::TimedOut.into(),
        other => io::Error::other(other),
    }
}
