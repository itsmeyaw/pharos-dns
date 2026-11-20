//! PROXY protocol (v1 and v2) support for Listener accept paths.
//!
//! The `proxyproto` Plugin builds one [`Config`] per Listener. The TCP and TLS accept
//! loops of this crate and the UDP workers call it directly. The seam for a Transport
//! The https and grpc accept loops call [`Config::accept_stream`] before the TLS handshake. The
//! quic and https3 endpoints read their UDP socket through [`quic::Socket`], which calls
//! [`Config::accept_datagram`] on each received datagram before quinn sees it.

pub mod header;
pub(crate) mod quic;
pub mod session;

use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use header::{Command, Parse};
use session::Sessions;

/// Metadata label that carries the hex-encoded PROXY v2 TLV vector.
pub const TLV_LABEL: &str = "proxyproto/tlv";

// go-proxyproto v0.15.0 DefaultReadHeaderTimeout: bound how long a peer may take to send its header.
const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// How a Listener treats the PROXY header of connections from one peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Policy {
    /// Replace the peer address with the header's source.
    Use,
    /// Consume a header but keep the peer address.
    Ignore,
    /// Close a connection that sends a header.
    Reject,
    /// Do not look for a header; the bytes belong to the application protocol.
    Skip,
}

/// UDP session tracking for Cloudflare Spectrum style headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UdpTracking {
    pub ttl: Duration,
    /// Cache bound for the whole Listener; each UDP worker holds its share.
    pub max_sessions: usize,
}

/// PROXY protocol settings of one Listener.
pub struct Config {
    decide: Box<dyn Fn(IpAddr) -> Policy + Send + Sync>,
    pub udp_tracking: Option<UdpTracking>,
    pub tlv_metadata: bool,
    pub header_timeout: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("udp_tracking", &self.udp_tracking)
            .field("tlv_metadata", &self.tlv_metadata)
            .field("header_timeout", &self.header_timeout)
            .finish_non_exhaustive()
    }
}

/// A stream whose PROXY header was consumed.
pub struct Accepted<S> {
    pub stream: Prefixed<S>,
    pub peer: SocketAddr,
    /// The hex TLV vector, present only when `tlv_metadata` is set and the header carried TLVs.
    pub tlv: Option<Arc<str>>,
}

/// What a parsed stream header contributes; `source` is set for the PROXY command only.
struct Seen {
    length: usize,
    source: Option<SocketAddr>,
    tlv: Option<Arc<str>>,
}

/// Per-worker UDP state: the session cache and the TLV hex of the last accepted datagram.
#[derive(Default)]
pub struct UdpState {
    sessions: Option<Sessions>,
    pub tlv: String,
    /// The Listener's UDP worker count, read once because looking it up allocates.
    pub workers: usize,
}

impl Config {
    #[must_use]
    pub fn new(policy: impl Fn(IpAddr) -> Policy + Send + Sync + 'static) -> Self {
        Self {
            decide: Box::new(policy),
            udp_tracking: None,
            tlv_metadata: false,
            header_timeout: DEFAULT_HEADER_TIMEOUT,
        }
    }

    /// The policy for connections and datagrams from `address`.
    #[must_use]
    pub fn policy(&self, address: IpAddr) -> Policy {
        (self.decide)(address)
    }

    /// Read the PROXY header of an accepted stream, applying the policy for `peer`.
    ///
    /// # Errors
    /// Returns an error when the connection must be closed: a malformed header, a header
    /// the policy rejects, a read failure, or no complete header within `header_timeout`.
    pub async fn accept_stream<S: AsyncRead + Unpin>(
        &self,
        mut stream: S,
        peer: SocketAddr,
    ) -> io::Result<Accepted<S>> {
        let policy = self.policy(peer.ip());
        let mut buffer = Vec::new();
        let mut seen = None;
        if policy != Policy::Skip {
            // go-proxyproto ReadHeaderTimeout: a header that never completes closes the connection.
            seen = tokio::time::timeout(
                self.header_timeout,
                self.read_header(&mut stream, &mut buffer),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "PROXY header timed out"))??;
        }
        let mut accepted = Accepted {
            peer,
            tlv: None,
            stream: Prefixed {
                inner: stream,
                buffered: Vec::new(),
                position: 0,
            },
        };
        if let Some(seen) = seen {
            match policy {
                // go-proxyproto REJECT: a connection that sends a PROXY header is refused.
                Policy::Reject => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "PROXY header rejected by policy",
                    ));
                }
                // go-proxyproto USE: a PROXY command replaces the peer; LOCAL keeps the connection's own.
                Policy::Use => {
                    if let Some(source) = seen.source {
                        accepted.peer = crate::canonical_peer(source);
                        accepted.tlv = seen.tlv;
                    }
                }
                Policy::Ignore | Policy::Skip => {}
            }
            buffer.drain(..seen.length);
        }
        accepted.stream.buffered = buffer;
        Ok(accepted)
    }

    // PROXY protocol §2: a receiver reads the header before any other data and does not guess its presence.
    async fn read_header<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        buffer: &mut Vec<u8>,
    ) -> io::Result<Option<Seen>> {
        loop {
            match header::parse(buffer)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            {
                Parse::NotProxy => return Ok(None),
                Parse::Header(parsed) => {
                    let mut hex = String::new();
                    let tlv = (self.tlv_metadata && header::tlv_hex(parsed.tlvs, &mut hex))
                        .then(|| hex.into());
                    return Ok(Some(Seen {
                        length: parsed.length,
                        source: parsed.source,
                        tlv,
                    }));
                }
                Parse::Incomplete => {}
            }
            if buffer.capacity() == buffer.len() {
                buffer.reserve(512);
            }
            if stream.read_buf(buffer).await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    /// Strip the PROXY header of one datagram.
    ///
    /// Returns the offset where the DNS payload starts and the client address, or `None`
    /// when the datagram must be dropped. `state.tlv` holds the TLV hex for the payload.
    pub fn accept_datagram(
        &self,
        state: &mut UdpState,
        datagram: &[u8],
        peer: SocketAddr,
        workers: usize,
    ) -> Option<(usize, SocketAddr)> {
        state.tlv.clear();
        let policy = self.policy(peer.ip());
        if policy == Policy::Skip {
            return Some((0, peer));
        }
        let parsed = match header::parse(datagram) {
            // go-proxyproto: a datagram header is v2 and names the UDP protocol.
            Ok(Parse::Header(parsed)) if parsed.version == 2 && parsed.datagram => parsed,
            // CoreDNS PacketConn: a bad header drops the datagram instead of ending the read loop.
            Ok(Parse::Header(_) | Parse::Incomplete) | Err(_) => return None,
            Ok(Parse::NotProxy) => return self.headerless(state, policy, peer),
        };
        let payload_empty = parsed.length == datagram.len();
        let client = match policy {
            Policy::Reject => return None,
            Policy::Use if parsed.command == Command::Proxy => {
                let source = crate::canonical_peer(parsed.source?);
                if self.tlv_metadata {
                    header::tlv_hex(parsed.tlvs, &mut state.tlv);
                }
                if let Some(tracking) = self.udp_tracking {
                    // CoreDNS PacketConn: the header datagram opens or refreshes the flow's session.
                    state
                        .sessions
                        .get_or_insert_with(|| Sessions::new(share(tracking, workers)))
                        .store(peer, (source, &state.tlv), Instant::now());
                }
                source
            }
            _ => peer,
        };
        // CoreDNS PacketConn: a header-only datagram has no DNS payload and is not delivered.
        (!payload_empty).then_some((parsed.length, client))
    }

    fn headerless(
        &self,
        state: &mut UdpState,
        policy: Policy,
        peer: SocketAddr,
    ) -> Option<(usize, SocketAddr)> {
        let (Policy::Use, Some(tracking)) = (policy, self.udp_tracking) else {
            return Some((0, peer));
        };
        // CoreDNS PacketConn: a headerless datagram takes the address its flow's header named.
        let client = state.sessions.as_mut().and_then(|sessions| {
            sessions.lookup(peer, Instant::now(), tracking.ttl, &mut state.tlv)
        });
        // Reload: a session cached while `tlv_metadata` was on publishes no TLVs once it is off.
        if !self.tlv_metadata {
            state.tlv.clear();
        }
        Some((0, client.unwrap_or(peer)))
    }
}

fn share(tracking: UdpTracking, workers: usize) -> usize {
    tracking.max_sessions.div_ceil(workers.max(1))
}

/// A stream that yields bytes read past a PROXY header before reading its inner stream.
pub struct Prefixed<S> {
    inner: S,
    buffered: Vec<u8>,
    position: usize,
}

impl<S> Prefixed<S> {
    /// Wrap a stream that needs no bytes replayed, for Listeners that serve connections with and without a header alike.
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            buffered: Vec::new(),
            position: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.position < this.buffered.len() {
            let rest = &this.buffered[this.position..];
            let count = rest.len().min(out.remaining());
            out.put_slice(&rest[..count]);
            this.position += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, out)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
