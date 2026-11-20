//! PROXY protocol (v1 and v2) support for Listener accept paths.
//!
//! The `proxyproto` Plugin builds one [`Config`] per Listener. The TCP and TLS accept
//! loops of this crate and the UDP workers call it directly. The seam for a Transport
//! that Pharos does not serve yet (https, grpc, quic, https3) is the same pair of calls:
//! [`Config::accept_stream`] on each accepted TCP stream before TLS or HTTP reads it, and
//! [`Config::accept_datagram`] on each received datagram before QUIC reads it.

pub mod header;
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
                        .store(peer, (source, &state.tlv), Instant::now(), tracking.ttl);
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
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    const PROXY: &str = "10.1.1.1:5000";
    const CLIENT: &str = "192.0.2.1:12345";

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn v1() -> Vec<u8> {
        b"PROXY TCP4 192.0.2.1 192.0.2.53 12345 53\r\n".to_vec()
    }

    // PROXY protocol §2.2: PROXY command, IPv4, STREAM (0x11) or DGRAM (0x12).
    fn v2(family: u8, tlvs: &[u8]) -> Vec<u8> {
        let mut wire = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        wire.extend([0x21, family]);
        wire.extend(u16::try_from(12 + tlvs.len()).unwrap().to_be_bytes());
        wire.extend([192, 0, 2, 1, 192, 0, 2, 53]);
        wire.extend(12345u16.to_be_bytes());
        wire.extend(53u16.to_be_bytes());
        wire.extend(tlvs);
        wire
    }

    fn config(policy: Policy) -> Config {
        let mut config = Config::new(move |_| policy);
        config.header_timeout = Duration::from_millis(200);
        config
    }

    async fn accept(
        config: &Config,
        wire: &[u8],
    ) -> io::Result<(SocketAddr, Option<Arc<str>>, Vec<u8>)> {
        let (mut client, server) = tokio::io::duplex(8192);
        client.write_all(wire).await.unwrap();
        drop(client);
        let mut accepted = config.accept_stream(server, addr(PROXY)).await?;
        let mut rest = Vec::new();
        accepted.stream.read_to_end(&mut rest).await.unwrap();
        Ok((accepted.peer, accepted.tlv, rest))
    }

    #[tokio::test]
    async fn v1_header_replaces_the_peer_and_keeps_following_bytes() {
        let mut wire = v1();
        wire.extend(b"\x00\x1dDNS");
        let (peer, tlv, rest) = accept(&config(Policy::Use), &wire).await.unwrap();
        assert_eq!(
            (peer, tlv, rest),
            (addr(CLIENT), None, b"\x00\x1dDNS".to_vec())
        );
    }

    #[tokio::test]
    async fn v2_header_replaces_the_peer() {
        let mut wire = v2(0x11, &[]);
        wire.extend(b"DNS");
        let (peer, _, rest) = accept(&config(Policy::Use), &wire).await.unwrap();
        assert_eq!((peer, rest), (addr(CLIENT), b"DNS".to_vec()));
    }

    #[tokio::test]
    async fn v2_local_command_keeps_the_peer() {
        let mut wire = v2(0x00, &[]);
        wire[12] = 0x20;
        wire[14..16].copy_from_slice(&0u16.to_be_bytes());
        wire.truncate(16);
        wire.extend(b"DNS");
        let (peer, _, rest) = accept(&config(Policy::Use), &wire).await.unwrap();
        assert_eq!((peer, rest), (addr(PROXY), b"DNS".to_vec()));
    }

    #[tokio::test]
    async fn v1_unknown_keeps_the_peer() {
        let (peer, _, rest) = accept(&config(Policy::Use), b"PROXY UNKNOWN\r\nDNS")
            .await
            .unwrap();
        assert_eq!((peer, rest), (addr(PROXY), b"DNS".to_vec()));
    }

    #[tokio::test]
    async fn stream_without_a_header_passes_through_under_use() {
        let wire = b"\x00\x1d\x12\x34 dns query";
        let (peer, _, rest) = accept(&config(Policy::Use), wire).await.unwrap();
        assert_eq!((peer, rest), (addr(PROXY), wire.to_vec()));
    }

    #[tokio::test]
    async fn ignore_consumes_the_header_and_keeps_the_peer() {
        let mut wire = v1();
        wire.extend(b"DNS");
        let (peer, tlv, rest) = accept(&config(Policy::Ignore), &wire).await.unwrap();
        assert_eq!((peer, tlv, rest), (addr(PROXY), None, b"DNS".to_vec()));
    }

    #[tokio::test]
    async fn reject_refuses_a_header_and_passes_other_streams() {
        let error = accept(&config(Policy::Reject), &v1()).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let (peer, _, rest) = accept(&config(Policy::Reject), b"\x00\x1dDNS")
            .await
            .unwrap();
        assert_eq!((peer, rest), (addr(PROXY), b"\x00\x1dDNS".to_vec()));
    }

    #[tokio::test]
    async fn skip_leaves_the_header_in_the_stream() {
        let wire = v1();
        let (peer, _, rest) = accept(&config(Policy::Skip), &wire).await.unwrap();
        assert_eq!((peer, rest), (addr(PROXY), wire));
    }

    #[tokio::test]
    async fn policy_is_chosen_per_peer() {
        let config = Config::new(|ip| {
            if ip == "10.1.1.1".parse::<IpAddr>().unwrap() {
                Policy::Use
            } else {
                Policy::Reject
            }
        });
        let (trusted, _, _) = accept(&config, &v1()).await.unwrap();
        assert_eq!(trusted, addr(CLIENT));
        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(&v1()).await.unwrap();
        let error = config
            .accept_stream(server, addr("10.9.9.9:1"))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn tlv_hex_is_kept_only_when_requested() {
        let mut wire = v2(0x11, &[0xEA, 0, 2, 0xCA, 0xFE]);
        wire.extend(b"DNS");
        let mut on = config(Policy::Use);
        on.tlv_metadata = true;
        let (_, tlv, _) = accept(&on, &wire).await.unwrap();
        assert_eq!(tlv.as_deref(), Some("ea0002cafe"));
        let (_, tlv, _) = accept(&config(Policy::Use), &wire).await.unwrap();
        assert_eq!(tlv, None);
        let (_, tlv, _) = accept(&on, &v2(0x11, &[])).await.unwrap();
        assert_eq!(tlv, None);
    }

    #[tokio::test]
    async fn header_split_across_reads_is_assembled() {
        let (mut client, server) = tokio::io::duplex(8192);
        let config = config(Policy::Use);
        let wire = v2(0x11, &[0xEA, 0, 1, 7]);
        let writer = tokio::spawn(async move {
            for chunk in wire.chunks(3) {
                client.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
            client
        });
        let accepted = config.accept_stream(server, addr(PROXY)).await.unwrap();
        assert_eq!(accepted.peer, addr(CLIENT));
        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn a_silent_peer_times_out() {
        let (_client, server) = tokio::io::duplex(1024);
        let mut config = config(Policy::Use);
        config.header_timeout = Duration::from_millis(50);
        let error = config
            .accept_stream(server, addr(PROXY))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_stalled_partial_header_times_out() {
        let (mut client, server) = tokio::io::duplex(1024);
        client.write_all(b"PROXY TCP4 192.0.2.1 ").await.unwrap();
        let mut config = config(Policy::Use);
        config.header_timeout = Duration::from_millis(50);
        let error = config
            .accept_stream(server, addr(PROXY))
            .await
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn truncated_headers_fail() {
        for wire in [&v1()[..20], &v2(0x11, &[])[..20]] {
            let error = accept(&config(Policy::Use), wire).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    #[tokio::test]
    async fn malicious_headers_fail_without_unbounded_reads() {
        let mut oversized = v2(0x11, &[]);
        oversized[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        let long_v1 = [b"PROXY UNKNOWN ".as_slice(), &[b'x'; 4096]].concat();
        for wire in [
            oversized,
            long_v1,
            b"PROXY TCP4 999.0.0.1 192.0.2.53 1 2\r\n".to_vec(),
            b"PROXY TCP4 192.0.2.1 192.0.2.53 1 2\n".to_vec(),
        ] {
            let error = accept(&config(Policy::Use), &wire).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    fn datagram(
        config: &Config,
        state: &mut UdpState,
        wire: &[u8],
        peer: &str,
    ) -> Option<(usize, SocketAddr)> {
        config.accept_datagram(state, wire, addr(peer), 1)
    }

    fn tracking(policy: Policy) -> Config {
        let mut config = config(policy);
        config.udp_tracking = Some(UdpTracking {
            ttl: Duration::from_secs(60),
            max_sessions: 10,
        });
        config.tlv_metadata = true;
        config
    }

    #[test]
    fn datagram_header_is_stripped_under_use() {
        let mut wire = v2(0x12, &[]);
        let header = wire.len();
        wire.extend(b"DNS");
        let result = datagram(&config(Policy::Use), &mut UdpState::default(), &wire, PROXY);
        assert_eq!(result, Some((header, addr(CLIENT))));
    }

    #[test]
    fn datagram_header_is_stripped_but_ignored_under_ignore() {
        let mut wire = v2(0x12, &[]);
        let header = wire.len();
        wire.extend(b"DNS");
        let result = datagram(
            &config(Policy::Ignore),
            &mut UdpState::default(),
            &wire,
            PROXY,
        );
        assert_eq!(result, Some((header, addr(PROXY))));
    }

    #[test]
    fn datagram_header_is_dropped_under_reject_and_untouched_under_skip() {
        let mut wire = v2(0x12, &[]);
        wire.extend(b"DNS");
        let mut state = UdpState::default();
        assert_eq!(
            datagram(&config(Policy::Reject), &mut state, &wire, PROXY),
            None
        );
        assert_eq!(
            datagram(&config(Policy::Skip), &mut state, &wire, PROXY),
            Some((0, addr(PROXY)))
        );
        assert_eq!(
            datagram(&config(Policy::Reject), &mut state, b"plain dns", PROXY),
            Some((0, addr(PROXY)))
        );
    }

    #[test]
    fn datagram_headers_that_are_not_v2_datagram_headers_are_dropped() {
        let mut state = UdpState::default();
        let stream = v2(0x11, &[]);
        let mut v1 = v1();
        v1.extend(b"DNS");
        let truncated = v2(0x12, &[])[..14].to_vec();
        for wire in [&stream[..], &v1, &truncated] {
            assert_eq!(
                datagram(&config(Policy::Use), &mut state, wire, PROXY),
                None
            );
        }
    }

    #[test]
    fn header_only_datagram_opens_a_session_for_headerless_ones() {
        let config = tracking(Policy::Use);
        let mut state = UdpState::default();
        let wire = v2(0x12, &[0xEA, 0, 1, 9]);
        assert_eq!(datagram(&config, &mut state, &wire, PROXY), None);
        assert_eq!(
            datagram(&config, &mut state, b"dns", PROXY),
            Some((0, addr(CLIENT)))
        );
        assert_eq!(state.tlv, "ea000109");
        assert_eq!(
            datagram(&config, &mut state, b"dns", "10.1.1.1:5001"),
            Some((0, addr("10.1.1.1:5001")))
        );
        assert_eq!(state.tlv, "");
    }

    #[test]
    fn header_datagram_without_tracking_publishes_its_tlv_only_for_itself() {
        let mut config = config(Policy::Use);
        config.tlv_metadata = true;
        let mut state = UdpState::default();
        let mut wire = v2(0x12, &[0xEA, 0, 1, 9]);
        wire.extend(b"dns");
        assert!(datagram(&config, &mut state, &wire, PROXY).is_some());
        assert_eq!(state.tlv, "ea000109");
        assert_eq!(
            datagram(&config, &mut state, b"dns", PROXY),
            Some((0, addr(PROXY)))
        );
        assert_eq!(state.tlv, "");
    }

    #[test]
    fn header_only_datagram_without_tracking_is_dropped() {
        let wire = v2(0x12, &[]);
        let result = datagram(&config(Policy::Use), &mut UdpState::default(), &wire, PROXY);
        assert_eq!(result, None);
    }

    #[test]
    fn ignore_does_not_use_sessions() {
        let config = tracking(Policy::Ignore);
        let mut state = UdpState::default();
        assert_eq!(datagram(&config, &mut state, &v2(0x12, &[]), PROXY), None);
        assert_eq!(
            datagram(&config, &mut state, b"dns", PROXY),
            Some((0, addr(PROXY)))
        );
    }

    #[test]
    fn expired_sessions_stop_applying() {
        let mut config = tracking(Policy::Use);
        config.udp_tracking = Some(UdpTracking {
            ttl: Duration::from_millis(20),
            max_sessions: 10,
        });
        let mut state = UdpState::default();
        assert_eq!(datagram(&config, &mut state, &v2(0x12, &[]), PROXY), None);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(
            datagram(&config, &mut state, b"dns", PROXY),
            Some((0, addr(PROXY)))
        );
    }

    #[test]
    fn session_capacity_is_shared_between_workers() {
        let tracking = UdpTracking {
            ttl: Duration::from_secs(1),
            max_sessions: 10,
        };
        assert_eq!(
            (share(tracking, 4), share(tracking, 1), share(tracking, 0)),
            (3, 10, 10)
        );
    }
}
