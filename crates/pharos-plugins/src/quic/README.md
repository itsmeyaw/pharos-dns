# quic

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/quic/README.md)

## quic

- `quic { max_streams N; max_connections N; worker_pool_size N }` configures `quic://` Server Blocks, which need a `tls` Directive and listen on UDP port 853 by default. Defaults and validation match CoreDNS: 256 streams per connection, 200 connections (`0` removes the limit) and 1024 concurrent stream workers. Each value may be set once, and `quic` may appear once per Server Block. When several Server Blocks share a Listener, the first block's limits apply, as in CoreDNS.
- The Listener speaks DoQ version 1 (RFC 9250) only: ALPN `doq`, TLS 1.3 only (the `tls` Directive's TLS 1.2 minimum applies to `tls://`), one Query per client-initiated bidirectional stream with a two-octet length prefix. Draft DoQ versions without the length prefix, or with other ALPN tokens, are rejected.
- Pharos runs the Plugin Chain with the TCP rules for Message size, so `Context::protocol` is TCP and `Context::transport` is `Quic`.
- RFC 9250 §4.3.3 protocol errors abort the connection with `DOQ_PROTOCOL_ERROR` (2): a non-zero Message ID, an `edns-tcp-keepalive` option, an unparseable Message, a zero length prefix, STREAM FIN before the whole Message arrived, and data after the Message. Pharos also requires the client's STREAM FIN before it answers, as RFC 9250 §4.2 requires; CoreDNS answers without waiting for it. Reading to FIN also keeps the server from sending STOP_SENDING toward clients.
- A stream that stalls longer than the `timeouts` read timeout (default 3 seconds), or that the peer resets, is abandoned alone with RESET_STREAM `DOQ_INTERNAL_ERROR` (1); the connection and its other streams continue. A Query the Chain drops, a Zone Transfer (not available over DoQ) or a Response that cannot be written is reset the same way. After a read timeout Pharos's QUIC library also sends STOP_SENDING to the stalled client.
- A connection over `max_connections` completes its handshake and is closed with code 0 and the reason `too many connections`, as CoreDNS does. A full worker pool pauses accepting new streams on connections until a worker is free, so the client's stream credit (`max_streams`) bounds the waiting Queries.
- `pharos_dns_quic_responses_total{server,status}` counts `0x0` for each answered Query, `0x1` for each reset stream and `0x2` for each protocol abort. Unlike CoreDNS, a client that closes a healthy connection with code 0 is not counted as `0x1`.
- Differences from CoreDNS: 0-RTT is disabled (RFC 9250 §4.5 requires replay protection that Pharos does not implement), unidirectional streams are not allowed (CoreDNS counts them against `max_streams`), and the server's QUIC idle timeout is the `timeouts` idle timeout (default 10 seconds) as in CoreDNS. The Listener does not use `SO_REUSEPORT`, since the kernel would split a connection's datagrams across sockets.
- Reload keeps the Listener's UDP socket and its connections. New connections use the reloaded certificate and limits; established connections keep theirs. Graceful shutdown stops accepting connections, finishes in-flight streams, then closes connections with code 0.
- TLS uses rustls with the aws-lc-rs provider; quinn is built with `rustls-aws-lc-rs` and without its default `rustls-ring` feature, so `ring` is not linked on Linux or macOS. `quinn`'s `platform-verifier`, `log` and `bloom` defaults are disabled.

## Sources

- [CoreDNS v1.15.0 `plugin/quic`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/quic)
- [CoreDNS v1.15.0 `core/dnsserver/server_quic.go`](https://github.com/coredns/coredns/tree/v1.15.0/core/dnsserver/server_quic.go)
- [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250)
