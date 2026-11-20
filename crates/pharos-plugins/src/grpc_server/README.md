# grpc_server

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/grpc_server/README.md)

## grpc_server

- `grpc://` Server Block Keys (default port 443) serve DNS over gRPC and require the `tls` Directive. `grpc_server { max_streams N; max_connections N }` is supported. Defaults and validation match CoreDNS: 256 streams per connection and 200 connections, `0` means unbounded, and each value may be set once per Server Block (a repeated `grpc_server` line merges, as in CoreDNS).
- A `max_streams` above 4294967295 is rejected at setup; CoreDNS converts it to a 32-bit value and wraps. `max_streams 0` advertises no `SETTINGS_MAX_CONCURRENT_STREAMS` limit.
- When Server Blocks share one `grpc://` Listener, the first block's limits apply, as in CoreDNS, and the blocks must share one TLS identity, client authentication policy and client CA pool.
- The service is `coredns.dns.DnsService/Query` with `DnsPacket { bytes msg = 1 }` (CoreDNS `pb/dns.proto`). Pharos writes the gRPC length-prefixed framing and the one-field protobuf by hand over hyper's HTTP/2 server, without tonic or prost. The protobuf reader keeps the last `msg` field, skips unknown fields and rejects groups. `pharos_server::grpc` exposes the framing for gRPC clients.
- The Listener offers only ALPN `h2`. A client that offers other protocols fails the handshake, and, as in grpc-go v1.84, a client that offers no ALPN is dropped after the handshake.
- Statuses follow grpc-go v1.84 as used by CoreDNS: a Query that is not DNS, or that miekg/dns would not accept (QR set, an opcode other than QUERY and NOTIFY, more than one Question), is `Unknown`; a payload that is not protobuf, a truncated message and a second request message are `Internal`; a payload over 65,539 octets (65,535 plus the protobuf tag and length, checked on the gRPC header) is `ResourceExhausted`; another service, method or malformed path is `Unimplemented`; a request that is not `application/grpc` or `application/grpc+proto` gets HTTP 415 with `InvalidArgument`, a method other than POST HTTP 405 with `Internal`, and a malformed `grpc-timeout` HTTP 400 with `Internal`. Error statuses are Trailers-Only responses with a percent-encoded `grpc-message`. The error texts of miekg/dns are not reproduced.
- Compression is not supported: a `grpc-encoding` other than `identity` is `Unimplemented`, and a message with the compressed flag is `Internal`. CoreDNS's sources import no compressor.
- `grpc-timeout` is honoured: a call still running at its deadline ends with `DeadlineExceeded`.
- When the Plugin Chain gives no Response (a dropped Query) or answers with a Zone Transfer stream, the status is `Internal` with `no response`. CoreDNS sends its own request Message back as the Response in that case, and its gRPC Transport has no Zone Transfer.
- Pharos runs the Plugin Chain with the TCP rules for Message size, so `Context::protocol` is TCP and `Context::transport` is `Grpc`.
- The client address is the TCP peer; `proxyproto` is not used yet.
- The TCP `read` timeout bounds the TLS handshake and reading the request message (a stalled call ends with `DeadlineExceeded`), `write` bounds the graceful close, and `idle` closes connections with no call in flight with a GOAWAY (see `timeouts`). CoreDNS has no idle timeout for gRPC; clients reconnect on demand.
- Connections over `max_connections` wait in the kernel accept backlog, as with Go's `netutil.LimitListener`. A Reload that changes `max_connections` counts connections of the old limit separately until they close. New connections use the reloaded certificate and limits; established connections keep theirs. Graceful shutdown sends GOAWAY and lets running calls finish.
- No metrics are specific to this Transport, as in CoreDNS; the usual per-server Plugin metrics carry the `grpc://:443` label.
- Pharos has no per-IP rate or in-flight limit beyond `max_connections` and `max_streams`; worst case memory is `max_connections` × `max_streams` × the 64 KiB message limit, and unbounded when either is `0`.

## Sources

- [CoreDNS v1.15.0 `plugin/grpc_server`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/grpc_server)
- [CoreDNS v1.15.0 `core/dnsserver/server_grpc.go`](https://github.com/coredns/coredns/tree/v1.15.0/core/dnsserver/server_grpc.go)
- [CoreDNS v1.15.0 `pb/dns.proto`](https://github.com/coredns/coredns/tree/v1.15.0/pb/dns.proto)
- [gRPC over HTTP/2](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
