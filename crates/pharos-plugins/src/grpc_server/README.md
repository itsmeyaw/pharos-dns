# grpc_server

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/grpc_server/README.md)

## grpc_server

- Syntax, defaults (256 streams, 200 connections, `0` unbounded) and once-per-block validation match CoreDNS. A `max_streams` above 4294967295 is rejected at setup; CoreDNS converts it to a 32-bit value and wraps.
- `grpc://` Server Block Keys (default port 443) require the `tls` Directive. The Listener offers only ALPN `h2`; as in grpc-go, a client that offers no ALPN is dropped after the handshake.
- Pharos writes the gRPC framing and the one-field `DnsPacket` protobuf by hand over hyper's HTTP/2 server, without tonic or prost. `pharos_server::grpc` exposes the framing for gRPC clients. The protobuf reader keeps the last `msg` field and skips unknown fields, including groups up to 100 levels deep.
- Statuses follow grpc-go v1.84 as used by CoreDNS (`Unknown` for a Query miekg/dns would not accept, `Internal` for malformed protobuf, `ResourceExhausted` above 65,539 octets in either direction, `Unimplemented` for another service or method, HTTP 415 for another content type). Error statuses are Trailers-Only responses. The error texts of miekg/dns are not reproduced.
- Compression is not supported: a `grpc-encoding` other than `identity` is `Unimplemented`, a compressed message is `Internal`. `grpc-timeout` is honoured with `DeadlineExceeded`.
- When the Plugin Chain gives no Response (a dropped Query) or answers with a Zone Transfer stream, the status is `Internal`. CoreDNS sends its own request Message back as the Response in that case, and its gRPC Transport has no Zone Transfer.
- The Plugin Chain runs with the TCP rules for Message size (`Context::protocol` is TCP, `Context::transport` is `Grpc`). The client address is the TCP peer; `proxyproto` applies to the TCP peer (`proxyproto-grpc`).
- Timeouts (see `timeouts`): `read` bounds the TLS handshake and reading the request message, `write` the graceful close, and `idle` closes connections with no call in flight with a GOAWAY. CoreDNS has no idle timeout for gRPC.
- Connections over `max_connections` wait in the kernel accept backlog. A Reload that changes `max_connections` counts connections of the old limit separately until they close; new connections use the reloaded certificate, handler and limits, established ones keep theirs. Shutdown sends GOAWAY and lets running calls finish.
- No Transport-specific metrics, as in CoreDNS. Worst-case memory is `max_connections` × `max_streams` × 64 KiB, and unbounded when either is `0`.

## Sources

- [CoreDNS v1.15.0 `plugin/grpc_server`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/grpc_server)
- [CoreDNS v1.15.0 `core/dnsserver/server_grpc.go`](https://github.com/coredns/coredns/tree/v1.15.0/core/dnsserver/server_grpc.go)
- [CoreDNS v1.15.0 `pb/dns.proto`](https://github.com/coredns/coredns/tree/v1.15.0/pb/dns.proto)
- [gRPC over HTTP/2](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
