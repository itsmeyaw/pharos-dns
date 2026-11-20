# https3

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/https3/README.md)

## https3

- `https3 { max_streams N; max_connections N }` configures `https3://` Server Blocks, which need a `tls` Directive and listen on UDP port 443 by default. Defaults and validation match CoreDNS: 256 streams per connection and 200 connections. Each value may be set once, and `https3` may appear once per Server Block. When several Server Blocks share a Listener, the first block's limits apply, as in CoreDNS.
- `max_connections 0` removes the connection limit; `max_streams 0` keeps the QUIC library's own credit of 100 concurrent requests per connection. A connection over `max_connections` completes its handshake and is closed with HTTP/3 `H3_EXCESSIVE_LOAD` (0x107) and the reason `too many connections`, as CoreDNS does.
- The Listener reuses the `quic` Listener's endpoint (one UDP socket, handshake bounds, Retry above the connection limit, no 0-RTT) with ALPN `h3` only, and the `https` Plugin's request rules: `/dns-query`, GET `?dns=` (unpadded base64url) or POST bodies up to 65536 octets, 404 for other paths, 400 for other methods or unparsable and UPDATE Messages, 500 when the Chain gives no Response, `Content-Type: application/dns-message` and `Cache-Control: max-age=N` on a 200. Request `Content-Type` is not checked, as in CoreDNS. The Plugin Chain sees `Context::protocol` TCP and `Context::transport` `Https3`.
- `pharos_dns_https3_responses_total{server,status}` counts responses by numeric HTTP status.
- Differences from CoreDNS: a request field section over 16 KiB (CoreDNS `DefaultHTTPS3MaxHeaderBytes`) is refused by the h3 library; a request that stalls longer than the `timeouts` read timeout is abandoned; unidirectional streams are limited to `max(max_streams, 3)` instead of `max_streams`, so the control and QPACK streams always fit; QUIC flow control is sized to one Message per stream times `max_streams`; graceful shutdown sends GOAWAY, finishes in-flight requests, then closes with `H3_NO_ERROR` after a short grace period for the client to close first. HTTP/3 server push, WebTransport and 0-RTT are not offered.
- TLS uses rustls with the aws-lc-rs provider through quinn; `h3` 0.0.8 and `h3-quinn` 0.0.10 do not link `ring`.

## Sources

- [CoreDNS v1.15.0 `plugin/https3`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/https3)
