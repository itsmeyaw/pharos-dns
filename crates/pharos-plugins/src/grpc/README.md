# grpc

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/grpc/README.md)

## grpc

- Syntax matches CoreDNS: `grpc FROM TO... { except NAME...; tls [CERT KEY] [CA]; tls_servername NAME; policy random|round_robin|sequential; fallthrough [ZONE...] }`. The Directive is allowed once per Server Block, takes at most 15 Upstreams, and accepts a resolv.conf-style file as TO (each `nameserver` on port 53).
- TO is an IP address, `IP:PORT` (default port 53), `[IPV6]:PORT`, `unix:///PATH` or a file. CoreDNS also accepts `dns://`, `grpc://`, `tls://`, `quic://` and `https://` prefixes in setup and fails at the first Query; Pharos rejects every scheme but `unix://` at setup. A nameserver in a resolv.conf-style file that is not an IP address fails setup; CoreDNS keeps it and fails at dial. An IPv6 zone is dropped, as in `forward`. A port outside 1-65535 is rejected at setup.
- A Query inside FROM and not under an `except` name goes to the Upstreams in `policy` order (default `random`; `round_robin` starts with the next Upstream on each Query). The first Upstream that answers wins; an error, a timeout or a reply that is not one DNS Message moves on to the next. One 5 second deadline covers all attempts, and is sent as `grpc-timeout`.
- Without `tls` and `tls_servername` the call is plain-text gRPC (HTTP/2 prior knowledge). Either one turns TLS on: `tls` takes `CA`, `CERT KEY` or `CERT KEY CA` (relative paths join `root`) and no argument keeps the system roots; `tls_servername` is the name the certificate must carry, else the Upstream's IP address. TLS 1.2 is the minimum and ALPN `h2` is required, as in grpc-go. The client uses the shared `pharos_server::tls` configuration (rustls with aws-lc-rs).
- The gRPC framing and the one-field `DnsPacket` protobuf are the hand-written ones of `pharos_server::grpc`, over hyper's HTTP/2 client, without tonic or prost. Compression is not offered and a compressed reply is an error. A reply over 65539 octets, a DNS Message over 65535 octets, or more than one message in the reply is an error, as `MaxCallRecvMsgSize` is in grpc-go.
- gRPC status `NotFound` is an empty NXDOMAIN reply (Question, RD and CD copied) and is not counted in the metrics. A reply whose Question differs from the Query's, or that is not a Response, is answered with FORMERR. When every Upstream fails the Query gets SERVFAIL.
- `fallthrough` hands an NXDOMAIN reply, or the failure of every Upstream, to the next Plugin; with no next Plugin the NXDOMAIN reply is the answer and a failure is SERVFAIL.
- Each Upstream has one lazily dialled HTTP/2 connection shared by concurrent Queries. A call that fails because a reused connection had closed is sent again once on a new connection (grpc-go retries transparently too). Shutdown closes the connections.
- AD is cleared on every reply (RFC 4035 §4.6, as for `forward`'s encrypted Upstreams); CoreDNS preserves it.
- Building a request and reading its reply allocates in hyper and `http` (header map, URI and message copies), so the warm path is not allocation-free.
- Metrics `pharos_grpc_requests_total{to}`, `pharos_grpc_responses_total{rcode,to}` and `pharos_grpc_request_duration_seconds{to}` replace the `coredns_` series. A call that errors is not counted, as in CoreDNS. The `to` label is the normalized socket address (`127.0.0.1:53`, `[::1]:53`) or `unix://PATH`, where CoreDNS keeps the text as configured. The response counter's help text repeats CoreDNS's ("Counter of requests made per upstream.").
- Differential scenarios are skipped: the CoreDNS reference binary has no gRPC Upstream to compare against without a shared stub, and the behaviour is pinned by the ported setup, policy and proxy tests plus the stub and `grpc_server` Listener tests in `tests/functional/grpc.rs`.
- Tracing spans are not created (the `trace` Plugin is not implemented).

## Sources

- [CoreDNS v1.15.0 `plugin/grpc`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/grpc)
- [CoreDNS v1.15.0 `pb/dns.proto`](https://github.com/coredns/coredns/tree/v1.15.0/pb/dns.proto)
- [gRPC over HTTP/2](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
