# forward

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/forward/README.md)

## forward

- Plain UDP and TCP Upstream exchange is available for `forward`.
- DNS-over-TLS is reserved for M3.
- The proxy retries a truncated UDP Response over TCP only when `prefer_udp` is set, as CoreDNS's `forward` does.
- Idle sockets are swept across shards at most once per expiry interval on Query traffic. Unlike CoreDNS’s periodic cleanup, an idle Proxy retains expired sockets until another Query or shutdown.
- Upstream TSIG Messages retain their original ID rather than rewriting the signed Message.
- Proxy metric RCODE series are initialized on first observation, allocating once per distinct RCODE.
- Connections rotate FIFO within each worker shard rather than in one global FIFO.
- Encrypted Upstreams (`tls://`, `quic://` and `https://`) and `tls` or `tls_servername` options fail setup rather than silently downgrade; TLS is deferred to M3.
- Hostname Upstreams resolve at setup using the system resolver or the configured `resolver`.
- `doh_method` has no effect on plain DNS.
- Upstream and resolver ports must be numeric and fit in 16 bits; CoreDNS can also accept service names and out-of-range ports at setup.
- Like CoreDNS, IPv6 scopes are stripped from numeric Upstreams, including resolv.conf entries.
- Non-IP nameservers from resolv.conf are retained, but currently fail without health probes rather than being resolved at dial time as in CoreDNS; retries of such entries pause for 1 ms to avoid a busy loop.
- Numeric Upstreams are deduplicated by normalized socket address; CoreDNS preserves textual address spelling and distinct scopes in its keys.
- Some option argument and Domain edge cases remain more restrictive than CoreDNS.
- Upstream Metadata uses the normalized numeric socket address, which may differ from CoreDNS's configured address text.
- Health checks start on exchange failure, and proxy connections and checks are stopped on Shutdown.
- Forward reuses Upstream Response buffers from a pool; a new buffer is allocated when concurrent Queries exceed the pool's previous high-water mark, and the pool retains that peak allocation until the Plugin is dropped.
