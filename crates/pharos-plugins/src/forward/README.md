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
- Special names `test.` and RFC 6303 reverse domains return immediate NXDOMAIN without an Upstream by default. Add `allow_special` to a `forward` stanza to permit upstream resolution for those names; `forward` returns NXDOMAIN for `invalid.` (an earlier explicit file Zone still takes precedence).
- Without the `local` Plugin, `forward` may send `localhost.` Queries upstream instead of synthesizing loopback/negative replies (RFC 6761 §6.3; documented Partial).
- Upstream and resolver ports must be numeric and fit in 16 bits; CoreDNS can also accept service names and out-of-range ports at setup.
- Like CoreDNS, IPv6 scopes are stripped from numeric Upstreams, including resolv.conf entries.
- Non-IP nameservers from resolv.conf are retained, but currently fail without health probes rather than being resolved at dial time as in CoreDNS; all-invalid sets fail fast.
- Numeric Upstreams are deduplicated by normalized socket address; CoreDNS preserves textual address spelling and distinct scopes in its keys.
- Some option argument and Domain edge cases remain more restrictive than CoreDNS.
- Upstream Metadata uses the normalized numeric socket address, which may differ from CoreDNS's configured address text.
- Health checks start on exchange failure, and proxy connections and checks are stopped on Shutdown.
- Forward reuses Upstream Response buffers from a pool capped at four idle scratch buffers; excess buffers are dropped on release.
- Per-upstream attempt counters and RRset sort scratch grow to their observed high-water sizes; the ECS fallback buffer grows only when a REFUSED retry needs it. Warm queries within retained pool capacity are allocation-free; bursts above four concurrent buffers can allocate again.

## Standards and compatibility notes

- `max_connect_attempts` is per Upstream and transport. Default is two Queries; configured values clamp silently to 1–3, so zero means one Query. Unsigned ECS Queries reserve one slot for the mandatory REFUSED retry without ECS: even a configured value of three allows only two ECS-bearing Queries, then one no-ECS retry. A failed retry preserves REFUSED for normal failover and `next` handling.
- Mismatched Upstream responses are discarded and retried; if no usable answer arrives, the client receives SERVFAIL, not FORMERR.
- Configured resolver lookups follow CNAMEs up to 16 hops and retry TC responses over TCP.
- Verified TSIG is stripped before forwarding. The forwarder clears AD on the response before it is TSIG-signed for the client.
- ECS response FAMILY, SOURCE and ADDRESS must match when ECS is returned; mismatch discards the response and tries the next upstream. Longer SCOPE is accepted. ECS SCOPE is zeroed in upstream Queries. TSIG-signed Queries are not rewritten and do not get the ECS REFUSED retry, preserving their MAC.
- Mixed-TTL RRsets are normalized to the lowest TTL per RFC 2181 §5.2. Repeated RRsets across sections are relayed unchanged; RFC 2181 §5.5 says they SHOULD NOT be repeated.
- EDNS option 11 is removed from unsigned UDP Queries. On TCP, Query option data is zero-length; a response TIMEOUT of zero closes the connection after that response. TSIG-signed Queries remain byte-identical, so option 11 is not rewritten on that path.
- Health probes require matching ID, QR, opcode, and exactly one echoed Question with matching name/type/class; answer RDATA is not decoded. Dead-server state expires and re-arms after 300 seconds.
- UDP sockets stay pooled and reusable to preserve allocation-free warm forwarding. RFC 5452 §9.2 source-port reuse remains deferred to [issue #109](https://github.com/itsmeyaw/pharos-dns/issues/109); a bounded randomized-port pool needs separate design and measurement.

## Sources

- [CoreDNS v1.15.0 `plugin/forward`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/forward)
