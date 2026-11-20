# forward

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/forward/README.md)

## forward

- Plain UDP and TCP Upstream exchange is available for `forward`.
- DNS-over-TLS Upstreams (`tls://HOST[:853]`) share the `pharos_server::tls` client configuration with the `tls` Plugin. The dial timeout bounds the TCP dial plus the TLS handshake, health checks probe over TLS, and idle connections follow `expire` and `max_idle_conns` under the `tcp-tls` metrics label.
- DNS-over-QUIC Upstreams (`quic://HOST[:853]`, RFC 9250) take the same `tls` and `tls_servername` options and `IP%NAME` zone as `tls://`, negotiate ALPN `doq` over TLS 1.3, and share one QUIC connection per Upstream with one stream per Query (Message ID zero upstream, the client's ID restored). The connection is replaced when it closes, idles past `expire` or outlives `max_age`; abandoned Queries reset only their own stream (`DOQ_REQUEST_CANCELLED`) and a protocol error closes the connection (`DOQ_PROTOCOL_ERROR`). `edns-tcp-keepalive` is stripped and AXFR/IXFR are refused. Connection reuse counts under the `quic` metrics label and health checks probe over DoQ. `max_idle_conns` does not apply because there is one connection, and the QUIC idle timeout is the larger of 30s, `expire` and `read_timeout`. Deferred and, as in CoreDNS, not done: EDNS padding of Queries (RFC 9250 §5.4), rejecting port 53 (RFC 9250 §4.1.1), and keeping a TSIG-signed Query valid after its ID becomes zero.
- `force_tcp` and `prefer_udp` do not affect `tls://`, `quic://` or `https://` Upstreams; as in CoreDNS they always use their own transport. Health checks over TLS ignore `force_tcp`.
- DNS-over-HTTPS Upstreams (`https://HOST[:443]`) use hyper over one multiplexed HTTP/2 connection (ALPN `h2`, falling back to persistent HTTP/1.1), the same TLS client configuration and `tls`/`tls_servername`/`%NAME` rules as `tls://`, and the shared `pharos_server::doh` rules (RFC 8484 §4.1). Queries are sent with Message ID 0 and the original ID is restored; signed (TSIG) Queries are sent unchanged. Connections follow `expire`, `max_age` and `max_idle_conns` (HTTP/1.1 only) under the `https` metrics label. `force_tcp` and `prefer_udp` do not affect them.
- `doh_method GET|POST` (default POST) picks the Query encoding; health checks always POST. The request path is always `/dns-query`: `https://HOST/path` fails setup. An `https://IP%NAME` zone sets the TLS server name as for `tls://`; CoreDNS ignores the zone of an HTTPS Upstream. The HTTP `Host` and TLS server name are `tls_servername`/`%NAME` when given, else the Upstream's IP address.
- Unlike CoreDNS, which accepts any HTTP status, a non-2xx status from a DoH Upstream is a failed exchange (RFC 8484 §4.2.1), so it counts toward `max_fails` and the next Upstream is tried.
- A warm DoH exchange allocates nothing in Pharos: request bodies and GET targets are built in pooled buffers. hyper and `http` still allocate per request (header map and, for GET, the target `Uri`), so the DoH path is not allocation-free like UDP and TCP; `proxy_https_allocations` shows it costs the same as a bare hyper client.
- The proxy retries a truncated UDP Response over TCP only when `prefer_udp` is set, as CoreDNS's `forward` does.
- Idle sockets are swept across shards at most once per expiry interval on Query traffic. Unlike CoreDNS’s periodic cleanup, an idle Proxy retains expired sockets until another Query or shutdown.
- Upstream TSIG Messages retain their original ID rather than rewriting the signed Message.
- Proxy metric RCODE series are initialized on first observation, allocating once per distinct RCODE.
- Connections rotate FIFO within each worker shard rather than in one global FIFO.
- `grpc://` and `unix://` Upstreams fail setup rather than silently downgrade; only `tls://`, `quic://` and `https://` are encrypted.
- `tls` takes `CA`, `CERT KEY` or `CERT KEY CA`; relative paths join `root`. Without arguments the system roots verify the server. A `tls://IP%NAME`, `quic://IP%NAME` or `https://IP%NAME` zone and `tls_servername` are mutually exclusive for one Upstream, and the name defaults to the Upstream's IP address.
- TLS names are lowercased, so `tls://IP%Name` and `tls://IP%name` (likewise `quic://` and `https://`) are one Upstream. CoreDNS keeps the case.
- Hostname Upstreams resolve at setup using the system resolver or the configured `resolver`.
- `doh_method` has no effect on plain DNS or `tls://` Upstreams.
- Special names `test.` and RFC 6303 reverse domains defer to the Chain's terminal NXDOMAIN unless a matching stanza opts into upstream lookup with `allow_special` or an explicit special-use `from` Zone. `invalid.` always gets terminal NXDOMAIN; explicit `forward .invalid` setup is rejected (RFC 6761 §§6.1, 6.2, 6.4).
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
- AD is cleared by default on unsigned Responses over plain UDP/TCP and TLS, QUIC and HTTPS Upstreams (RFC 4035 §4.6). This differs from CoreDNS, which preserves upstream AD; the trust-policy decision is tracked in [issue #110](https://github.com/itsmeyaw/pharos-dns/issues/110). TSIG Responses stay unchanged so their MAC remains valid.
- ECS response FAMILY, SOURCE and ADDRESS must match when ECS is returned; mismatch discards the response and tries the next upstream. Longer SCOPE is accepted. ECS SCOPE is zeroed in upstream Queries. TSIG-signed Queries are not rewritten and do not get the ECS REFUSED retry, preserving their MAC.
- Mixed-TTL RRsets are normalized to the lowest TTL per RFC 2181 §5.2. Repeated RRsets across sections are relayed unchanged; RFC 2181 §5.5 says they SHOULD NOT be repeated.
- EDNS option 11 is removed from unsigned UDP Queries. On TCP, Query option data is zero-length; a response TIMEOUT of zero closes the connection after that response. TSIG-signed Queries remain byte-identical, so option 11 is not rewritten on that path.
- Health probes require matching ID, QR, opcode, and exactly one echoed Question with matching name/type/class; answer RDATA is not decoded. Dead-server state expires and re-arms after 300 seconds.
- UDP sockets stay pooled and reusable to preserve allocation-free warm forwarding. RFC 5452 §9.2 source-port reuse remains deferred to [issue #109](https://github.com/itsmeyaw/pharos-dns/issues/109); a bounded randomized-port pool needs separate design and measurement.

## Sources

- [CoreDNS v1.15.0 `plugin/forward`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/forward)
