# cache

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/cache/README.md)

## cache

- Negative Responses use the SOA MINIMUM as well as the record TTLs to bound the cache lifetime, following RFC 2308; CoreDNS's `MinimalTTLWithMaximum` checks only record TTLs.
- Positive cache TTLs use the configured minimum, including zero-TTL responses, for CoreDNS compatibility (ADR 0002; RFC 1035 §3.2.1 deviation); the minimum never overrides RRSIG expiration.
- `denial_min_ttl` is accepted for CoreDNS syntax compatibility but ignored: RFC 2308 §3 does not permit raising a negative TTL above its SOA-derived lifetime.
- NXDOMAIN entries omit QTYPE from their key as RFC 2308 §5 requires; SOA-less NODATA, explicit wildcard QNAMEs, TKEY transactions, and ECS-bearing queries or responses are not cached.
- Negative max TTL is capped at the positive max, and `keepttl` still ages negative TTLs, following RFC 2308 §§5–6.
- Cache entries retain only query-relevant Answer/Authority RRsets; non-OPT Additional records are omitted from hits as a conservative bailiwick policy (RFC 5452 §6).
- Cache hits retain each RRset's own minimum TTL rather than CoreDNS's response-wide minimum (RFC 2181 §5.2).
- Stale responses use a positive 30-second default TTL, following RFC 8767 §4.
- ECS bypass is conservative: even a scope-0 ECS response is not cached, and ECS queries do not use ordinary cached answers; network-prefix scope matching is not implemented (RFC 7871 §7.3).
- Known cache gaps: failures are not keyed by upstream address (RFC 2308 §7.1), full data trust ranking is not implemented (RFC 2181 §5.4.1), and setup A/AAAA lookups do not validate owner names (RFC 5452 §6; `forward` plugin).
- Cache hits may precede authoritative file data because plugin order places cache before file; deployments needing zone-file precedence must avoid overlapping cached names (RFC 2181 §5.4.1).
- AD from upstream is retained for AD/DO clients without a configured secure-channel trust policy (RFC 4035 §4.6).
- NXDOMAIN Responses with CNAME-only Answers are negative Responses under RFC 6604 §3 and use denial caching.
- `test.`, `invalid.`, and RFC 6303 reverse names bypass cache unless a matching `forward` stanza opts into `test.` or reverse lookup. Opted-in upstream answers, including negative answers, use normal cache admission; `invalid.` never forwards (RFC 6761 §§6.1, 6.2, 6.4).
- Without the `local` Plugin, cache does not synthesize localhost loopback or block upstream lookup for `localhost.` (RFC 6761 §6.3; documented Partial).
- The cache hashes the same Query fields with FNV-1a rather than CoreDNS's FNV-1, so shard placement and eviction choices differ.
- Configured Domains must be representable as DNS names; CoreDNS can normalize some malformed `disable` names without validating them.
- Very large TTLs are bounded to the DNS TTL range during use rather than reproducing Go duration overflow.
- Queries with compressed Questions and Responses with compressed or multiple Questions are not cached: removing those encodings could invalidate compression pointers. CoreDNS re-encodes them.
- On a miss, Queries whose encoded names point into the header, or whose non-OPT RDATA might contain a compression pointer, also bypass the cache rather than changing AD.
- Opaque EDNS option data is not treated as name compression.
- On a hit, Pharos rewrites the Question's case in the stored wire Message; record names compressed against it therefore acquire the current Query's case, whereas CoreDNS rebuilds records from the cached Response.
- If a UDP caller's Response buffer is too small for a cached Message, Pharos falls through to Next instead of growing it on the hit.
- TSIG-signed Queries and Responses bypass caching so that ID, flags and TTL rewrites cannot invalidate their signatures.
- SERVFAIL, REFUSED, and internal resolution errors use the `servfail` TTL (default 5 seconds, minimum 1 second); repeated failures back off exponentially to 5 minutes, and expired failures are not served stale (RFC 9520 §3.2). `servfail 0` and sub-second values are raised to one second.
- `disable denial` retains CoreDNS behavior and can leave positive caching enabled, despite RFC 2308 §8.
- Cached DNAME Responses are reusable only for their exact QNAME; descendant synthesis from a cached DNAME is not implemented (RFC 6672 §§3.2, 3.4).
- REFUSED responses are cached as resolution failures per RFC 9520 §§2.2 and 3.2; this differs from the previous CoreDNS-compatible behavior (ADR 0002).
- Known gap: failure entries use QNAME, QTYPE, QCLASS, DO, and CD but omit upstream server address, contrary to RFC 2308 §7.1.
- Wildcard source Metadata is not saved with cache entries.
- Background refreshes use a fresh Metadata map and retain Listener state for Self Lookup.
- A `verify` refresh on a routed Server Block runs as a background task, even without a verify timeout, and concurrent verifies are coalesced.
- Direct use of an unbound Plugin cannot launch a background refresh; its verify mode does not enforce the configured timeout.
- Stale age is evaluated in whole seconds, but fractional configured windows are not truncated as they are in CoreDNS.
- A refresh is not stored if a newer cache entry was installed while it was in flight.
- A hit that launches a background refresh allocates for the task and its Query and Response buffers; ordinary warmed hits do not allocate.
- Cache metric series are initialized at setup, including zero-valued series; CoreDNS initializes individual labelled series on first use.

## Differential scenarios

The `cache` scenario repeats Queries through `forward` to a local `whoami`
Server Block. Its records have TTL 0, which cache raises to the configured
minimum; SRV ports are masked because each forwarded connection uses an
ephemeral port. This exercises miss/hit Responses, not upstream call counts.
No `errors`-specific differential scenario is included: the implemented
Plugins cannot deterministically return the same error in both servers, and
`forward` is not implemented. Error logging and consolidation are tested in Rust.

## Sources

- [CoreDNS v1.15.0 `plugin/cache`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/cache)
- [CoreDNS v1.15.0 `plugin/pkg/cache`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/pkg/cache)
- [CoreDNS v1.15.0 `plugin/pkg/dnsutil`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/pkg/dnsutil)
