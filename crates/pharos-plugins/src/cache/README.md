# cache

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/cache/README.md)

## cache

- Negative Responses use the SOA MINIMUM as well as the record TTLs to bound the cache lifetime, following RFC 2308; CoreDNS's `MinimalTTLWithMaximum` checks only record TTLs.
- The cache hashes the same Query fields with FNV-1a rather than CoreDNS's FNV-1, so shard placement and eviction choices differ.
- Configured Domains must be representable as DNS names; CoreDNS can normalize some malformed `disable` names without validating them.
- Very large TTLs are bounded to the DNS TTL range during use rather than reproducing Go duration overflow.
- Queries with compressed Questions, and Responses with compressed or multiple Questions or an OPT before other Additional records, are not cached: removing those encodings could invalidate compression pointers. CoreDNS re-encodes them.
- On a miss, Queries whose encoded names point into the header, or whose non-OPT RDATA might contain a compression pointer, also bypass the cache rather than changing AD.
- Opaque EDNS option data is not treated as name compression.
- On a hit, Pharos rewrites the Question's case in the stored wire Message; record names compressed against it therefore acquire the current Query's case, whereas CoreDNS rebuilds records from the cached Response.
- If a UDP caller's Response buffer is too small for a cached Message, Pharos falls through to Next instead of growing it on the hit.
- TSIG-signed Queries and Responses bypass caching so that ID, flags and TTL rewrites cannot invalidate their signatures.
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
