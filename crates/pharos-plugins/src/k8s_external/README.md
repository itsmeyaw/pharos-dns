# k8s_external

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/k8s_external/README.md)

## k8s_external

- LoadBalancer hostname Self Lookups use pooled buffers and futures (#86) but still allocate per Query: the result is copied out of the pool and the hostname Name is copied.
- Per-thread Query scratch grows on first use or when larger Services are queried; warmed Queries reuse it without allocating.
- EndpointSlice updates copy a Service's slice-index vector while an in-flight Query retains its snapshot.
- Zone Transfers encode the entire Zone under the Kubernetes store read lock before sending. Memory and worker time grow with Zone size; CoreDNS streams batches.
- Zone Transfers allocate one encoded snapshot, one shared Stream producer, and one reusable deduplication table, not per record. macOS also allocates the producer's mutex on first use.
- UDP IXFR returns the current SOA instead of CoreDNS's REFUSED, following RFC 1995 §2.
- SRV queries and AXFR require named ports. Query responses also require address-resolving, non-CNAME targets; missing target addresses suppress the SRV RR (RFC 2782).
- AXFR emits SRV records for hostname targets without resolving their address records; transfer generation is synchronous.
- A/AAAA alias queries keep their CNAME; the target lookup sets the final RCODE, and negative answers carry target Authority records (RFC 1034 §4.3.2, RFC 6604 §3, RFC 2308 §3).
- AXFR omits unavailable IPv6 address RRs and deduplicates repeated address and SRV records.

## Sources

- [CoreDNS v1.15.0 `plugin/k8s_external`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/k8s_external)
- [CoreDNS v1.15.0 `plugin/kubernetes/external.go`](https://github.com/coredns/coredns/blob/v1.15.0/plugin/kubernetes/external.go)
