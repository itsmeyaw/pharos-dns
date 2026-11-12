# k8s_external

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/k8s_external/README.md)

## k8s_external

- LoadBalancer hostname Self Lookups allocate per Query until #86 pools their buffers and futures.
- DNS Listeners bind before Startup hooks, so an occupied port can mask the missing-Kubernetes error; CoreDNS runs Startup before binding.
- Per-thread Query scratch grows on first use or when larger Services are queried; warmed Queries reuse it without allocating.
- Zone Transfers encode the entire Zone under the Kubernetes store read lock before sending. Memory and worker time grow with Zone size; CoreDNS streams batches.
- Zone Transfers allocate one encoded snapshot, one shared Stream producer, and one reusable deduplication table, not per record. macOS also allocates the producer's mutex on first use.
- UDP IXFR returns the current SOA instead of CoreDNS's REFUSED, following RFC 1995 §2.

## Sources

- [CoreDNS v1.15.0 `plugin/k8s_external`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/k8s_external)
- [CoreDNS v1.15.0 `plugin/kubernetes/external.go`](https://github.com/coredns/coredns/blob/v1.15.0/plugin/kubernetes/external.go)
