# k8s_external

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/k8s_external/README.md)

## k8s_external

- A missing Kubernetes Plugin is rejected while preparing Servers; CoreDNS rejects it during Startup.
- LoadBalancer hostname Self Lookups allocate per Query until #86 pools their buffers and futures.
- Duplicate suppression scans matching records repeatedly, so Query and headless transfer CPU time can grow quadratically with Service size.
- Zone Transfers encode the entire Zone under the Kubernetes store read lock before sending. Memory and worker time grow with Zone size; CoreDNS streams batches.
- UDP IXFR returns the current SOA instead of CoreDNS's REFUSED, following RFC 1995 §2.

## Sources

- [CoreDNS v1.15.0 `plugin/k8s_external`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/k8s_external)
- [CoreDNS v1.15.0 `plugin/kubernetes/external.go`](https://github.com/coredns/coredns/blob/v1.15.0/plugin/kubernetes/external.go)
