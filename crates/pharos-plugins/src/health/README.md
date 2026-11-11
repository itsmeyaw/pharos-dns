# health

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/health/README.md)

## health

- Health addresses are shared once per exact configured address, using the first Lameduck duration; CoreDNS creates one Listener and probe per Server Block and can share ports using SO_REUSEPORT.
- Pharos reports bind errors, requires numeric ports, and uses a five-second total HTTP connection lifetime and a 1,024-connection limit.
- Unlike Go's ServeMux, it does not redirect unclean paths or decode escaped path segments, and its 404 responses omit Go's `X-Content-Type-Options` header.
- The self-probe opens a fresh connection for every check and exports classic histogram buckets, not Prometheus native histogram samples.

## Sources

- Derived from CoreDNS v1.15.0 plugin/health/health_test.go.
- Derived from CoreDNS v1.15.0 plugin/health/setup_test.go.

- [CoreDNS v1.15.0 `plugin/health`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/health)
