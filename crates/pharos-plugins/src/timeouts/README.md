# timeouts

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/timeouts/README.md)

## timeouts

- TCP timeouts and `maxtcpqueries` apply per Listener; encrypted Listener transports and their README scenarios are deferred to M3.
- Pharos can read pipelined Queries while earlier Queries are executing, but starts the idle deadline only after all in-flight Queries finish; CoreDNS reads the next Query after handling the previous one. Existing connections keep their timeout settings across Reload, while newly accepted connections use the new settings.

## Sources

- [CoreDNS v1.15.0 `core/dnsserver/server.go`](https://github.com/coredns/coredns/tree/v1.15.0/core/dnsserver/server.go)
- [CoreDNS v1.15.0 `plugin/timeouts`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/timeouts)
