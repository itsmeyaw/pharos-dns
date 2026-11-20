# timeouts

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/timeouts/README.md)

## timeouts

- TCP timeouts and `maxtcpqueries` apply per Listener; `tls://` Listeners use the same TCP timeouts and `maxtcpqueries`; `https://` Listeners use `read` for the TLS handshake and request body, `write` as the graceful-close grace period and `idle` for connections with no request in flight (`maxtcpqueries` does not apply); on `quic://` Listeners `read` bounds each stream's Query (a stalled stream is reset, not the connection), `write` bounds each Response and `idle` is the QUIC idle timeout, while `maxtcpqueries` does not apply; `grpc://` and `https3://` Listeners are deferred.
- Pharos can read pipelined Queries while earlier Queries are executing, but starts the idle deadline only after all in-flight Queries finish; CoreDNS reads the next Query after handling the previous one. Existing connections keep their timeout settings across Reload, while newly accepted connections use the new settings.

## Sources

- [CoreDNS v1.15.0 `core/dnsserver/server.go`](https://github.com/coredns/coredns/tree/v1.15.0/core/dnsserver/server.go)
- [CoreDNS v1.15.0 `plugin/timeouts`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/timeouts)
