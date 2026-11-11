# prometheus

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/metrics/README.md)

## prometheus

- The `prometheus` Directive accepts `runtime_metrics`, but has no effect: Go runtime metrics do not exist in Pharos.
- The `tls` option is parsed, but any TLS configuration fails startup rather than silently serving unprotected HTTP; Prometheus exporter-toolkit TLS and authentication are not implemented.
- Blocks sharing a metrics address must use the same TLS configuration.
- Metrics HTTP connections are capped at five seconds total, rather than CoreDNS's separate per-request read, write and idle deadlines, and at 1,024 simultaneous connections.
- Only GET requests are served at `/metrics`; other HTTP methods return 404.
- Pharos requires a numeric metrics port at startup; CoreDNS can also resolve service names supported by the host.
- Bind and startup errors are reported, whereas CoreDNS's shared Listener setup currently discards errors from its `uniq.ForEach` callback.

## Differential scenarios

The Prometheus scenarios compare DNS Responses, not the metrics endpoint.

## Sources

- Derived from CoreDNS v1.15.0 plugin/metrics/setup_test.go.
