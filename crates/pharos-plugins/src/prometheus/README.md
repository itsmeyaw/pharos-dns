# prometheus

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/metrics/README.md)

## prometheus

- The `prometheus` Directive accepts `runtime_metrics`, but has no effect: Go runtime metrics do not exist in Pharos.
- The `tls` option names an exporter-toolkit v0.20.0 web configuration file: `tls_server_config`, `http_server_config` (`http2`, `headers`) and `basic_auth_users` (bcrypt) are implemented, and an invalid file fails startup before the address is bound.
- Web configuration files that name `rate_limit` with a nonzero `interval`, `client_allowed_sans`, or inline `cert`, `key` and `client_ca` fail startup instead of being ignored; use `cert_file`, `key_file` and `client_ca_file`.
- The web configuration file, certificates and keys are read once at startup; exporter-toolkit also re-reads them for new connections and requests, so changes need a Pharos restart or reload.
- TLS is limited to TLS 1.2 and 1.3 with rustls and aws-lc-rs: a `min_version` of `TLS10` or `TLS11` means TLS 1.2, a `max_version` of `TLS10` or `TLS11` fails startup, and Go's CBC cipher suites and `CurveP521` are skipped with a warning (an empty remainder fails startup).
- Blocks sharing a metrics address must use the same TLS configuration.
- Metrics HTTP connections are capped at five seconds total, rather than CoreDNS's separate per-request read, write and idle deadlines, and at 1,024 simultaneous connections.
- GET and HEAD are served at `/metrics`; recognized other methods return 405 with `Allow: GET, HEAD`, and unknown methods return 501. This replaces the previous 404 behavior.
- Pharos defers `/metrics` SHA-256 ETags to requests with `If-Match` or `If-None-Match` as a performance exception to RFC 9110 §8.8.3.1; 304/412 retain that validator. Range requests receive the full representation; RFC 9110 §14.2 permits ignoring `Range`.
- Pharos requires a numeric metrics port at startup; CoreDNS can also resolve service names supported by the host.
- Bind and startup errors are reported, whereas CoreDNS's shared Listener setup currently discards errors from its `uniq.ForEach` callback.

## Differential scenarios

The Prometheus scenarios compare DNS Responses, not the metrics endpoint.

## Sources

- Derived from CoreDNS v1.15.0 plugin/metrics/setup_test.go.

- [CoreDNS v1.15.0 `plugin/metrics`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/metrics)
