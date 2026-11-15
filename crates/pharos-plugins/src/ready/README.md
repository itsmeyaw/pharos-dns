# ready

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/ready/README.md)

## ready

- The `ready` endpoint allows GET and HEAD; recognized other methods return 405 and unknown methods return 501. HEAD shares GET status and headers but has no content.
- `/ready` 200 responses carry SHA-256 strong ETags; 304/412 retain that validator. Ordinary errors omit ETags. Range requests receive the full representation; RFC 9110 §14.2 permits ignoring `Range`.
- A 503 readiness response says the condition is temporary, prefixing its detail with `Service temporarily unavailable:`. CoreDNS accepts other methods instead of returning 405.
- HTTP connections use the same five-second total lifetime and 1,024-connection limit as the metrics endpoint.
- Pharos requires numeric ports at startup and reports bind errors; CoreDNS supports service names and currently discards errors from shared Listener startup.
- Pharos does not log unready Plugin names on every readiness request.
- Readiness state is reset on Reload.
- During Lameduck Pharos keeps `/ready` available with 503 `Service temporarily unavailable: Shutting down`. CoreDNS v1.15.0 normally closes the readiness Listener before the health Lameduck delay, so subsequent requests fail to connect instead.

## Sources

- Derived from CoreDNS v1.15.0 plugin/ready/setup_test.go.

- [CoreDNS v1.15.0 `plugin/ready`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/ready)
