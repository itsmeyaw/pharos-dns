# ready

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/ready/README.md)

## ready

- The `ready` endpoint allows GET and HEAD; recognized other methods return 405 and unknown methods return 501. HEAD shares GET status and headers but has no content.
- Responses carry strong body-hash ETags and evaluate `If-Match` and `If-None-Match`. Range requests receive the full representation; byte ranges are not implemented.
- A 503 readiness response says the condition is temporary. CoreDNS accepts other methods instead of returning 405.
- HTTP connections use the same five-second total lifetime and 1,024-connection limit as the metrics endpoint.
- Pharos requires numeric ports at startup and reports bind errors; CoreDNS supports service names and currently discards errors from shared Listener startup.
- Pharos does not log unready Plugin names on every readiness request.
- Readiness state is reset on Reload.
- During Lameduck Pharos keeps `/ready` available with 503 `Shutting down`. CoreDNS v1.15.0 normally closes the readiness Listener before the health Lameduck delay, so subsequent requests fail to connect instead.

## Sources

- Derived from CoreDNS v1.15.0 plugin/ready/setup_test.go.

- [CoreDNS v1.15.0 `plugin/ready`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/ready)
