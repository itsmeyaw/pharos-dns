# errors

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/errors/README.md)

## errors

- The `errors` Plugin uses Rust's `regex` syntax rather than Go's RE2 syntax. For example, `\w`, `\d`, `\s` and word boundaries are Unicode-aware in Rust but ASCII-only in Go; some expressions are accepted by only one engine.
- Rust's regex compiler also imposes its own compiled-size limit.
- The Plugin contract represents an error as SERVFAIL without an independent RCODE, so error logs always report `2`.
- Rust panic traces and Pharos's text/JSON logging format differ from CoreDNS's Go stack and log format.
- Pharos selects `stacktrace` per routed Server Block; CoreDNS's last Server Block setting applies to the whole Listener.
- Replacing Rust's process-wide panic hook after Listener setup disables Pharos's stacktrace capture.

## Sources

- Derived from CoreDNS v1.15.0 plugin/errors/errors_test.go.
- Derived from CoreDNS v1.15.0 plugin/errors/setup_test.go.
