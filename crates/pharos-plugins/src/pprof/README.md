# pprof

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/pprof/README.md)

## pprof

- Pharos serves CPU profiles in the pprof protobuf format, so `go tool pprof http://localhost:6053/debug/pprof/profile?seconds=4` works. The profile is sampled at 100 Hz and is not gzip-compressed; `go tool pprof` reads both forms.
- Like CoreDNS, the server has a five-second write timeout, so `seconds` must be 1 to 4. A missing, unparsable or non-positive `seconds` means Go's default of 30 and is rejected with 400 `profile duration exceeds server's WriteTimeout`. `seconds` is not percent-decoded.
- Only one CPU profile runs at a time in the process; a concurrent request gets 500 `Could not enable CPU profiling: cpu profiling already in use`.
- Profiling samples with `SIGPROF` through the [pprof-rs](https://github.com/tikv/pprof-rs) crate and builds the report on a blocking thread, so a running profile does not delay the Query path.
- `/debug/pprof/` lists only the endpoints Pharos serves: `profile`, `cmdline` and `symbol`. `/debug/pprof` redirects to it with 302.
- `/debug/pprof/cmdline` returns the process arguments separated by NUL bytes.
- `/debug/pprof/symbol` answers GET with `num_symbols: 0`. Symbolisation by POST is not supported because Pharos profiles already carry symbols; POST returns 405.
- The Go-only profiles `allocs`, `block`, `goroutine`, `heap`, `mutex` and `threadcreate`, and `/debug/pprof/trace`, have no Rust equivalent and return 404 (`Unknown profile`, or an execution-trace notice for `trace`).
- `block [RATE]` is parsed and validated like CoreDNS (`RATE` defaults to 1 and may be any integer, as Go's `strconv.Atoi` accepts), then ignored, because Rust has no block profiler. Pharos logs one line at startup saying so.
- CoreDNS v1.15.0 has no `mutex` property; `mutex` is an `unknown property 'mutex'` error here too.
- Server Blocks that name the same address share one Listener. Pharos reports bind errors, requires numeric ports, caps each HTTP connection at five seconds in total and accepts 1,024 connections.
- Only GET and HEAD are allowed; recognized other methods return 405 and unknown methods return 501. CoreDNS serves the pprof handlers for every method.

## Sources

- Derived from CoreDNS v1.15.0 plugin/pprof/setup_test.go.

- [CoreDNS v1.15.0 `plugin/pprof`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/pprof)
