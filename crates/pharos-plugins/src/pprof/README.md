# pprof

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/pprof/README.md)

## pprof

- **Security:** pprof is a debugging tool. Everything served on the configured address, including the command line (`cmdline`) and CPU profiles, is unauthenticated. Restrict access to the address, or enable the Plugin only temporarily. The default address, `localhost:6053`, binds the loopback interface only.
- Pharos serves CPU profiles in the pprof protobuf format, so `go tool pprof http://localhost:6053/debug/pprof/profile?seconds=30` works. The profile is sampled at 100 Hz and is not gzip-compressed; `go tool pprof` reads both forms.
- `seconds` is percent-decoded and defaults to 30 when absent, as in Go. Unlike Go, which silently profiles for 30 seconds when `seconds` is unparsable or not positive, Pharos rejects those values with 400 `invalid seconds`, and rejects a value above 300 with 400 `profile duration too long`. The 300-second cap is a Pharos limit; Go has none.
- The Listener keeps each connection open for up to 330 seconds, so a profile of 300 seconds can complete, where other operational Listeners close connections after five seconds. Shutdown and reload still drain for five seconds, so a profile still running then is cut off and the client sees a closed connection.
- Only one CPU profile runs at a time in the process; a concurrent request gets 500 `Could not enable CPU profiling: cpu profiling already in use`.
- Profiling samples with `SIGPROF` through the [pprof-rs](https://github.com/tikv/pprof-rs) crate and builds the report on a blocking thread, so a running profile does not delay the Query path.
- `/debug/pprof/` lists only the endpoints Pharos serves: `profile`, `cmdline` and `symbol`. `/debug/pprof` redirects to it with 302.
- `/debug/pprof/cmdline` returns the process arguments separated by NUL bytes.
- `/debug/pprof/symbol` answers GET with `num_symbols: 0`. Symbolisation by POST is not supported because Pharos profiles already carry symbols; POST returns 405.
- The Go-only profiles `allocs`, `block`, `goroutine`, `heap`, `mutex` and `threadcreate`, and `/debug/pprof/trace`, have no Rust equivalent and return 404 (`Unknown profile`, or an execution-trace notice for `trace`).
- `block [RATE]` is parsed and validated like CoreDNS (`RATE` defaults to 1 and may be any integer, as Go's `strconv.Atoi` accepts), then ignored, because Rust has no block profiler. Pharos logs one line at startup saying so.
- CoreDNS v1.15.0 has no `mutex` property; `mutex` is an `unknown property 'mutex'` error here too.
- Server Blocks that name the same address share one Listener. Pharos reports bind errors, requires numeric ports, caps each HTTP connection at 330 seconds in total and accepts 1,024 connections.
- Only GET and HEAD are allowed; recognized other methods return 405 and unknown methods return 501. CoreDNS serves the pprof handlers for every method.

## Sources

- Derived from CoreDNS v1.15.0 plugin/pprof/setup_test.go.

- [CoreDNS v1.15.0 `plugin/pprof`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/pprof)
