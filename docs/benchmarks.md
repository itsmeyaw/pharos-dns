# Benchmarks

Run `cargo xtask bench` to measure the workspace's Criterion micro-benchmarks,
then run a 10-second UDP dnsperf macro-benchmark. Install dnsperf 2.16 with
`brew install dnsperf` (macOS) or `apt install dnsperf` (Debian/Ubuntu). If it
is missing, the micro-benchmarks still run and the macro-benchmark is skipped.
`cargo xtask check` compiles benches with Clippy but does not run them.

The macro-benchmark builds Pharos in release mode and starts it with a
`whoami` Plugin. It also runs CoreDNS v1.15.0 if cached by `cargo xtask coredns`;
CoreDNS is informational. Both receive the same Corefile and Query list.
Use `cargo xtask bench --corefile path/to/Corefile` to override the default.
Use `{port}` in explicit Listener ports so each server gets a free port; relative
paths inside the Corefile are resolved from the Corefile's directory.

The table reports completed Queries per second, p50 and p99 latency in ms, and
peak process RSS in KiB. Latencies are nearest-rank estimates using the upper
bound of dnsperf's histogram buckets (approximately 3% resolution); they exclude
lost Queries. RSS is sampled every 100 ms and can miss shorter peaks. dnsperf
output, the Query list and server logs are retained under `target/bench/`;
inspect the output for Query loss. The installed dnsperf must support
`-O latency-histogram`.

Save a baseline on the reference revision and compare on the branch:

```sh
cargo xtask bench --save-baseline main
cargo xtask bench --baseline main
```

The macro baseline is stored at `$(git rev-parse --git-common-dir)/pharos-bench/main`;
Criterion data is shared at `$(git rev-parse --git-common-dir)/pharos-criterion`,
so both work across worktrees. New micro-benchmarks missing from the reference
baseline must be benchmarked on that reference before comparison. The command
prints `REGRESSION` and fails if Pharos QPS falls or p99/RSS rises by more than
5%; exactly 5% is not a regression. Baseline names use letters, digits, `_`
and `-`. If dnsperf is missing, no macro baseline is saved or compared.

Numbers are informational, not hard performance targets. Compare on the same
machine under similar load; measurement noise, histogram resolution and Query
loss can all affect results.
