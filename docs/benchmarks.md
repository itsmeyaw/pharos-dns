# Benchmarks

Run `cargo xtask bench` to measure the workspace's Criterion micro-benchmarks,
then run a 10-second UDP dnsperf macro-benchmark. Install dnsperf 2.16 with
`brew install dnsperf` (macOS) or `apt install dnsperf` (Debian/Ubuntu). If it
is missing, the micro-benchmarks still run and the macro-benchmark is skipped.
`cargo xtask check` compiles benches with Clippy but does not run them.

The macro-benchmark builds Pharos in release mode and starts it with a
`whoami` Plugin. It also runs CoreDNS v1.15.0 if cached by `cargo xtask coredns`
and Hickory DNS 0.26.3 if cached by `cargo xtask hickory`; both are informational.
CoreDNS receives the same Corefile and Query list. Hickory has no `whoami`, so it
answers the same Queries from small authoritative zones generated under
`target/bench/hickory/`, and ignores `--corefile`.
Use `cargo xtask bench --corefile path/to/Corefile` to override the default.
Use `{port}` in explicit Listener ports so each server gets a free port; relative
paths inside the Corefile are resolved from the Corefile's directory.
The harness temporarily writes a private Corefile copy in that directory,
so it must be writable.

The table reports completed Queries per second, p50 and p99 latency in ms, and
peak process RSS in KiB. Latencies are nearest-rank estimates using the upper
bound of dnsperf's histogram buckets (approximately 3% resolution); they exclude
lost Queries. RSS is sampled every 100 ms and can miss shorter peaks. dnsperf
output, the Query list and server logs are retained under `target/bench/`;
inspect the output for Query loss. The installed dnsperf must support
`-O latency-histogram`.

dnsperf runs with 16 clients (source ports), 4 threads and 256 Queries in
flight. On macOS, `SO_REUSEPORT` sends every Datagram on a port to a single
socket, so one Pharos worker serves the whole UDP load and UDP QPS stops at what
one worker can do (about 50k QPS on an M-series laptop, about the same as
CoreDNS). On Linux the kernel spreads Queries across sockets by source port.
Compare UDP throughput on Linux.

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

## Kubernetes cache memory

The synthetic API and measured client run in separate processes. The API serves
10,000 Services, 10,000 EndpointSlices with three endpoints each, and one
Namespace. It logs every request, including unsupported paths, to stderr. It
supports ordinary lists/watches, streaming initial events, and discovery/version
requests. Its temporary kubeconfig is removed on an orderly SIGINT shutdown;
an abrupt exit can leave it behind.

```sh
cargo build --release -p pharos-kubernetes --example memory
work=$(mktemp -d "${TMPDIR:-/tmp}/pharos-kubernetes-memory.XXXXXX")
TMPDIR="$work" target/release/examples/memory serve 127.0.0.1:0 >"$work/api.log" 2>&1 &
api_pid=$!
cleanup() {
    kill -CONT "$api_pid" 2>/dev/null || true
    [ -z "${coredns_pid:-}" ] || kill "$coredns_pid" 2>/dev/null || true
    kill -INT "$api_pid" 2>/dev/null || true
    wait "$api_pid" "${coredns_pid:-$api_pid}" 2>/dev/null || true
    rm -r "$work"
}
trap cleanup EXIT
for i in $(seq 1 100); do grep -q '^KUBECONFIG=' "$work/api.log" && break; sleep 0.1; done
API_URL=$(sed -n 's/^API_URL=//p' "$work/api.log" | head -1)
KUBECONFIG=$(sed -n 's/^KUBECONFIG=//p' "$work/api.log" | head -1)
test -n "$API_URL" && test -f "$KUBECONFIG"

cargo run --release -p pharos-kubernetes --example memory -- client "$API_URL"
```

The client reports current process RSS and live Rust-global-allocator bytes
before and after sync, plus Store counts. Live heap is allocated minus freed
bytes, including reallocation changes already counted in those totals. The
delta includes watcher, client and runtime allocations as well as the Store;
it is not an exact Store-only measurement. The client waits 500 ms after sync
to let transient list buffers drop. RSS can retain freed allocator pages; it is
not a live-heap measurement. C-library allocations are not counted by the Rust
global allocator. The API server's allocations are not included in either
measurement.

The server can also be run with
`cargo run --release -p pharos-kubernetes --example memory -- serve [ADDR]`;
omit `[ADDR]` to bind an ephemeral loopback port.

To compare the cached CoreDNS v1.15.0 against the same API, use unused local
ports in the following Corefile. Stop the API temporarily to measure CoreDNS
before sync, then resume it and wait for Readiness and DNS to confirm sync:

```sh
cat >"$work/Corefile" <<EOF
.:15353 {
    bind 127.0.0.1
    errors
    ready 127.0.0.1:18181
    kubernetes cluster.local {
        kubeconfig $KUBECONFIG
        startup_timeout 30s
    }
}
EOF
kill -STOP "$api_pid"
target/coredns/v1.15.0/coredns -conf "$work/Corefile" >"$work/coredns.log" 2>&1 &
coredns_pid=$!
for i in $(seq 1 100); do grep -q 'waiting for Kubernetes API before starting server' "$work/coredns.log" && break; sleep 0.1; done
grep -q 'waiting for Kubernetes API before starting server' "$work/coredns.log"
ps -o rss= -p "$coredns_pid"  # before sync, KiB
kill -CONT "$api_pid"
for i in $(seq 1 200); do curl -fsS --max-time 1 http://127.0.0.1:18181/ready >/dev/null && break; sleep 0.1; done
curl -fsS http://127.0.0.1:18181/ready
for i in $(seq 1 100); do
    answer=$(dig +tcp +time=1 +tries=1 @127.0.0.1 -p 15353 svc1.bench.svc.cluster.local A +short 2>/dev/null)
    [ "$answer" = 10.0.0.1 ] && break
    sleep 0.1
done
test "$answer" = 10.0.0.1
dig +tcp @127.0.0.1 -p 15353 192-0-0-3.svc1.bench.svc.cluster.local A +short
sleep 0.5
ps -o rss= -p "$coredns_pid"  # after sync, KiB
cat "$work/api.log"           # inspect all requested paths
cleanup
trap - EXIT
```

On Linux the example reads `/proc/self/status`; on macOS it uses `ps`. Run the
Linux comparison remotely. Process RSS includes the runtime and allocator
overhead and the numbers are informational, not hard limits. CoreDNS is a full
DNS process; the Pharos example measures only its Kubernetes client and Store,
not a Pharos DNS Listener, so their RSS values have different scopes.
