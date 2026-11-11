# Differential scenarios

Run `cargo xtask coredns` once with Go installed, then `cargo xtask diff`.
`cargo xtask check` runs the scenarios when that binary is cached. The cache
is `target/coredns/v1.15.0/coredns`. `cargo xtask diff --self-test` deliberately
changes a Response and must fail with a diagnostic.

Each scenario is a directory containing:

- `Corefile`: the same configuration for both processes; `{port}` is replaced
  by the chosen Listener port, `{port2}` by a second DNS Listener port, and
  `{metrics_port}` by a distinct free port for each process. `{loopback}` is
  `lo0` on macOS and `lo` elsewhere. Omit it to exercise each built-in default in an empty working
  directory.
- `{kubeconfig}` starts one standalone Rust fixture API for the scenario and
  substitutes the same absolute kubeconfig path for both processes. The harness
  waits for each process's `ready` endpoint and for an answer to
  `web.default.svc.cluster.local. A` with the fixture's ClusterIP before
  comparing Queries. Scenarios use `{metrics_port}` for the readiness endpoint.
  The API and DNS Listeners use the same non-ephemeral port reservation helper.
- `queries`: one Query per line, `name type class udp|tcp [flags...]`.
  Names are absolute; comments begin with `#`. Supported flags are `+dnssec`,
  `+bufsize=N`, `+nsid`, `+ednsoption=CODE:HEX`, `+norec`, `+ednsversion=N`, and `+opcode=NAME` or a number.
- `expect` (optional): one setting per line. `ttl N` permits a TTL difference
  of N seconds for ordinary records; default is zero. `mask
  additional.srv.port` ignores only the SRV port in Additional (whoami reports
  each client's ephemeral port). `deviation Heading` records an expected
  operational difference and must refer to an existing level-two heading in
  `docs/compatibility.md`. For a documented header difference only,
  `deviation Heading | exact Query line | flags=0xPHAROS:0xCOREDNS` allows
  that exact pair of flag values on that Query; other fields remain checked.
  `mask soa.serial` ignores only the SOA serial, for scenarios that explicitly
  opt in; Kubernetes SOA serials can depend on each process's startup time.
- Any other files or subdirectories are copied into separate temporary working
  directories for both processes, preserving relative paths.

IDs and RR order within each section are ignored; all other fields are compared.

The `kubernetes-*` scenarios exercise the small, read-only API fixture in
`crates/pharos-kubernetes/examples/differential.rs`, sharing the HTTP server
with the memory example. It serves static Services, EndpointSlices, Pods and
Namespaces; list and watch apply label and field selectors. Watches do not
produce mutations. The fixture accepts equality, inequality, set and existence
label selectors, and field selectors for name, namespace, pod phase, pod IP and
node name; unsupported field selectors return an error. Run its tests with
`cargo test -p pharos-kubernetes --example differential`, and run the full
comparisons with `cargo xtask coredns` followed by `cargo xtask diff` after the
Kubernetes Plugin is available. The zonal scenario also requires zonal Plugin
and store support.

The loadbalance scenarios compare a multi-address `hosts` Response with
round-robin and subnet preference, and a single-address weighted Response.
They do not compare randomized order or weight distributions.
The `whoami-log` scenario compares Responses, not log output. The current whoami
Responses cannot exceed the 512-octet UDP minimum for these short Queries, so
truncation is not covered.
The `bufsize` README scenarios use a local `whoami` Upstream instead of the
example's external resolver, and `hosts` instead of the unimplemented `file`
backend. They compare Responses for both UDP and TCP, with and without EDNS.
The two `chaos` README scenarios configure the same explicit identity on both
servers; default identity differences are covered by Rust tests instead.
The `local` README and prefix-off scenarios use `whoami` as Next to compare
both intercepted Queries and those passed through.
The three `header` README scenarios use `whoami` as the Backend and compare
Responses over UDP and TCP; Rust tests also inspect forwarded Queries.
The metadata scenarios compare DNS Responses with inherited and explicit Domains.
The Metadata README mentions `rewrite` without a concrete Corefile; those scenarios
use Kubernetes and whoami instead. Metadata values and log formatting are checked
by Rust tests, not the differential harness.
The `loop` scenario compares Responses for a non-looping configuration. The
looping README example is covered by a binary exit test instead: this harness
expects both processes to remain available and does not compare exit codes.
The acl README scenarios use whoami as Next. The harness originates Queries
from loopback, so non-loopback allow and drop branches require Rust tests.
The dns64 README scenarios use an inline hosts Backend. The harness sends from
IPv4 loopback, so synthesis without `allow_ipv4` is covered by Rust tests.
The siit README scenario uses an inline hosts Backend to exercise the prefix.
The `rewrite` name, PTR and TTL scenarios use inline hosts records. The CNAME
scenario combines the Kubernetes ExternalName fixture with hosts; RCODE uses a
missing hosts record. The type and EDNS scenarios use whoami and mask its client
port. The EDNS variable scenario covers QNAME, QTYPE, client IP and protocol.
The NSID and subnet scenarios compare client Responses; Rust tests also inspect
the rewritten Query because whoami does not echo those options.
The `{server_port}` and `{client_port}` examples are covered by Rust tests: the
processes use different ports. The metadata name example is also covered by Rust
tests because the Kubernetes fixture has no Pod with the harness's loopback IP.
The documented imaginary `some-plugin` metadata example cannot run because that
Plugin does not exist.
The `rewrite edns0` example without an EDNS Query is not compared: CoreDNS
returns OPT while Pharos omits it under RFC 6891 §7, and the harness cannot mask
additional records. A Rust integration test covers this deviation.
The Prometheus scenarios compare DNS Responses, not the metrics endpoint.
The bind scenario compares Responses on 127.0.0.1 with an excluded IPv6 address;
the harness cannot send Queries to another bind address or scrape metrics.
The Reload README scenarios use `whoami` instead of the unimplemented `erratic`
backend and compare DNS Responses rather than reload timing.

The `cache` scenario repeats Queries through `forward` to a local `whoami`
Server Block. Its records have TTL 0, which cache raises to the configured
minimum; SRV ports are masked because each forwarded connection uses an
ephemeral port. This exercises miss/hit Responses, not upstream call counts.
No `errors`-specific differential scenario is included: the implemented
Plugins cannot deterministically return the same error in both servers, and
`forward` is not implemented. Error logging and consolidation are tested in Rust.
