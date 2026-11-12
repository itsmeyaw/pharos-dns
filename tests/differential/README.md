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
  `+bufsize=N`, `+nsid`, `+ednsoption=CODE:HEX`, `+norec`, `+ednsversion=N`, `+opcode=NAME` or a number,
  and `+tsig=NAME:BASE64[:badkey|badsig|badtime]` (HMAC-SHA256).
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

The `tsig` transfer README example is skipped until the `transfer` Plugin is
available. Signed scenarios authenticate each Response before comparing its
other fields; TSIG timestamps and MAC bytes are not compared between servers.
The `tsig-forward` README example replaces its unreachable external Upstream
with a local deterministic fixture.

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
