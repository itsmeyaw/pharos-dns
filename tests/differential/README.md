# Differential scenarios

Run `cargo xtask coredns` once with Go installed, then `cargo xtask diff`.
`cargo xtask check` runs the scenarios when that binary is cached. The cache
is `target/coredns/v1.15.0/coredns`. `cargo xtask diff --self-test` deliberately
changes a Response and succeeds only when it detects that injected mismatch.

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
  `+ixfr=SERIAL` for an IXFR SOA in Authority,
  `+add=OWNER:TYPE:TTL:HEX` for an UPDATE-section addition with wire-format RDATA,
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
   `mask rrsig` ignores only the RRSIG Original TTL, signature contents and
   inception/expiration timestamps; signature validity duration, signature length,
   all other fields and record counts are compared.
   `mask rrsig.random-validity` also permits independent validity durations,
   as required by the randomized offline `sign` Plugin.
   `rcode REFUSED | exact Query line` or `rcode NOERROR | exact Query line`
   additionally checks that both servers return the specified RCODE.
   `answer 192.0.2.1 | exact Query line` additionally requires that address in
   each Answer section.
- Any other files or subdirectories are copied into separate temporary working
  directories for both processes, preserving relative paths.
- `wait-zone` (optional): a Query whose positive answer indicates that an
  asynchronously transferred secondary Zone is ready for comparisons.
- `PrimaryCorefile` (optional): run each primary in a separate process, then
  repeat with the Pharos and CoreDNS primaries exchanged. `{port2}` is the
  primary Listener and `{port}` is its secondary Listener.
- `next-zone` and `next-wait` (optional): replace each primary's `db.zone`
  with the new Zone, wait for the given positive Query on both secondaries,
  and repeat all comparisons. The fixture must use a longer SOA refresh than
  the test timeout so the new answer demonstrates NOTIFY-driven transfer.
- `verify-dnssec` (optional): name a fixture DNSKEY file. For every `+dnssec`
  Query, verify each Answer and Authority RRSIG from both implementations and
  reject unsigned RRsets or signatures outside their validity interval.

IDs and RR order within each section are ignored; all other fields are compared.
TCP AXFR comparisons collect the complete stream through its closing SOA before
comparing records, independent of Message boundaries. Signed streams are
authenticated in full, including the closing Message, before comparison. The
combined records must fit into one 65,535-octet comparison Message.

The two `dynupdate` README examples use the documented seed and public test key.
They compare a signed UPDATE followed by a Query; the in-memory case also
exercises cache bypass after a Negative Response.

The `file` README scenarios omit the example's remote NOTIFY destination so
the tests do not send traffic outside the local fixture.
`file-root-readme` uses a fixture-relative root instead of `/etc/coredns/zones`.
The intentionally invalid root-Server-Block example cannot produce DNS
Responses because its SOA owner does not match the configured root Zone; the
`coredns_readme_root_without_zone_is_invalid` test checks startup rejection.

The `secondary` README scenarios replace the documented remote Primaries with
local `file` and `transfer` fixtures. `wait-zone` waits for the asynchronous
transfer, including the catalog member transfer, before comparing Responses.
`secondary-fallback-readme` uses unreachable port zero for the first Primary,
then transfers from the second Primary.
`transfer-notify-pair` compares both implementations and mixed primary/secondary
pairs before and after a serial change. CoreDNS secondary AXFR requests and
transfer NOTIFY messages are unsigned, so these pairs are unsigned for parity.
`tsig-transfer-readme` separately covers signed and unsigned AXFR clients.

The `sign-readme` scenario uses local test keys and a one-second file reload
to wait for offline signing. It serves the signed Zone through `file` and
`dnssec`, compares Responses and validates both servers' RRSIGs. The two README examples using `key directory` are
skipped because CoreDNS itself rejects that unimplemented option. The final
example documents a configuration pitfall rather than a stable response.

The `auto` README scenarios use fixture-relative directories instead of
`/etc/coredns/zones/org`. `auto-transfer-readme` omits the remote NOTIFY
destination; `auto-regexp-readme` includes an unmatched file to exercise the
documented filename pattern.
The differential harness compares DNS Responses, not scraped metrics; dynamic
`auto` Zone labels are covered by functional and allocation tests.

The `template-invalid` README scenario uses EDNS Queries when testing `ederror`:
the Listener intentionally strips unsolicited OPT records from non-EDNS
Responses, and the harness cannot mask that difference.

The `erratic-drop` scenario uses a root zone so the startup probe consumes the
first two queries: the first is dropped, the second answered, and the single
compared query is answered under `drop 3`. The harness cannot compare dropped
queries because a timeout aborts the scenario; the default and `drop 2` plus
`truncate 2` examples are therefore skipped. `erratic-delay` and
`erratic-truncate-delay` compare responses from the other README examples, not
elapsed time. The latter exercises CoreDNS's truncation bitmask on UDP and TCP.
Truncated AXFR is skipped because the harness requires a closing SOA.

The `tsig` transfer README example uses a small file Zone. Signed scenarios authenticate each Response before comparing its
other fields; TSIG timestamps and MAC bytes are not compared between servers.
The `tsig-forward` README example replaces its unreachable external Upstream
with a local deterministic fixture.

The literal `k8s_external` fallthrough example forwards to 8.8.8.8 and is
skipped because the differential suite must not depend on an external network.
`k8s-external-fallthrough` uses `whoami` as a deterministic Next instead.

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

The `dnssec-whoami` and `dnssec-kubernetes` scenarios cover the file-key README
examples with unsigned and DO-bit Queries, including apex DNSKEY, ordinary
responses and Kubernetes Negative Responses.
Their public test keys reuse the Ed25519 fixture in `crates/pharos-dnssec/tests`;
they must never be used for real zones. The opt-in RRSIG mask accommodates
independently generated signatures and signing times. It also permits Pharos's
RRset Original TTL to differ from CoreDNS's hardcoded 3600 (RFC 4034 §3.1.4).
It does not verify signatures.
The AWS Secrets Manager README example is skipped because it requires live AWS
credentials and a provisioned secret; the default build also disables the AWS
feature.

The `view` README scenarios use loopback clients, so the non-loopback CIDR
branches require Rust tests. The forwarding examples replace the documented
external Upstreams with separate local IPv4 and IPv6 fixtures.

The `root` TLS and `timeouts` TLS, HTTPS and QUIC examples are skipped because
encrypted Listeners are deferred to M3. The `rewrite` imaginary `some-plugin`
example cannot run because that Plugin does not exist. The `sign` examples
using `key directory` are rejected by CoreDNS itself. The final `sign` example
demonstrates a configuration pitfall rather than a stable Response.
