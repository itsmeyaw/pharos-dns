# template

See the [CoreDNS template documentation](https://github.com/coredns/coredns/blob/v1.15.0/plugin/template/README.md).

## template

- Go templates and expressions use the supported subsets documented in the
  [template engine](../gotemplate/README.md) and [expression engine](../expression/README.md).
- Match expressions use Rust regex syntax and Unicode rules rather than Go RE2.
- Variables and expressions of one rule share 65,535 bytes of scratch;
  exhausting it returns SERVFAIL.
- Each worker keeps a workspace per rule; first use may allocate. Memory grows
  with the regexes and their capture groups. Workspaces for removed rules are
  reclaimed on that worker's next workspace initialization or thread exit.
- On 64-bit macOS, README example rule workspaces measured 66,711 bytes
  (NXDOMAIN), 75,415 (address), 73,239 (reverse), 70,743 (hex), 77,719
  (LAN), and 80,423 (two patterns). These include scratch, matcher caches,
  capture slots, and workspace vectors, but exclude thread-local hash-table
  bookkeeping, allocator overhead, and shared compiled configuration.
- Failure metric `template` labels use the configured source, not Go's
  normalized template parse tree. Wildcard class/type metric labels allocate
  when a combination first matches; later increments use cached handles.
- Rendering buffers, record vectors and zone-text parsing allocate for matched
  Queries; #91 tracks allocation-free single-record parsing.
- Rendered zone text cannot use `$INCLUDE`; unlike miekg/dns, it cannot read files during a Query.
- For a non-EDNS Query, the Listener removes the `ederror` OPT from the
  Response; CoreDNS can retain it. See the Server notes in `docs/compatibility.md`.
- CNAME Self Lookup allocates; #86 tracks allocation-free Self Lookup.
