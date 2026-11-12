# template

See the [CoreDNS template documentation](https://github.com/coredns/coredns/blob/v1.15.0/plugin/template/README.md).

## template

- Go templates and expressions use the supported subsets documented in the
  [template engine](../gotemplate/README.md) and [expression engine](../expression/README.md).
- Match expressions use Rust regex syntax and Unicode rules rather than Go RE2.
- Setup rejects more than 127 capture groups per match and more than 32 variables
  per rule. Expression evaluation has 4,096 bytes of scratch per variable and
  expression; exhausting it returns SERVFAIL.
- Queries using the same match expression serialize while its capture and
  expression workspaces are in use, including record rendering.
- Failure metric `template` labels use the configured source, not Go's
  normalized template parse tree. Wildcard class/type metric labels allocate
  when a combination first matches; later increments use cached handles.
- Rendering buffers, record vectors and zone-text parsing allocate for matched
  Queries; #91 tracks allocation-free single-record parsing.
- Rendered zone text cannot use `$INCLUDE`; unlike miekg/dns, it cannot read files during a Query.
- For a non-EDNS Query, the Listener removes the `ederror` OPT from the
  Response; CoreDNS can retain it. See the Server notes in `docs/compatibility.md`.
- CNAME Self Lookup allocates; #86 tracks allocation-free Self Lookup.
