# autopath

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/autopath/README.md)

## autopath

- Search-path Self Lookups allocate; issue #86 tracks allocation-free Self Lookup.
- Search-path Self Lookups re-enter the Listener rather than CoreDNS's Next,
  so earlier Plugins, routing, Response limits and error handling also apply.
  After an unwritten first outcome, SERVFAIL, REFUSED, FORMERR and NOTIMP
  Self Lookup Responses are treated as unwritten: Listener synthesis obscures
  whether a later Plugin actually wrote such a Response.
- A query for exactly the first search suffix (`default.svc.cluster.local.`) is
  passed to the next Plugin unchanged. CoreDNS v1.15.0 returns SERVFAIL because
  `TrimZone` overshoots (#126); Pharos follows RFC 1034 §4.3.2 instead. Names
  above the first suffix (`svc.cluster.local.`) pass through in both.
- Resolver files must be UTF-8. Search suffixes that cannot be represented as
  DNS wire names are treated as the root suffix; CoreDNS accepts arbitrary text.
- A Response containing RDATA that cannot be decoded and relocated by Pharos
  fails rather than being rebuilt by CoreDNS's DNS library.

## Differential scenarios

The autopath file example uses the Kubernetes fixture to supply NXDOMAIN and
positive Responses. The @kubernetes example compares passthrough only: the
fixture has no Pod with the loopback address used by the harness; Rust tests
cover verified Pod namespace search using an explicit client address.

## Sources

- Derived from CoreDNS v1.15.0 plugin/autopath/autopath_test.go.
- Derived from CoreDNS v1.15.0 plugin/autopath/setup_test.go.

- [CoreDNS v1.15.0 `plugin/autopath`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/autopath)
- [miekg/dns resolver configuration parsing](https://github.com/miekg/dns)
