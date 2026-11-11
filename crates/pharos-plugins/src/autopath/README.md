# autopath

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/autopath/README.md)

## autopath

- Search-path Self Lookups allocate; issue #86 tracks allocation-free Self Lookup.
- Search-path Self Lookups re-enter the Listener rather than CoreDNS's Next,
  so earlier Plugins, routing, Response limits and error handling also apply.
  After an unwritten first outcome, SERVFAIL, REFUSED, FORMERR and NOTIMP
  Self Lookup Responses are treated as unwritten: Listener synthesis obscures
  whether a later Plugin actually wrote such a Response.
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
