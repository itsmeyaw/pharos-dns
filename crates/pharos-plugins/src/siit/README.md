# siit

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/siit/README.md)

## siit

- AAAA Self Lookup allocates per Query; issue #86 tracks allocation-free Self
  Lookup. Queries that do not need it do not allocate in this Plugin.
- Self Lookup uses Listener size and EDNS handling, which can truncate the
  intermediate Response. Unsupported name-bearing or malformed records in a
  synthesized or error Response produce SERVFAIL rather than being copied.

## Differential scenarios

The siit README scenario uses an inline hosts Backend to exercise the prefix.

## Sources

- Derived from CoreDNS v1.15.0 plugin/siit/setup_test.go.
- Derived from CoreDNS v1.15.0 plugin/siit/siit_test.go.
