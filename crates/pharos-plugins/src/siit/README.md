# siit

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/siit/README.md)

## siit

- Rejects non-/96 use of the RFC 6052 Well-Known Prefix (RFC 6052 §2.1).
- Translates with the Well-Known Prefix only for globally reachable IPv4 addresses (RFC 6052 §3.1); explicit EAMs and configured Network-Specific Prefixes remain available.
- Defaults to the Well-Known Prefix; stateless translation deployments should configure a Network-Specific Prefix (RFC 6052 §3.3).
- AAAA Self Lookup does not allocate once the Listener's Self Lookup pools are
  warm (#86). Queries that do not need it do not allocate in this Plugin.
- Self Lookup uses Listener size and EDNS handling, which can truncate the
  intermediate Response. Unsupported name-bearing or malformed records in a
  synthesized or error Response produce SERVFAIL rather than being copied.

## Differential scenarios

The siit README scenario uses an inline hosts Backend to exercise the prefix.

## Sources

- Derived from CoreDNS v1.15.0 plugin/siit/setup_test.go.
- Derived from CoreDNS v1.15.0 plugin/siit/siit_test.go.

- [CoreDNS v1.15.0 `plugin/siit`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/siit)
