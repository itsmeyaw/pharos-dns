# acl

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/acl/README.md)

## acl

- For a Query without EDNS, Pharos omits the OPT record from blocked and
  filtered Responses as required by RFC 6891 §7. CoreDNS sends its EDE OPT
  even when the Query did not include an OPT record.
- Scoped IPv6 rules accept numeric zone IDs, such as `fe80::%2/64`; unscoped `block`/`drop`/`filter` rules match any zone to prevent fail-open, while unscoped `allow` rules do not match scoped clients (RFC 4007 §§11–12). Thus `allow net fe80::/10` followed by `block net *` still blocks scoped link-local clients; a scoped allow such as `allow net fe80::%7/10` can match before a later block.
- IPv6 networks match IPv4 clients through their IPv4-mapped addresses (RFC 4291 §§2.3, 2.5.5.2). Thus `block net ::/0` blocks both IPv4 and IPv6 clients. Deprecated IPv4-compatible IPv6 addresses are not normalized.

## Differential scenarios

The acl README scenarios use whoami as Next. The harness originates Queries
from loopback, so non-loopback allow and drop branches require Rust tests.

## Sources

- Derived from CoreDNS v1.15.0 plugin/acl/acl_test.go, TestACLServeDNS.
- Derived from CoreDNS v1.15.0 plugin/acl/acl_test.go.
- Derived from CoreDNS v1.15.0 plugin/acl/setup_test.go.

- [CoreDNS v1.15.0 `plugin/acl`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/acl)
