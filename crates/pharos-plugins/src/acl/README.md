# acl

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/acl/README.md)

## acl

- For a Query without EDNS, Pharos omits the OPT record from blocked and
  filtered Responses as required by RFC 6891 §7. CoreDNS sends its EDE OPT
  even when the Query did not include an OPT record.

## Differential scenarios

The acl README scenarios use whoami as Next. The harness originates Queries
from loopback, so non-loopback allow and drop branches require Rust tests.

## Sources

- Derived from CoreDNS v1.15.0 plugin/acl/acl_test.go, TestACLServeDNS.
- Derived from CoreDNS v1.15.0 plugin/acl/acl_test.go.
- Derived from CoreDNS v1.15.0 plugin/acl/setup_test.go.
