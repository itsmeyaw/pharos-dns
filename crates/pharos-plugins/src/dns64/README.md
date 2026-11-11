# dns64

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/dns64/README.md)

## dns64

- AAAA synthesis uses a Self Lookup that allocates per Query; issue #86 tracks
  allocation-free Self Lookup. Queries that do not require synthesis do not
  allocate in this Plugin.
- The A Self Lookup passes through the Listener's normal size and EDNS
  handling, unlike CoreDNS's in-process capture, so its result may be truncated
  before synthesis. An unsupported name-bearing or malformed record in that
  result produces SERVFAIL rather than being copied into the Response.

## Differential scenarios

The dns64 README scenarios use an inline hosts Backend. The harness sends from
IPv4 loopback, so synthesis without `allow_ipv4` is covered by Rust tests.

## Sources

- Derived from CoreDNS v1.15.0 plugin/dns64/dns64_test.go, TestTo6.
- Derived from CoreDNS v1.15.0 plugin/dns64/setup_test.go.
