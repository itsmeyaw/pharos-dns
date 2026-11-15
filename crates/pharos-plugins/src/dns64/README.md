# dns64

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/dns64/README.md)

## dns64

- Rejects non-/96 use of the RFC 6052 Well-Known Prefix and nonzero /96 reserved octets (RFC 6052 §2.1–2.2).
- Synthesizes with the Well-Known Prefix only for globally reachable IPv4 addresses (RFC 6052 §3.1).
- Synthesized responses use AA/RA from the initial AAAA response and TC/RCODE from the A lookup (RFC 6147 §5.4).
- A successful empty A lookup leaves the original AAAA response unchanged unless it contains excluded IPv4-mapped AAAA (RFC 6147 §§5.1.4, 5.4).
- Filtering IPv4-mapped AAAA rebuilds from a wire snapshot so compression pointers remain valid; only this exclusion path allocates.
- A CNAME-only A lookup follows at most eight targets using sequential Self Lookups; this adds tail latency. Exceeding the bound returns SERVFAIL; DNAME-only responses are not chased (RFC 6147 §5.1.5).
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

- [CoreDNS v1.15.0 `plugin/dns64`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dns64)
