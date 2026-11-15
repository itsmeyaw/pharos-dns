# header

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/header/README.md)

## header

- AA cannot be set on Queries or added to non-authoritative Responses (RFC 1035 §4.1.1); CoreDNS permits both overrides.
- Response RD copies the received Query; response RD rules are rejected at setup. Query RD rules still affect Next, while CoreDNS can retain either override (RFC 1035 §4.1.1).
- Header rules modify encoded Response flags in place; a compressed name pointing into the changed header bytes can therefore decode differently than CoreDNS's re-encoded Response. Query views retain their original name bytes until forwarded, rather than re-encoding them.
- Forwarding a Query with changed flags returns FORMERR when the existing forwarding safety check cannot rule out compression pointers into the header or opaque RDATA. CoreDNS re-encodes its decoded Query instead.
- Response rules apply only to a Response returned by Next; Listener-synthesized Responses for errors or unanswered outcomes are not modified, following the explicit Plugin outcome contract.

## Differential scenarios

The three `header` README scenarios use `whoami` as the Backend and compare
Responses over UDP and TCP; Rust tests also inspect forwarded Queries.

## Sources

- [CoreDNS v1.15.0 `plugin/header`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/header)
