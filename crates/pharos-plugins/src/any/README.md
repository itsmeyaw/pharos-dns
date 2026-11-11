# any

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/any/README.md)

## any

- Like CoreDNS, `any` synthesizes its HINFO before consulting a Backend, even for a CNAME or signed Zone; it cannot include an RRSIG when DO is set (RFC 8482 §4.2).
- The UDP caller must supply a Response buffer with enough capacity; otherwise Pharos returns an error instead of allocating on the UDP Query path.
