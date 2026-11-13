# sign

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/sign/README.md)

## sign

- Only SHA-256 CDS records are created. CoreDNS also creates SHA-1 CDS; RFC 9905 §2 forbids creating SHA-1 DS records.
- The shared signer has the key and canonical-RDATA restrictions listed under `dnssec`, including rejecting SHA-1 signing algorithms and RSA keys below 2048 bits.
- CAA and URI output preserves literal backslash octets. CoreDNS's presentation-format writer can interpret them as escapes.
- Restart and shutdown wait for in-progress signing to finish before returning; CoreDNS does not wait for its signing goroutines.

CoreDNS checks SOA signature inception and expiration every five hours; it does not check whether the unsigned file changed. The actual expiration window is seven days, despite the upstream README saying 14 days. Like CoreDNS, `key directory` is not implemented.

CoreDNS shares key records across multiple origins in one Directive and leaves their owner set to the last origin. Pharos follows this behavior: earlier Zones may lack their apex DNSKEY and produce invalid DNSSEC. Configure one `sign` Directive per origin.

## Sources

- [CoreDNS v1.15.0 `plugin/sign/testdata`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/sign/testdata)
- [CoreDNS v1.15.0 `plugin/sign`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/sign)
