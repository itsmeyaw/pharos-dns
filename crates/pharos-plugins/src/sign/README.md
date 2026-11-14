# sign

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/sign/README.md)

## sign

- Only SHA-256 CDS records are created. CoreDNS also creates SHA-1 CDS; RFC 9905 §2 forbids creating SHA-1 DS records.
- The shared signer has the key and canonical-RDATA restrictions listed under `dnssec`, including rejecting SHA-1 signing algorithms and RSA keys below 2048 bits.
- CAA and URI output escapes octets that CoreDNS's presentation-format writer would misread, so literal backslashes survive. CoreDNS writes `a\123z` as `a{z`; plain values are written as CoreDNS writes them.
- Restart and shutdown wait for in-progress signing to finish before returning; CoreDNS does not wait for its signing goroutines. Pharos serializes each signer's checks, while CoreDNS's initial signing can overlap its periodic check.

- CoreDNS checks SOA signature inception and expiration every five hours; it does not check whether the unsigned file changed. The actual expiration window is seven days, despite the upstream README saying 14 days. Like CoreDNS, `key directory` is not implemented.

- CoreDNS shares key records across multiple origins in one Directive and leaves their owner set to the last origin. Pharos follows this behavior: earlier Zones may lack their apex DNSKEY and produce invalid DNSSEC. Configure one `sign` Directive per origin.
- The source file's SOA owner must match the configured origin; otherwise signing fails because the RRSIG Signer's Name would identify a different zone (RFC 4034 §3.1.7).
- Offline RRSIG TTL and Original TTL use the covered RRset's minimum TTL; mixed-TTL RRsets are normalized to that value (RFC 2181 §5.2).
- Offline NSEC TTL is `min(SOA TTL, SOA.MINIMUM)` (RFC 9077 §3.1); apex NS RRSIG TTL matches the NS RRset TTL (RFC 4034 §3).
- Zone-file RRSIG calendar times at the RFC 1982 half-range (±2^31 seconds) from now are rejected; miekg/dns wraps them into 32 bits (RFC 4034 §3.1.5).
- The shared key loader rejects noncanonical RSA DNSKEY exponent/modulus encodings, which miekg/dns accepts (RFC 3110 §2; see the `dnssec` README).
- If Unix time is not newer than the input SOA serial under RFC 1982 arithmetic, the offline signer advances the existing serial by one. CoreDNS assigns Unix time directly, which can repeat or move the serial backward (RFC 1982 §3.2; RFC 4033 §8.2).

## Sources

- [CoreDNS v1.15.0 `plugin/sign/testdata`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/sign/testdata)
- [CoreDNS v1.15.0 `plugin/sign`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/sign)
