# transfer

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/transfer/README.md)

## transfer

- UDP IXFR returns the current SOA rather than REFUSED, as decided in the Server compatibility notes (RFC 1995 §2).
- Kubernetes sends NOTIFY after initial sync and when its data changes (RFC 1996 §§3.1, 4.1); CoreDNS's Kubernetes Plugin does not send NOTIFY.
- `to` accepts CIDR prefixes as a Pharos extension for incoming AXFR/IXFR ACLs only. CIDR entries are not NOTIFY recipients: setup logs one WARN per entry and NOTIFY skips it, succeeding when every IP address succeeds. Use explicit IP addresses for NOTIFY.
- Transfer ACLs compare IP addresses rather than CoreDNS's configured text, accepting equivalent IPv6 and IPv4-mapped forms (RFC 5952 §§4, 8; RFC 4291 §2.5.5.2). Scoped `to` addresses are rejected at setup because scope-aware transfer authorization is not supported.
- **Partial** — RFC 1996 §2.1: NOTIFY does not derive its default set from the apex NS RRset minus the SOA MNAME. `to` is required, and outgoing NOTIFY targets only explicit IP destinations; the transfer Plugin receives no apex NS/SOA records for discovery. Configure explicit IPs.
- IXFR requires the Authority SOA owner and class to match the Question and returns SERVFAIL on mismatch, stricter than CoreDNS (RFC 1995 §3); RFC 1995 defines no RCODE, so SERVFAIL is a Pharos choice.
- IXFR serial ordering follows RFC 1982 §3.2, including wraparound. An equal or newer client serial gets one current SOA; CoreDNS's generic and Kubernetes paths check equality only (RFC 1995 §2).
- A TCP IXFR answered with only the current SOA clears AA, as CoreDNS does (#75); an IXFR client serial of 0 is an ordinary serial (RFC 1982 §7), whereas CoreDNS treats it as unknown and sends the full Zone.

## Sources

- [CoreDNS v1.15.0 `plugin/transfer`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/transfer)
