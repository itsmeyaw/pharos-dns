# transfer

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/transfer/README.md)

## transfer

- UDP IXFR returns the current SOA rather than REFUSED, as decided in the Server compatibility notes (RFC 1995 §2).
- Kubernetes sends NOTIFY after initial sync and when its data changes (RFC 1996 §§3.1, 4.1); CoreDNS's Kubernetes Plugin does not send NOTIFY.
- `to` accepts CIDR prefixes as a Pharos extension for incoming AXFR/IXFR ACLs only. CIDR entries are not NOTIFY recipients; NOTIFY returns an error for them. Use explicit IP addresses for NOTIFY.
- IXFR requires the Authority SOA owner and class to match the Question and returns SERVFAIL on mismatch, stricter than CoreDNS (RFC 1995 §3).
- IXFR serial ordering follows RFC 1982 §3.2, including wraparound. An equal or newer client serial gets one current SOA; CoreDNS's generic and Kubernetes paths check equality only (RFC 1995 §2).

## Sources

- [CoreDNS v1.15.0 `plugin/transfer`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/transfer)
