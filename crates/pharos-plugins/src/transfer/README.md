# transfer

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/transfer/README.md)

## transfer

- UDP IXFR returns the current SOA rather than REFUSED, as decided in the Server compatibility notes (RFC 1995 §2).
- Kubernetes sends NOTIFY after initial sync and when its data changes (RFC 1996 §§3.1, 4.1); CoreDNS's Kubernetes Plugin does not send NOTIFY.

## Sources

- [CoreDNS v1.15.0 `plugin/transfer`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/transfer)
