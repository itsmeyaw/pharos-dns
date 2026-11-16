# whoami

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/whoami/README.md)

## whoami

- A/AAAA and SRV records use class IN. Non-IN Questions pass through. SRV owner names use `_whoami._udp` or `_whoami._tcp`.
- RFC 2782 §2 requires `_Service._Proto.Name`; CoreDNS-compatible owners omit `_whoami` (`_udp.Name` / `_tcp.Name`), while Pharos keeps the RFC-compliant service label.
- Whoami reports an error if adding the protocol label would make its SRV owner name exceed the DNS name length limit. CoreDNS ignores the resulting write error.
- The UDP caller must supply a Response buffer with enough capacity; otherwise Pharos reports an error instead of allocating on the UDP Query path.

## Differential scenarios

The `whoami-log` scenario compares Responses, not log output. The current whoami
Responses cannot exceed the 512-octet UDP minimum for these short Queries, so
truncation is not covered.

## Sources

- [CoreDNS v1.15.0 `plugin/whoami`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/whoami)
