# whoami

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/whoami/README.md)

## whoami

- Whoami reports an error if adding the protocol label would make its SRV owner name exceed the DNS name length limit. CoreDNS ignores the resulting write error.
- The UDP caller must supply a Response buffer with enough capacity; otherwise Pharos reports an error instead of allocating on the UDP Query path.

## Differential scenarios

The `whoami-log` scenario compares Responses, not log output. The current whoami
Responses cannot exceed the 512-octet UDP minimum for these short Queries, so
truncation is not covered.
