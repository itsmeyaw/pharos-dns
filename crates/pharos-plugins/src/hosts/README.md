# hosts

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/hosts/README.md)

## hosts

- An unmapped name without fallthrough gets authoritative NXDOMAIN and a synthetic SOA, rather than CoreDNS's SERVFAIL (RFC 1034 §4.3.2; RFC 2308 §3).
- Authoritative NODATA includes a synthetic SOA for negative caching (RFC 2308 §3).
- Non-IN Questions pass through rather than receiving IN-class host records (RFC 1034 §4.3.1).
- Wildcard lookup replaces only the leftmost QNAME label; it does not search ancestor suffixes for the closest encloser (RFC 4592 §§2.2.1, 3.3). This matches CoreDNS v1.15.0's single wildcard-key lookup.
- Pharos discards names that are not valid DNS names or UTF-8; CoreDNS retains arbitrary fields in its hosts maps.
- Pharos lowercases ASCII name bytes, while CoreDNS applies Go's Unicode lowercasing.
- Configured Domains that cannot be represented as DNS names are ignored for matching; CoreDNS keeps its normalized strings.
- On a file read error, an unfinished field is discarded; CoreDNS processes the last partial chunk before logging the error.
- Responses require a preallocated UDP buffer, as with Whoami.
- Hosts-file reloads stop during configuration Restart and resume if that Restart fails.
- File parsing runs on a Tokio worker, so a large or slow hosts file can delay other tasks on that worker.

## Sources

- CoreDNS plugin/hosts/hosts_test.go hostsExample.

- [CoreDNS v1.15.0 `plugin/hosts`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/hosts)
- [CoreDNS v1.15.0 `plugin/pkg/fall`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/pkg/fall)
