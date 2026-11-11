# dnssec

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/dnssec/README.md)

## dnssec

- Keys with RSASHA1 or RSASHA1-NSEC3-SHA1 (algorithms 5 and 7) are refused at startup: RFC 9905 §2 says they MUST NOT be used for signing, and validating resolvers treat such Zones as unsigned. CoreDNS signs with them. Roll over to algorithm 8, 13 or 15 before migrating (RFC 6781 §4.1.4).
- RSA private keys below 2048 bits are rejected by aws-lc-rs; CoreDNS accepts them.
- Key files currently require a standalone DNSKEY record with an absolute owner, IN class if specified, and a numeric TTL; the complete zone-file grammar is not supported.
- Canonical signing rejects A6 and legacy name-bearing RDATA that `pharos-proto` cannot safely relocate, rather than signing them as CoreDNS does.
- Constructing a black-lie NSEC allocates; callers must check that its span does not cover an existing name and convert NXDOMAIN to NODATA.

## Sources

- [CoreDNS v1.15.0 `plugin/dnssec/black_lies.go`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dnssec/black_lies.go)
- [CoreDNS v1.15.0 `plugin/sign/testdata`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/sign/testdata)
