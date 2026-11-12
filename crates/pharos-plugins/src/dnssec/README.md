# dnssec

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/dnssec/README.md)

## dnssec

- Keys with RSASHA1 or RSASHA1-NSEC3-SHA1 (algorithms 5 and 7) are refused at startup: RFC 9905 §2 says they MUST NOT be used for signing, and validating resolvers treat such Zones as unsigned. CoreDNS signs with them. Roll over to algorithm 8, 13 or 15 before migrating (RFC 6781 §4.1.4).
- RSA private keys below 2048 bits are rejected by aws-lc-rs; CoreDNS accepts them.
- Key files currently require a standalone DNSKEY record with an absolute owner, IN class if specified, and a numeric TTL; the complete zone-file grammar is not supported.
- Canonical signing rejects A6 and legacy name-bearing RDATA that `pharos-proto` cannot safely relocate, rather than signing them as CoreDNS does.
- Constructing a black-lie NSEC allocates; callers must check that its span does not cover an existing name and convert NXDOMAIN to NODATA.
- The signature cache stores complete signed Responses rather than independent RRsets. Changed Responses miss even when an RRset is unchanged; `cache_capacity` limits Responses rather than RRsets and the cache metrics count RRsets within those Responses. Signing a cache miss allocates; Queries without DO and cache hits do not. Concurrent misses may sign the same data more than once instead of sharing CoreDNS's single-flight operation.
- `key aws_secretsmanager` requires the optional `dnssec-aws` Cargo feature, which is off by default. Without it, startup fails with a feature diagnostic. The official AWS SDK uses its default credential chain. TLS uses rustls with aws-lc-rs and no ring; the SDK's aws-sigv4 uses RustCrypto hmac/sha2, and aws-config SSO uses RustCrypto sha1 internally.
- Binary-only AWS secrets cause a startup error instead of CoreDNS's nil `SecretString` panic.
- AWS secret JSON rejects lone surrogate escapes in `key` or `private`; Go replaces these with U+FFFD, including in otherwise ignored key-file comments. Unknown fields are skipped.

## Sources

- [CoreDNS v1.15.0 `plugin/dnssec/black_lies.go`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dnssec/black_lies.go)
- [CoreDNS v1.15.0 `plugin/dnssec`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dnssec)
- [CoreDNS v1.15.0 `plugin/sign/testdata`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/sign/testdata)
