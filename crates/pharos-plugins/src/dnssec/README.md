# dnssec

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/dnssec/README.md)

## dnssec

- Keys with RSASHA1 or RSASHA1-NSEC3-SHA1 (algorithms 5 and 7) are refused at startup: RFC 9905 §2 says they MUST NOT be used for signing, and validating resolvers treat such Zones as insecure. CoreDNS signs with them. Roll over to algorithm 8, 13 or 15 before migrating (RFC 6781 §4.1.4).
- RSA private keys below 2048 bits are rejected by aws-lc-rs; CoreDNS accepts them.
- Key files currently require a standalone DNSKEY record with an absolute owner, IN class if specified, and a numeric TTL; the complete zone-file grammar is not supported.
- Canonical signing rejects A6 and legacy name-bearing RDATA that `pharos-proto` cannot safely relocate, rather than signing them as CoreDNS does.
- Constructing a black-lie NSEC allocates. Direct `black_lie` library callers must ensure its span does not cover existing names and convert NXDOMAIN to NODATA. The plugin matches CoreDNS's synthetic spans and converts NXDOMAIN, but has no authoritative zone inventory to validate spans; in particular, a referral span can include descendant names.
- The signature cache stores complete signed Responses rather than independent RRsets. Changed Responses miss even when an RRset is unchanged; `cache_capacity` limits Responses rather than RRsets and the cache metrics count signed RRsets within those Responses. The global limit is `max(capacity / 256, 4) * 256` with integer division, matching CoreDNS's effective capacity but not its per-shard eviction. The default 10,000 therefore permits 9,984 Responses. At the 65,535-byte TCP message limit, each entry can retain up to 65,533 key bytes plus 65,535 signed bytes: about 1.22 GiB total before map, allocation and other overhead. Signing a cache miss allocates; Queries without DO and cache hits do not. Concurrent misses may sign the same data more than once instead of sharing CoreDNS's single-flight operation.
- Unlike CoreDNS's periodic cleanup, expired cache entries remain until the same Response is re-signed or arbitrary eviction removes them.
- Signing errors return a plugin error, which the Listener turns into SERVFAIL. CoreDNS ignores `d.sign` errors and can return unsigned or partially signed Responses instead.
- RRsets are grouped by owner, class and type (RFC 2181 §5). CoreDNS groups by owner and type, so mixed-class Responses can differ.
- With all Plugin features enabled, the debug `cache::cache_stale::prefer_positive_retains_last_good_answer_after_nonanswer_prefetch` test overflows the default macOS test-thread stack. It passes with `RUST_MIN_STACK=4194304`; production impact has not been established.
- `key aws_secretsmanager` requires the optional `dnssec-aws` Cargo feature, which is off by default. Without it, Plugin setup fails with a feature diagnostic. The official AWS SDK uses its default credential chain. TLS uses rustls with aws-lc-rs and no ring; the SDK's aws-sigv4 uses RustCrypto hmac/sha2, and aws-config SSO uses RustCrypto sha1 internally.
- Binary-only AWS secrets cause a setup error instead of CoreDNS's nil `SecretString` panic.
- AWS secret JSON rejects lone surrogate escapes in `key` or `private`; Go replaces these with U+FFFD, including in otherwise ignored key-file comments. Unknown fields are skipped.

## Sources

- [CoreDNS v1.15.0 `plugin/dnssec/black_lies.go`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dnssec/black_lies.go)
- [CoreDNS v1.15.0 `plugin/dnssec`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dnssec)
- [CoreDNS v1.15.0 `plugin/sign/testdata`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/sign/testdata)
