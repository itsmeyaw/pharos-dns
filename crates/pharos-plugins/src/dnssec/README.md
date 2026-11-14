# dnssec

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/dnssec/README.md)

## dnssec

- RRSIG Original TTL and RRSIG TTL use the covered RRset's TTL (RFC 4034 §3, §3.1.4). If its records have different TTLs, Pharos uses the lowest for every record (RFC 2181 §5.2). This also applies to apex DNSKEY answers without DO. CoreDNS hardcodes Original TTL to 3600 and uses a 3600-second RRSIG TTL for intercepted DNSKEY answers.
- If a Response already contains RRSIGs covering RRsets Pharos signs, their TTLs and the covered RRset are limited to the lowest received TTL without extending any record's lifetime. Existing signatures retain their Original TTL fields.
- In a signed Response, TTL normalization applies only to signed RRsets and their covering RRSIGs. Records outside configured Zones and unsigned RRsets retain their TTLs.
- Like CoreDNS, Pharos signs RRsets separately in each section. If an upstream Response splits one RRset across sections, its signatures do not cover the union; TTL normalization still considers all sections.
- The signature cache key includes the Response's TTLs. RRsets whose TTL counts down behind `cache` or `forward` can miss more often than in CoreDNS.
- On a cache miss, TTL normalization rescans the Response for each record; its cost grows quadratically with the record count.
- Keys with RSASHA1 or RSASHA1-NSEC3-SHA1 (algorithms 5 and 7) are refused at startup: RFC 9905 §2 says they MUST NOT be used for signing, and validating resolvers treat such Zones as insecure. CoreDNS signs with them. Roll over to algorithm 8, 13 or 15 before migrating (RFC 6781 §4.1.4).
- RSASHA512 (algorithm 10) is refused for signing under RFC 9904 §3. RSA modulus and exponent values above 4096 bits are rejected (RFC 3110 §2; RFC 5702 §§2.1–2.2).
- P-256/P-384/Ed25519 sign with aws-lc-rs (RustCrypto was tried and reverted, see [#106](https://github.com/itsmeyaw/pharos-dns/issues/106)). A signature costs one Rust-heap allocation (ECDSA also allocates inside aws-lc-rs); RSA allocates an intermediate signature buffer. C-heap use is not measured.
- Each loaded DNSKEY is bound to its owner zone and cannot sign another configured zone (RFC 4035 §2.1).
- Apex DNSKEY interception matches only QCLASS IN and ANY; other classes pass to Next, but DO Responses in signed zones are still signed. CoreDNS intercepts DNSKEY without the class gate (RFC 2181 §5.1).
- In split-key mode, Pharos signs only the apex DNSKEY RRset with the KSK and signs non-apex DNSKEY RRsets with the ZSK. CoreDNS uses the KSK for all DNSKEY RRsets (RFC 6781 §3.1).
- Calendar RRSIG dates at least 2^31 seconds from now are rejected; miekg/dns wraps them into 32-bit timestamps (RFC 4034 §3.1.5; RFC 1982 §3.2).
- RSA DNSKEY parsing rejects leading zero octets and the extended exponent-length form for exponents shorter than 256 octets; miekg/dns accepts them (RFC 3110 §2).
- A configured zone without a matching key passes DNSKEY and DO queries through unchanged.
- Negative NXDOMAIN/NODATA answers return NOERROR with synthetic NXNAME NSEC in Authority. CoreDNS also maps NXDOMAIN to NOERROR, but puts its black-lie NSEC in Answer.
- A DO negative response without SOA fails with SERVFAIL; Pharos does not return an unsigned denial. CoreDNS returns the upstream negative response.
- Any explicit QTYPE 128 query receives FORMERR when the dnssec plugin is in the chain, regardless of QNAME, as RFC 9824 §3.5 requires of implementing servers.
- Only a DNAME-synthesized CNAME is unsigned; real CNAME RRsets in the same response remain signed (RFC 6672 §5.3.1).
- A sole apex CDS/CDNSKEY delete signal is retained and signed; CoreDNS drops it while replacing publication records (RFC 8078 §4).
- RSA private keys below 2048 bits are rejected by aws-lc-rs; CoreDNS accepts them.
- Key files currently require a standalone DNSKEY record with an absolute owner, IN class if specified, and a numeric TTL; the complete zone-file grammar is not supported.
- Canonical signing rejects A6 and legacy name-bearing RDATA that `pharos-proto` cannot safely relocate, rather than signing them as CoreDNS does.
- Constructing a black-lie NSEC allocates. Direct `black_lie` library callers must ensure its span does not cover existing names and convert NXDOMAIN to NODATA. The plugin matches CoreDNS's synthetic spans and converts NXDOMAIN, but has no authoritative zone inventory to validate spans; in particular, a referral span can include descendant names.
- The signature cache stores complete signed Responses rather than independent RRsets. Changed Responses miss even when an RRset is unchanged; `cache_capacity` limits Responses rather than RRsets and the cache metrics count signed RRsets within those Responses. The global limit is `max(capacity / 256, 4) * 256` with integer division, matching CoreDNS's effective capacity but not its per-shard eviction. The default 10,000 therefore permits 9,984 Responses. At the 65,535-byte TCP message limit, each entry can retain up to 65,533 key bytes plus 65,535 signed bytes: about 1.22 GiB total before map, allocation and other overhead. Signing a cache miss allocates; Queries without DO and cache hits do not. Concurrent misses may sign the same data more than once instead of sharing CoreDNS's single-flight operation.
- Cache-miss/RSA allocation removal is tracked in [#106](https://github.com/itsmeyaw/pharos-dns/issues/106).
- Cache byte budget, mutex gauge scan, RRset TTL rescans, and Additional grouping scans are tracked in [#107](https://github.com/itsmeyaw/pharos-dns/issues/107).
- Unlike CoreDNS's periodic cleanup, expired cache entries remain until the same Response is re-signed or arbitrary eviction removes them.
- Signing errors return a plugin error, which the Listener turns into SERVFAIL. CoreDNS ignores `d.sign` errors and can return unsigned or partially signed Responses instead.
- RRsets are grouped by case-insensitive owner, class and type (RFC 2181 §5; RFC 4343 §3). CoreDNS groups by case-sensitive owner and type, so mixed-class or mixed-case Responses can differ.
- With all Plugin features enabled, the debug `cache::cache_stale::prefer_positive_retains_last_good_answer_after_nonanswer_prefetch` test overflows the default macOS test-thread stack. It passes with `RUST_MIN_STACK=4194304`, and in the release profile without that setting; production impact has not been established.
- `key aws_secretsmanager` requires the optional `dnssec-aws` Cargo feature, which is off by default. Without it, Plugin setup fails with a feature diagnostic. The official AWS SDK uses its default credential chain. TLS uses rustls with aws-lc-rs and no ring; the SDK's aws-sigv4 uses RustCrypto hmac/sha2, and aws-config SSO uses RustCrypto sha1 internally.
- Binary-only AWS secrets cause a setup error instead of CoreDNS's nil `SecretString` panic.
- AWS secret JSON rejects lone surrogate escapes in `key` or `private`; Go replaces these with U+FFFD, including in otherwise ignored key-file comments. Unknown fields are skipped.

## Sources

- [CoreDNS v1.15.0 `plugin/dnssec/black_lies.go`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dnssec/black_lies.go)
- [CoreDNS v1.15.0 `plugin/dnssec`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dnssec)
- [CoreDNS v1.15.0 `plugin/sign/testdata`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/sign/testdata)
