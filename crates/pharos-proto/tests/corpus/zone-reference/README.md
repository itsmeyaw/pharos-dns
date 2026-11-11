# Zone parser reference corpus

`miekg.zone` adapts cases from miekg/dns `scan_test.go` and `parse_test.go`;
the malformed-record cases in `zone_reference.rs` also adapt `scan_test.go`.
The reference checkout is revision `b2d6c9f4480a71247e0df4ce709122852a2849cf`,
BSD-3-Clause; see `MIEKG-LICENSE` for copyright and license terms.

`coredns.zone` copies `exampleOrgSigned` from CoreDNS `plugin/file/example_org.go`;
`coredns-escape.zone` copies `dbEscapeOwner` from `plugin/file/escape_test.go`.
CoreDNS revision `a6fde3fe339c6ec848447e11cc9796be8c97b4e0` is Apache-2.0,
copyright 2016–2020 The CoreDNS authors and contributors. See the repository's
`LICENSE` and `THIRD_PARTY_NOTICES`.

The `.expected` files contain one tab-separated line per record: uncompressed
owner wire hex, decimal TTL, class and type, and uncompressed RDATA wire hex.
They were generated using miekg/dns `ZoneParser` and `PackRR` without compression.
The reference gives the `$GENERATE` records in `miekg.zone` TTL 3600, despite
the preceding `$TTL 2H`; this is reference behavior, not a standards claim.
The octet corpus exhaustively tests single escaped TXT octets; the seeded corpus
uses 512 fixed pseudo-random TXT records with varied escaped bytes, TTLs, class
order and whitespace. This is a bounded offline differential corpus, not a
runtime fuzzer or a comprehensive test of all zone grammar and record types.

To regenerate after installing the local Go dependencies, run from the local
miekg/dns checkout with network access disabled (replace the absolute paths):

```sh
GOPROXY=off GOSUMDB=off go run /path/to/pharos/crates/pharos-proto/tests/corpus/zone-reference/generate.go /path/to/pharos/crates/pharos-proto/tests/corpus/zone-reference
```

The generator rewrites the generated `octets.zone`, `seeded.zone`, and all
`.expected` files. Rust tests use only the checked-in files, not Go.
