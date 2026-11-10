# RDATA test sources

TXT escape tests in `rdata.rs` adapt miekg/dns v1.1.73
`parse_test.go`'s `TestDomainNameAndTXTEscapes`. Character-string
presentation follows `types.go` and `msg_helpers.go` from that version.
Service-record fixtures in `rdata_service.rs` adapt its `parse_test.go` and
`dns_test.go` examples.
Differential RDATA tests use NLnet Labs' domain as a reference. Licenses are
listed in the repository's `THIRD_PARTY_NOTICES`.
