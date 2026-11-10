# RDATA test sources

TXT escape tests in `rdata.rs` adapt miekg/dns v1.1.73
`parse_test.go`'s `TestDomainNameAndTXTEscapes`. Character-string
presentation follows `types.go` and `msg_helpers.go` from that version.
Service-record fixtures in `rdata_service.rs` adapt its `parse_test.go` and
`dns_test.go` examples.
DNSSEC fixtures in `rdata_dnssec.rs` adapt its `parse_test.go` (`TestNSEC`,
`TestParseDS`, `TestRfc1982`) and `msg_helpers_test.go` bitmap cases. miekg/dns
is BSD-3-Clause, copyright 2009 The Go Authors; extensions copyright 2011 Miek
Gieben.
SVCB and HTTPS fixtures in `rdata_svcb.rs` adapt miekg/dns v1.1.73
`parse_test.go` (`TestParseSVCB`) and `svcb_test.go` under the same license.
Security fixtures in `rdata_security.rs` adapt miekg/dns v1.1.73
`parse_test.go` (`TestParseTLSA`, `TestParseSSHFP`, `TestParseZONEMD`)
and `tsig_test.go` under the same license.
The type-name fixture `corpus/miekg-types.txt` derives from miekg/dns v1.1.73
`ztypes.go` and `types.go`, under the same license. RFC 3597 examples are
covered in `rdata_unknown.rs`.
Differential RDATA tests use NLnet Labs' domain as a reference. Licenses are
listed in the repository's `THIRD_PARTY_NOTICES`.
