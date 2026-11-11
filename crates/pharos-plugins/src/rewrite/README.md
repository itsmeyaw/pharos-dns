# rewrite

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/rewrite/README.md)

## rewrite

- CNAME Self Lookup allocates per Query; issue #86 tracks allocation-free Self Lookup.
- The CNAME rewrite depth limit counts all Self Lookups, including those from other Plugins; CoreDNS counts only CNAME rewrites.
- EDNS rewrites use preallocated scratch storage and serialize Queries at the same Self Lookup depth; independent depths use separate buffers.
- If the original Query had no OPT record, Pharos omits OPT from the Response as required by RFC 6891 §7. CoreDNS can return an OPT created by `rewrite edns0` to that client.
- Regex rules use Rust regex syntax rather than Go RE2; character classes such as `\d` and `\w` are Unicode-aware by default, unlike Go. Regex captures allocate per Query.
- Regex matchers share a preallocated, synchronized cache per pattern, so concurrent matches of the same pattern briefly serialize.
- TTL rewrites leave OPT's extended RCODE, version and flags untouched as required by RFC 6891 §6.1.3; CoreDNS applies its TTL rule to OPT records as well.
- Rebuilding a rewritten Query or Response rejects malformed or unsupported name-bearing RDATA with SERVFAIL instead of copying it as CoreDNS does.

## Differential scenarios

The `rewrite` name, PTR and TTL scenarios use inline hosts records. The CNAME
scenarios use analogous names from the Kubernetes ExternalName and hosts fixtures;
the README's literal `my-app.com` example has no matching fixture. The README's
SERVFAIL-to-NOERROR RCODE examples are tested in Rust: the shared harness has no
deterministic SERVFAIL backend. `rewrite-rcode` compares a nonmatching NXDOMAIN,
and `rewrite-rcode-refused` compares a matching REFUSED-to-NOERROR rewrite using ACL.
The type and EDNS scenarios use whoami and mask its client
port. The EDNS variable scenario covers QNAME, QTYPE, client IP and protocol.
The NSID and subnet scenarios compare client Responses; Rust tests also inspect
the rewritten Query because whoami does not echo those options.
`rewrite-edns-global` verifies option registration across Server Blocks.
The `{server_port}` and `{client_port}` examples are covered by Rust tests: the
processes use different ports. The metadata name example is also covered by Rust
tests because the Kubernetes fixture has no Pod with the harness's loopback IP.
The documented imaginary `some-plugin` metadata example cannot run because that
Plugin does not exist.
The `rewrite edns0` example without an EDNS Query is not compared: CoreDNS
returns OPT while Pharos omits it under RFC 6891 §7, and the harness cannot mask
additional records. A Rust integration test covers this deviation.

## Sources

- Derived from CoreDNS v1.15.0 plugin/rewrite/cname_target_test.go TestCNAMETargetRewrite_upstreamFailurePaths.
- Derived from CoreDNS v1.15.0 plugin/rewrite/cname_target_test.go TestCNameTargetRewrite.
- Derived from CoreDNS v1.15.0 plugin/rewrite/cname_target_test.go.
- Derived from CoreDNS v1.15.0 plugin/rewrite/edns0_test.go TestEdns0LocalSetRevertNoLeak and TestEdns0LocalSetRevertRestoresPreexisting.
- Derived from CoreDNS v1.15.0 plugin/rewrite/edns0_test.go.
- Derived from CoreDNS v1.15.0 plugin/rewrite/name_metadata_test.go TestRegexNameMetadataConcurrentResponses.
- Derived from CoreDNS v1.15.0 plugin/rewrite/name_metadata_test.go TestRegexNameMetadataLegacyLiteral.
- Derived from CoreDNS v1.15.0 plugin/rewrite/name_metadata_test.go TestRegexNameMetadataSkippedAndInvalid.
- Derived from CoreDNS v1.15.0 plugin/rewrite/name_metadata_test.go TestRegexNameMetadataValues.
- Derived from CoreDNS v1.15.0 plugin/rewrite/name_metadata_test.go.
- Derived from CoreDNS v1.15.0 plugin/rewrite/name_test.go TestNewNameRule.
- Derived from CoreDNS v1.15.0 plugin/rewrite/name_test.go TestRemapStringRewriter.
- Derived from CoreDNS v1.15.0 plugin/rewrite/name_test.go TestRewriteIllegalName.
- Derived from CoreDNS v1.15.0 plugin/rewrite/name_test.go answer tables.
- Derived from CoreDNS v1.15.0 plugin/rewrite/name_test.go.
- Derived from CoreDNS v1.15.0 plugin/rewrite/rcode_test.go TestRCodeRewriteEmptyResponse.
- Derived from CoreDNS v1.15.0 plugin/rewrite/rcode_test.go.
- Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go TestEDNS0ResponseReverterNoOPT.
- Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go TestResponseReverter.
- Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go TestResponseReverterRestoresMissingQuestion.
- Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go TestResponseReverterWriteMsgNilResponse.
- Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go valueTests.
- Derived from CoreDNS v1.15.0 plugin/rewrite/reverter_test.go.
- Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestEdns0MultiRule.
- Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestNewRule.
- Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestRewrite.
- Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestRewriteEDNS0LocalVariable.
- Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestRewriteEDNS0Revert.
- Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go TestRewriteEDNS0Subnet.
- Derived from CoreDNS v1.15.0 plugin/rewrite/rewrite_test.go.
- Derived from CoreDNS v1.15.0 plugin/rewrite/setup_test.go.
- Derived from CoreDNS v1.15.0 plugin/rewrite/ttl_test.go TestNewTTLRule.
- Derived from CoreDNS v1.15.0 plugin/rewrite/ttl_test.go TestTtlRewrite.
- Derived from CoreDNS v1.15.0 plugin/rewrite/ttl_test.go.
