# CoreDNS rewrite test map

Reference: CoreDNS v1.15.0 `plugin/rewrite/*_test.go`. Rust integration tests
exercise the public Plugin/Next contract; `rewrite.rs`, `rewrite_setup.rs`,
`rewrite_edns_port.rs` and `rewrite_cname_port.rs` below are in this directory.

| CoreDNS test | Rust coverage |
| --- | --- |
| `setup_test.go:TestParse` | `rewrite_setup.rs:coredns_rewrite_setup_cases` (all 10 rows) |
| `rewrite_test.go:TestNewRule` | `rewrite_setup.rs:coredns_new_rule_setup_rows`, `coredns_edns_local_setup_cases`, `coredns_edns_variable_setup_cases`, `coredns_edns_nsid_and_subnet_setup_cases`, and `coredns_invalid_utf8_rule_arguments_cannot_enter_str_setup` |
| `rewrite_test.go:TestRewriteDefaultRevertPolicy` | `rewrite.rs:coredns_name_answer_rows` (all 4 rows) |
| `rewrite_test.go:TestRewrite` | `rewrite.rs:coredns_chained_rule_question_rows` (all 14 rows at Next) |
| `rewrite_test.go:TestRewriteEDNS0Local` | `rewrite.rs:coredns_edns_local_append_replace_and_unset` (all 6 rows at Next) |
| `rewrite_test.go:TestEdns0MultiRule` | `rewrite_edns_port.rs:coredns_edns_multiple_rules_rows` (all 18 rows) |
| `rewrite_test.go:TestRewriteEDNS0LocalVariable` | `rewrite.rs:coredns_edns_local_variables_and_metadata` (all 10 rows at Next) |
| `rewrite_test.go:TestRewriteEDNS0Subnet` | `rewrite.rs:coredns_edns_subnet_prefix_rows` (all 6 rows at Next) |
| `rewrite_test.go:TestRewriteEDNS0Revert` | `rewrite_edns_port.rs:coredns_edns_revert_rows` (all 8 rows) |
| `rewrite_test.go:TestRewriteEDNS0Unset` | `rewrite.rs:coredns_edns_local_append_replace_and_unset` (all 10 rows at Next) |
| `rewrite_test.go:TestRewriteEDNS0RevertDoesNotLeakThroughScrubWriter` | `rewrite_edns_port.rs:coredns_revert_survives_listener_scrubbing` (empty answer) |
| `edns0_test.go:TestEdns0LocalSetRevertNoLeak` | `rewrite_edns_port.rs:coredns_revert_survives_listener_scrubbing` (empty original option) |
| `edns0_test.go:TestEdns0LocalSetRevertRestoresPreexisting` | `rewrite_edns_port.rs:coredns_revert_survives_listener_scrubbing` (preexisting option) |
| `ttl_test.go:TestNewTTLRule` | `rewrite_setup.rs:coredns_ttl_setup_cases` (all rows and both modes) |
| `ttl_test.go:TestTtlRewrite` | `rewrite.rs:coredns_ttl_answer_rows` (all 16 rows) |
| `ttl_test.go:TestNewTTLRuleLargeRegex` | `rewrite_setup.rs:coredns_rewrite_rejects_oversized_patterns` |
| `rcode_test.go:TestNewRCodeRule` | `rewrite_setup.rs:coredns_rcode_setup_cases` (all 6 rows and both modes) |
| `rcode_test.go:TestRCodeRewrite` | `rewrite.rs:coredns_rcode_rewrite_updates_extended_opt_code` (SERVFAIL to FORMERR) |
| `rcode_test.go:TestRCodeRewriteEmptyResponse` | `rewrite.rs:coredns_rcode_rewrites_unanswered_response` (all 4 codes and both modes) |
| `rcode_test.go:TestNewRCodeRuleLargeRegex` | `rewrite_setup.rs:coredns_rewrite_rejects_oversized_patterns` |
| `name_test.go:TestRewriteIllegalName` | `rewrite.rs:coredns_illegal_exact_name_is_not_forwarded` |
| `name_test.go:TestRewriteNamePrefixSuffix` | `rewrite.rs:coredns_non_regex_name_rewrite_modes` (all 4 rows at Next) |
| `name_test.go:TestRewriteNameNoRewrite` | `rewrite.rs:coredns_name_answer_rows` (all 5 rows) |
| `name_test.go:TestRewriteNamePrefixSuffixNoAutoAnswer` | `rewrite.rs:coredns_name_answer_rows` (all 5 rows) |
| `name_test.go:TestRewriteNamePrefixSuffixAutoAnswer` | `rewrite.rs:coredns_name_answer_rows` (all 5 rows) |
| `name_test.go:TestRewriteNameExactAnswer` | `rewrite.rs:coredns_name_answer_rows` (all 5 rows) |
| `name_test.go:TestRewriteNameRegexAnswer` | `rewrite.rs:coredns_name_answer_rows` (all 3 rows) |
| `name_test.go:TestNewNameRule` | `rewrite_setup.rs:coredns_name_setup_cases` (all rows, both modes) |
| `name_test.go:TestNewNameRuleLargeRegex` | `rewrite_setup.rs:coredns_rewrite_rejects_oversized_patterns` |
| `name_test.go:TestRemapStringRewriter` | `rewrite.rs:coredns_remap_name_boundary_rows` (six valid DNS names; two impossible names below) |
| `name_metadata_test.go:TestRegexNameMetadata` | `rewrite.rs:coredns_metadata_rewrites_are_per_query_when_concurrent` and `coredns_regex_name_metadata_and_missing_labels` |
| `name_metadata_test.go:TestRegexNameMetadataValues` | `rewrite.rs:coredns_metadata_replacement_rows` (all 6 rows) |
| `name_metadata_test.go:TestRegexNameMetadataConcurrentResponses` | `rewrite.rs:coredns_metadata_rewrites_are_per_query_when_concurrent` (32 queries) |
| `name_metadata_test.go:TestRegexNameMetadataValidation` | `rewrite_setup.rs:coredns_name_metadata_validation` (all 8 invalid replacements and 4 match types) |
| `name_metadata_test.go:TestRegexNameMetadataSkippedAndInvalid` | `rewrite.rs:coredns_metadata_skip_and_invalid_rows` (all 4 rows) |
| `name_metadata_test.go:TestRegexNameMetadataLegacyLiteral` | `rewrite.rs:coredns_legacy_regex_keeps_metadata_label_literal` |
| `reverter_test.go:TestResponseReverter` | `rewrite.rs:coredns_response_reverter_rows` (all 6 fixtures, both modes; see policy note below) |
| `reverter_test.go:TestValueResponseReverter` | `rewrite.rs:coredns_response_value_fixture_rows` (all 7 record fixtures and 4 rule sets; see policy note below) |
| `reverter_test.go:TestEDNS0ResponseReverterNoOPT` | `rewrite_edns_port.rs:coredns_reverter_preserves_no_opt_backend_response` (both rows) |
| `reverter_test.go:TestResponseReverterRestoresMissingQuestion` | `rewrite.rs:coredns_reverter_restores_missing_question_and_answer_name` |
| `reverter_test.go:TestResponseReverterWriteMsgNilResponse` | `rewrite.rs:coredns_reverter_rejects_missing_response_without_panicking` |
| `cname_target_test.go:TestCNameTargetRewrite` | `rewrite_cname_port.rs:coredns_cname_target_rows` (all 8 rows) |
| `cname_target_test.go:TestCNAMETargetRewrite_upstreamFailurePaths` | `rewrite_cname_port.rs:coredns_cname_dropped_lookup_preserves_target` and `rewrite.rs:coredns_cname_lookup_failure_keeps_original_answer` |
| `cname_target_test.go:TestNewCNAMERuleLargeRegex` | `rewrite_setup.rs:coredns_rewrite_rejects_oversized_patterns` |
| `cname_target_test.go:TestNewCNAMERuleNormalization` | `rewrite.rs:coredns_cname_rewrite_follows_target_through_self_lookup` (mixed-case, relative config) |
| `cname_target_test.go:TestCNAMETargetRewriteLoop` | `rewrite.rs:coredns_cname_loop_stops_after_nine_lookups` |

## Public-seam adaptations

- CoreDNS injects `NoRevertPolicy` or `NoRestorePolicy` directly into a Go test
  object. These are not Corefile options. Pharos checks the rewritten Question at
  `Next`, checks the raw backend Response before returning it, and checks the final
  Response using the production restoration policy instead of exposing extra
  configuration solely for tests. In `valueTests` the seven `noRevert` duplicate
  rows share their input fixtures with the seven production-policy rows; their
  unmodified fields are checked at the backend boundary.
- Two `TestNewRule` rows pass an invalid UTF-8 byte directly to a private Go
  constructor. Rust's public parser takes `&str`; the setup test checks those exact
  byte strings cannot enter that seam. This is not a claim about imported Corefile
  byte decoding.
- `TestRemapStringRewriter` includes the raw strings `.example.com.` and `""`.
  Neither is a valid DNS name that can reach the public Plugin contract; the other
  six rows are exercised as record owners.
- A nil Go `*dns.Msg` has no Rust `Outcome` equivalent; an empty Response buffer
  with `Outcome::Response` exercises the corresponding malformed-response error.
- CoreDNS's `TestRewriteEDNS0Revert` appends `fromOpts` to the received Response
  after calling `ServeDNS`; the port does the same rather than treating those as
  input options. Separate tests cover preexisting Query options and scrubbing.
