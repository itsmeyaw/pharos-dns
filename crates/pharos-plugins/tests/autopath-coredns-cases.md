# CoreDNS v1.15.0 autopath test mapping

- `TestSetupAutoPath`: `coredns_autopath_setup_cases` covers all seven rows;
  `coredns_resolv_search_order_and_explicit_domain` checks the search order.
- `TestAutoPath`: `coredns_autopath_search_and_passthrough` covers both rows.
- `TestAutoPathNoAnswer` and `TestAutoPathNilMsgFromNext`:
  `coredns_unwritten_replies_keep_the_first_outcome` covers both outcomes.
- `TestInSearchPath`: `coredns_first_search_suffix_membership` covers all four
  names through the Plugin contract. An exact suffix matches, but CoreDNS's
  subsequent `TrimZone` fails; the test checks the resulting error.

Additional tests cover a later Response after a drop, the first positive
Response with a different owner, repeated Directives, case normalization,
provider validation, metrics, verified Kubernetes Pods and allocations.
