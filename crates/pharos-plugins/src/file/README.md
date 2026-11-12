# file

[CoreDNS v1.15.0 file README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/file/README.md)

## file

- CNAME and synthesized DNAME targets use allocating Self Lookup when the target
  has no Zone-tree record (including out-of-Zone and empty-nonterminal targets),
  for NS Queries, or for SOA Queries targeting the apex. Zone Cut Referrals and
  ordinary locally resolved targets avoid it. This mirrors CoreDNS and includes
  in-Zone exceptions to the no-allocation Query rule until #86 is implemented.
- The current Self Lookup API allocates Query and Response buffers and a recursive
  task/future. Resolving locally instead would bypass the Plugin Chain and can
  change routing or other Plugin behavior; allocation-free re-entry needs #86.

## Sources

- CoreDNS v1.15.0 [`plugin/file/file.go`](https://github.com/coredns/coredns/blob/v1.15.0/plugin/file/file.go), [`setup.go`](https://github.com/coredns/coredns/blob/v1.15.0/plugin/file/setup.go), [`zone.go`](https://github.com/coredns/coredns/blob/v1.15.0/plugin/file/zone.go), and [`lookup.go`](https://github.com/coredns/coredns/blob/v1.15.0/plugin/file/lookup.go).
- CoreDNS v1.15.0 [`plugin/file/reload.go`](https://github.com/coredns/coredns/blob/v1.15.0/plugin/file/reload.go), [`xfr.go`](https://github.com/coredns/coredns/blob/v1.15.0/plugin/file/xfr.go), [`tree/`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/file/tree), and [`*_test.go`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/file).
