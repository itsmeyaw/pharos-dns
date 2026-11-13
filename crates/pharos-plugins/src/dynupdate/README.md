# dynupdate

[CoreDNS v1.15.0 dynupdate README](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dynupdate)

## dynupdate

- Shared Zone CNAME/DNAME Self Lookup allocates for missing Zone-tree names,
  including empty nonterminals, and for NS or apex SOA targets. This matches
  CoreDNS routing but is an exception to the Query allocation rule until #86.
- If a metadata write or its sync fails, later writes to that open database
  return SERVFAIL until all overlapping instances release it and it is reopened.
  The on-disk transaction may have reached the new metadata despite the error;
  this prevents reusing its pages.
- Zone Transfer streams allocate once per transfer, as in the shared Zone code.

## Sources

- CoreDNS v1.15.0 [`plugin/dynupdate`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dynupdate).
- bbolt v1.5.0 [`internal/common`](https://github.com/etcd-io/bbolt/tree/v1.5.0/internal/common) and [`tx.go`](https://github.com/etcd-io/bbolt/blob/v1.5.0/tx.go).
