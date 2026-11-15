# secondary

See the [CoreDNS secondary documentation](https://github.com/coredns/coredns/tree/v1.15.0/plugin/secondary).

## secondary

- Transferred Zones require an apex NS RRset and confine owners to the Zone before publication (RFC 1034 §4.2; RFC 2181 §6.1; for AXFR, see RFC 5936 §3.1).
- The shared Zone lookup may allocate for CNAME or DNAME Self Lookups for missing
  tree names, NS queries, and apex SOA targets; see #86 and the file Plugin notes.
- Zone Transfer streams allocate once per transfer, as in the shared Zone module.
