# secondary

See the [CoreDNS secondary documentation](https://github.com/coredns/coredns/tree/v1.15.0/plugin/secondary).

## secondary

- The shared Zone lookup may allocate for CNAME or DNAME Self Lookups for missing
  tree names, NS queries, and apex SOA targets; see #86 and the file Plugin notes.
- Zone Transfer streams allocate once per transfer, as in the shared Zone module.
- Scoped IPv6 NOTIFY sources compare interface indices, so a numeric scope and
  its equivalent interface name can match where CoreDNS compares host text.
