# secondary

See the [CoreDNS secondary documentation](https://github.com/coredns/coredns/tree/v1.15.0/plugin/secondary).

## secondary

- The shared Zone lookup may allocate for CNAME or DNAME Self Lookups for missing
  tree names, NS queries, and apex SOA targets; see #86 and the file Plugin notes.
- Zone Transfer streams allocate once per transfer, as in the shared Zone module.
- Pharos extension: `max_records <n>` (default 4000000) and `max_bytes <n>` (default 1073741824, owner
  plus RDATA octets) cap one AXFR. A transfer that exceeds either is rejected with a WARN log, keeping
  the Zone in service. One AXFR must also finish within 10 minutes. CoreDNS has no such bounds.
- A failed NOTIFY-triggered SOA check or transfer enters the RETRY state (RFC 1996 §3.11; RFC 1034 §4.3.5).
- SOA checks and AXFR are not TSIG-signed, matching CoreDNS; RFC 5936 §6 recommends TSIG for AXFR (RFC 8945).
- No IXFR client (RFC 1995): every change costs a full AXFR (RFC 5936).
