# dynupdate

[CoreDNS v1.15.0 dynupdate README](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dynupdate)

## dynupdate

- Seed, stored, and updated Zones require an apex NS RRset and confine owners to the Zone; an update cannot remove the last apex NS (RFC 2181 §6.1; RFC 1034 §4.2).
- Shared Zone CNAME/DNAME Self Lookup allocates for missing Zone-tree names,
  including empty nonterminals, and for NS or apex SOA targets. This matches
  CoreDNS routing but is an exception to the Query allocation rule until #86.
- The `database` file uses the pharos-kv format (#93), not bbolt, so CoreDNS can no longer read it.
  The database opens during startup; failure to open it fails startup or reload rather than retrying on Queries.
  An UPDATE writes only the records it adds or removes, in place, and is answered after the
  write is synced. After a write or sync error the database refuses further updates (SERVFAIL)
  until it is reopened, because a failed `fsync` may have dropped data.
- A bbolt database (including one written by CoreDNS) is converted the first time Pharos opens
  it for serving: the new file replaces the path and the original stays next to it as
  `<database>.bbolt.bak`, with a log line. `pharos check` reads a bbolt file without converting
  it. Conversion refuses to run if `<database>.bbolt.bak` already exists as a different file.
- To roll back to CoreDNS, stop Pharos and put `<database>.bbolt.bak` back. It lacks every UPDATE
  made after the conversion; to keep them, AXFR the Zone and use the export as CoreDNS's seed.
- A database with a damaged header block is refused instead of falling back to the other header, which could silently drop acknowledged updates; restore it from a backup or an AXFR.
- The database file grows when the Zone outgrows its regions; the abandoned regions are not reclaimed.
- A hard link made to the bbolt file before conversion keeps pointing at the old (backup) file;
  link the converted file again.
- After a restart the records of an RRset come back in key order, not insertion order (RFC 2181 §5.2).
- Compaction of the update log runs after the reply; UPDATEs that arrive during the few
  milliseconds it takes wait for it.
- Zone Transfer streams allocate once per transfer, as in the shared Zone code.

## Sources

- CoreDNS v1.15.0 [`plugin/dynupdate`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dynupdate).
- bbolt v1.5.0 [`internal/common`](https://github.com/etcd-io/bbolt/tree/v1.5.0/internal/common), read for conversion only.
