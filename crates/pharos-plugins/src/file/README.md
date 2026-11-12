# file

See [CoreDNS file](https://coredns.io/plugins/file/).

## file

- CNAME Self Lookup allocates per Query until #86 is implemented.
- `reload_by_mtime` records the opened file's modification time. CoreDNS stats
  the path before opening it, so a replacement between those operations can
  cause an extra reload and NOTIFY.
