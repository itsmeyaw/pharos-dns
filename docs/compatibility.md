# CoreDNS compatibility

## Plugins

Only `whoami` is implemented. Other built-in Directives are disabled by
default; explicitly enabling their Cargo features makes setup fail with a
not-implemented error rather than accepting their configuration.

Whoami reports an error if adding the protocol label would make its SRV owner
name exceed the DNS name length limit. CoreDNS ignores the resulting write
error. The caller must supply a Response buffer with enough capacity; otherwise
Pharos reports an error instead of allocating on the Query path.

## Domain names

CoreDNS v1.15.0 uses miekg/dns v1.1.73. Pharos rejects compression
pointers that do not point backwards, while miekg/dns follows them until
its hop limit. Pharos also rejects targets whose encoding overlaps the
pointer; miekg/dns accepts them. Pharos permits up to 255 pointer hops;
miekg/dns permits 126.
Pharos also rejects decimal name escapes above 255 instead of wrapping them
to an octet as miekg/dns does.

## Environment substitution

CoreDNS v1.15.0 (coredns/caddy v1.1.4) re-scans a token after each
`{$VAR}` / `{%VAR%}` replacement, so a value that contains its own
reference loops forever. Pharos reports an error instead, and also stops
after 10,000 replacements or 16 MiB of expanded text.

## DNS Listener

CoreDNS v1.15.0 defaults to no per-connection Query limit
(`core/dnsserver/server.go`, `tcpMaxQueries = -1`). Pharos also leaves the
total number of Queries per connection unlimited, but limits a Listener to
1,024 simultaneous TCP connections, 256 in-flight TCP Queries overall, and
16 in-flight Queries per connection. Excess connections wait in the TCP
backlog; excess Queries wait until a slot is available.

The default TCP read, write, and idle timeouts are 3, 5, and 10 seconds,
respectively, matching CoreDNS v1.15.0 `core/dnsserver/server.go`. Pharos
drains in-flight Queries on shutdown without CoreDNS's five-second grace
deadline. A Handler that does not return can therefore delay shutdown.

On Linux, receive calls batch up to 16 UDP Queries. Sends currently use
`sendmmsg` one Response at a time: nix 0.31's send-result iterator reads
uninitialized addresses (nix-rust/nix#2797), so it cannot safely report
partial sends for a batch of Responses to different clients.
