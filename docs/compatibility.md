# CoreDNS compatibility

## Plugins

Only `whoami` is implemented. Other built-in Directives are disabled by
default; explicitly enabling their Cargo features makes setup fail with a
not-implemented error rather than accepting their configuration.

Whoami reports an error if adding the protocol label would make its SRV owner
name exceed the DNS name length limit. CoreDNS ignores the resulting write
error. The UDP caller must supply a Response buffer with enough capacity;
otherwise Pharos reports an error instead of allocating on the UDP Query path.
TCP allocates the buffer when whoami runs, not while earlier Plugins await.

## Domain names

CoreDNS v1.15.0 uses miekg/dns v1.1.73. Pharos rejects compression
pointers that do not point backwards, while miekg/dns follows them until
its hop limit. Pharos also rejects targets whose encoding overlaps the
pointer; miekg/dns accepts them. Pharos permits up to 255 pointer hops;
miekg/dns permits 126.
Pharos also rejects decimal name escapes above 255 instead of wrapping them
to an octet as miekg/dns does.

## EDNS

The protocol parser rejects duplicate OPT records, OPT records outside
Additional, and non-root OPT owners as invalid Messages intended for FORMERR.
The DNS Listener returns FORMERR for these malformed Messages and drops
short headers. CoreDNS v1.15.0 accepts
them when its header-count policy allows them, and selects the last OPT in
Additional. CoreDNS returns FORMERR on option unpacking errors; HTTP and QUIC
report transport errors. Pharos returns a header-only FORMERR
for malformed Messages, whereas CoreDNS may retain a partially decoded Question.

For pass-through Responses, Pharos truncates the encoded Message without
recompression; CoreDNS may fit more records by recompressing first.
Pharos removes OPT from a Response to a non-EDNS Query, as RFC 6891 requires;
CoreDNS may preserve a Plugin-supplied OPT in that case.
Pharos logs Plugin errors and answers SERVFAIL; CoreDNS ignores returned errors.

Pharos also rejects Client Subnet address lengths that do not match the prefix
and non-zero host bits, which miekg/dns accepts. It validates the supported
typed options and framing; other option codes are passed through without the
additional type-specific validation miekg/dns applies to some of them. Invalid
UTF-8 in Extended DNS Error text is rendered with replacement characters.

## Environment substitution

CoreDNS v1.15.0 (coredns/caddy v1.1.4) re-scans a token after each
`{$VAR}` / `{%VAR%}` replacement, so a value that contains its own
reference loops forever. Pharos reports an error instead, and also stops
after 10,000 replacements or 16 MiB of expanded text.

## Listener

CoreDNS v1.15.0 has no connection cap or per-connection in-flight cap
(`core/dnsserver/server.go`, `tcpMaxQueries = -1`). Pharos limits a Listener
to 1,024 simultaneous TCP connections and 16 in-flight Queries per connection.
Excess connections wait in the TCP backlog; excess Queries wait for a slot.

The default TCP read, write, and idle timeouts are 3, 5, and 10 seconds,
respectively, matching CoreDNS v1.15.0 `core/dnsserver/server.go`.

On Linux, each `sendmmsg` sends one Response (nix-rust/nix#2797).

Lifecycle hooks for a Server Block shared by multiple Listeners run once per
Listener. Explicit Listener shutdown runs shutdown hooks; dropping it cannot
await them. CoreDNS runs lifecycle hooks per configuration instance.
