# CoreDNS compatibility

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
