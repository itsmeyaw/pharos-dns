# CoreDNS compatibility

## Domain names

CoreDNS v1.15.0 uses miekg/dns v1.1.73. Pharos rejects compression
pointers that do not point backwards, while miekg/dns follows them until
its hop limit. Pharos permits up to 255 pointer hops; miekg/dns permits 126.
Pharos also rejects decimal name escapes above 255 instead of wrapping them
to an octet as miekg/dns does.

Unknown opcode and RCODE presentation names use `OPCODE<number>` and
`RCODE<number>`; miekg/dns v1.1.73 renders their numeric values without
these prefixes. Known names and TYPE/CLASS numeric presentation follow its
maps.
