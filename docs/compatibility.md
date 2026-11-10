# CoreDNS compatibility

## Domain names

CoreDNS v1.15.0 uses miekg/dns v1.1.73. Pharos rejects compression
pointers that do not point backwards, while miekg/dns follows them until
its hop limit. Pharos permits up to 255 pointer hops; miekg/dns permits 126.
Pharos also rejects decimal name escapes above 255 instead of wrapping them
to an octet as miekg/dns does.

## Message truncation

For size-limited Messages, Pharos sets TC when it cannot fit a Question or
an Answer or Authority record. If an Additional record cannot fit, Pharos
omits the entire Additional section without setting TC (preserving an
existing TC), so no optional Additional RRset is left partial. CoreDNS
v1.15.0 uses miekg/dns v1.1.73 `Msg.Truncate`, which retains individual
records and sets TC for omitted Additional records too. Pharos follows
RFC 2181 section 9 for optional additional data; it does not yet classify
records that are required in Additional (such as EDNS, covered by #11).

Unknown opcode and RCODE presentation names use `OPCODE<number>` and
`RCODE<number>`; miekg/dns v1.1.73 renders their numeric values without
these prefixes. Known names and TYPE/CLASS numeric presentation follow its
maps.
