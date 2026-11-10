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

## EDNS

The protocol parser rejects duplicate OPT records, OPT records outside
Additional, and non-root OPT owners as invalid Messages intended for FORMERR.
Listener-side FORMERR handling is not implemented yet. CoreDNS v1.15.0 accepts
these when its header-count policy allows them, and selects the last OPT in
Additional. CoreDNS's UDP/TCP Listener returns FORMERR on option unpacking
errors; short headers are dropped. HTTP and QUIC report transport errors.

Pharos also rejects Client Subnet address lengths that do not match the prefix
and non-zero host bits, which miekg/dns accepts. It validates the supported
typed options and framing; other option codes are passed through without the
additional type-specific validation miekg/dns applies to some of them. Invalid
UTF-8 in Extended DNS Error text is rendered with replacement characters.

## Record data

The typed RDATA parser currently supports A, AAAA, NS, CNAME, PTR, MX,
SOA, TXT, HINFO, CAA, URI, SRV, NAPTR, DS, CDS, DNSKEY, CDNSKEY, RRSIG,
NSEC, NSEC3, NSEC3PARAM, SVCB, HTTPS, TLSA, SSHFP, ZONEMD and TSIG.
Unsupported name-bearing types are rejected by the typed parser;
other types remain opaque and print in RFC 3597 form rather than using their
CoreDNS presentation. Presentation parsing is not yet implemented. Unlike
miekg/dns, incomplete typed records are rejected rather than accepted as
partial values.

Pharos rejects a zero-length TXT RDATA, which lacks the required character
string; miekg/dns accepts it. TXT strings of length zero are accepted. Pharos
rejects empty and non-alphanumeric CAA tags as required by RFC 8659;
miekg/dns accepts them. CAA and URI presentation follows miekg/dns's
octet-string escaping, including its interpretation of backslashes in wire
values, which can make the displayed value differ from the original octets.
SRV targets and NAPTR replacements may be decoded from compressed names, but
are always written uncompressed. RRSIG signer names and NSEC next names have
the same behavior.

TLSA and SSHFP accept empty tails like miekg/dns's wire decoder and domain
0.12.3. ZONEMD digests shorter than 12 octets are rejected as required by RFC
8976; miekg/dns v1.1.73's `zmsg.go` unpacker accepts them, while domain also
rejects them. TSIG algorithm names accept compression on decode but are written
literally. `Record::display_tsig()` renders the full miekg/dns pseudo-section;
`Rdata` display contains only its data fields.

SVCB and HTTPS targets likewise accept compressed names on decode and are
written uncompressed. Their parameters must be ordered with no duplicate or
reserved keys. As required by RFC 9460 and ADR-0002, mandatory lists must be
nonempty, strictly ordered, and contain neither mandatory itself nor the
reserved key; ALPN IDs must be present and nonempty. miekg/dns v1.1.73
unpacking accepts these malformed mandatory and ALPN values. Domain 0.12.3
wire decoding checks parameter framing and order but not individual values or
the reserved key, so it also accepts empty hints and IPv4-mapped IPv6 hints
that miekg/dns and Pharos reject. Neither cross-key dependencies nor AliasMode
semantics are enforced by this wire codec; consumers must ignore AliasMode
parameters.

NSEC and NSEC3 bitmap windows must be ordered, nonempty, at most 32 octets,
complete, and have a nonzero final octet (RFC 4034 section 4.1.2; ADR-0002).
miekg/dns and domain 0.12.3 accept trailing zero octets and all-zero windows;
domain also accepts duplicate or disordered windows. Both accept empty NSEC
bitmaps; Pharos rejects them but accepts empty NSEC3 bitmaps (RFC 6840 section
6.4).

The SRV and NAPTR fixtures in `crates/pharos-proto/tests/rdata_service.rs`
are adapted from miekg/dns v1.1.73 `parse_test.go` and `dns_test.go`
([BSD-3-Clause](https://github.com/miekg/dns/blob/v1.1.73/LICENSE),
copyright 2009 The Go Authors; extensions copyright 2011 Miek Gieben).
DNSSEC fixtures in `crates/pharos-proto/tests/rdata_dnssec.rs` are adapted from
miekg/dns v1.1.73 `parse_test.go` and `msg_helpers_test.go` under the same license.
SVCB/HTTPS fixtures in `crates/pharos-proto/tests/rdata_svcb.rs` adapt its
`parse_test.go` and `svcb_test.go` under the same license.
Security record fixtures in `crates/pharos-proto/tests/rdata_security.rs`
adapt its `parse_test.go` and `tsig_test.go` under the same license.

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
