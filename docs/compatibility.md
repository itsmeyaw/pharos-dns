# CoreDNS compatibility

## Binary

Pharos uses POSIX-style flags rather than CoreDNS's single-dash long flags;
legacy spellings report their replacements. The Corefile lookup also checks
`/etc/pharos/pharos.conf` before `./Corefile`. Version and startup banners
identify Pharos and include Rust rather than Go build information.

`--log-format json` switches log lines to JSON; the startup banner stays text.
SIGUSR1 logs `SIGUSR1: Reloading` but does not replace the configuration
until M1. SIGUSR2 upgrades are not yet
implemented. After SIGINT's Shutdown hooks, Pharos drains Listeners before
exiting; Caddy exits without calling `Stop()` on SIGINT.

Exit codes, compared with CoreDNS v1.15.0's `coremain/run.go` and
coredns/caddy v1.1.4's `sigtrap.go`, `sigtrap_posix.go` and `caddy.go`:

| Code | Meaning |
| --- | --- |
| 0 | Help, version, Plugin listing, SIGQUIT, or successful shutdown |
| 1 | Configuration, startup, or log-format error |
| 2 | Invalid flag or second SIGINT during shutdown |
| 3 | Listener stop failure on SIGTERM (Caddy's `Stop()` currently always returns nil) |
| 4 | Shutdown hook failure |

## Logging

Pharos writes UTC RFC3339 timestamps, unbracketed levels and Plugin names to
stdout; CoreDNS uses the Go logger's date and time and bracketed levels such
as `[INFO] plugin/x:`. Pharos also supports JSON lines selected at startup.
The `log` Plugin's body uses CoreDNS's common format by default, preceded by
Pharos's timestamp and `INFO log:` rather than CoreDNS's `[INFO]` prefix.
JSON entries use Pharos's generic log fields rather than CoreDNS's access-log
fields.
`{local}` reports the configured Listener address; for wildcard Listeners it
does not report the connection's actual local address. For unanswered errors,
the logged Response size includes the Listener's synthesized EDNS OPT, whereas
CoreDNS's logging-only synthetic Message has no OPT. For a returned Response,
`{rsize}` is the size before truncation, as in CoreDNS. `{rflags}` also
describes the Message before truncation; CoreDNS scrubs its recorded Message
in place, so its `{rflags}` shows `tc` when the Listener truncates. A Drop is logged with `-` RCODE and flags and zero size; a
Plugin error is logged as a synthesized SERVFAIL. Zone Transfer streams are
not yet served and are logged as a Message-less outcome. The formatter cannot
expand compressed names in unsupported RDATA when calculating Message size.

## Process metrics

Pharos exports the six core process metrics on Linux when their `/proc` data
is available. On macOS it exports the open-file count; other process metrics
are omitted. CoreDNS's Prometheus Go client also collects process metrics on
macOS. Pharos does not export Go runtime metrics.
The build information label `goversion` is named `rustc` in Pharos.

## DNS metrics

The current Listener reports the encoded Query size; CoreDNS's metrics Plugin
reports the decoded Message length. Malformed Messages that cannot be parsed
are not counted. View names
are currently empty, and a wildcard Listener is labelled as an unbound address
even when explicitly bound to an unspecified IP. Plugin attribution identifies
the Plugin that returned the Response; CoreDNS's nested writers can attribute
the outer Plugin instead.
Pharos counts dropped Queries only on a Listener with at least one `prometheus`
Server Block; CoreDNS's server-level error reporting counts them unconditionally.
Concurrent scrapes can observe histogram buckets and sums at slightly different
instants, unlike the Go client's synchronized histogram snapshot.

## Plugins

Only `forward`, `health`, `log`, `prometheus`, `ready` and `whoami` are implemented. Other built-in Directives are
disabled by default; explicitly enabling their Cargo features makes setup fail with a
not-implemented error rather than accepting their configuration.

The `prometheus` Directive accepts `runtime_metrics`, but has no effect: Go
runtime metrics do not exist in Pharos. The `tls` option is parsed, but any
TLS configuration fails startup rather than silently serving unprotected HTTP;
Prometheus exporter-toolkit TLS and authentication are not implemented.
Blocks sharing a metrics address must use the same TLS configuration. Metrics
HTTP connections are capped at five seconds total, rather than CoreDNS's
separate per-request read, write and idle deadlines, and at 1,024 simultaneous
connections. Only GET requests are served at `/metrics`; other HTTP methods
return 404. Pharos requires a numeric metrics port at startup; CoreDNS can
also resolve service names supported by the host.
Bind and startup errors are reported, whereas CoreDNS's shared Listener setup
currently discards errors from its `uniq.ForEach` callback.

The `ready` endpoint serves GET only; CoreDNS also accepts other methods.
HTTP connections use the same five-second total lifetime and 1,024-connection
limit as the metrics endpoint. Pharos requires numeric ports at startup and
reports bind errors; CoreDNS supports service names and currently discards
errors from shared Listener startup. Pharos does not log unready Plugin names
on every readiness request. Reload is not implemented, so readiness state is
not reset by SIGUSR1.

During Lameduck Pharos keeps `/ready` available with 503 `Shutting down`.
CoreDNS v1.15.0 normally closes the readiness Listener before the health
Lameduck delay, so subsequent requests fail to connect instead.

Health addresses are shared once per exact configured address, using the
first Lameduck duration; CoreDNS creates one Listener and probe per Server
Block and can share ports using SO_REUSEPORT. Pharos reports bind errors,
requires numeric ports, and uses the HTTP connection limits described above.
Unlike Go's ServeMux, it does not redirect unclean paths or decode escaped path
segments, and its 404 responses omit Go's `X-Content-Type-Options` header. The
self-probe opens a fresh connection for every check and exports classic
histogram buckets, not Prometheus native histogram samples.

Whoami reports an error if adding the protocol label would make its SRV owner
name exceed the DNS name length limit. CoreDNS ignores the resulting write
error. The UDP caller must supply a Response buffer with enough capacity;
otherwise Pharos reports an error instead of allocating on the UDP Query path.

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
For a header-only Message claiming one Question, Pharos returns FORMERR;
CoreDNS returns SERVFAIL.

For pass-through Responses, Pharos truncates the encoded Message without
recompression; CoreDNS may fit more records by recompressing first.
If an OPT precedes other Additional records, Pharos drops the following
records and sets TC rather than shifting their compression pointers.
Pharos removes OPT from a Response to a non-EDNS Query, as RFC 6891 requires;
CoreDNS may preserve a Plugin-supplied OPT in that case.
Pharos logs Plugin errors and answers SERVFAIL; CoreDNS ignores returned errors.
Zone Transfer streams are not yet served by the Listener.

Pharos also rejects Client Subnet address lengths that do not match the prefix
and non-zero host bits, which miekg/dns accepts. It validates the supported
typed options and framing; other option codes are passed through without the
additional type-specific validation miekg/dns applies to some of them. Invalid
UTF-8 in Extended DNS Error text is rendered with replacement characters.

## Record data

The requested record-data families are complete: the typed RDATA parser supports
A, AAAA, NS, CNAME, PTR, MX, SOA, TXT, HINFO, CAA, URI, SRV, NAPTR, DS, CDS,
DNSKEY, CDNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, SVCB, HTTPS, TLSA, SSHFP,
ZONEMD and TSIG.
Unsupported name-bearing types are rejected by the typed parser;
other types remain opaque, preserve their bytes and print in RFC 3597 form
rather than using their CoreDNS presentation. Presentation parsing is deferred
to the zone-file parsing issue (see the existing `shortcut:` comment in
`rdata.rs`). Unlike miekg/dns, incomplete typed records are rejected rather
than accepted as partial values.

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

## Upstream proxy

Plain UDP and TCP Upstream exchange is available for `forward`.
DNS-over-TLS is reserved for M3. The proxy retries a truncated UDP Response over TCP only
when `prefer_udp` is set, as CoreDNS's `forward` does.

Idle sockets are swept across shards at most once per expiry interval on Query
traffic. Unlike CoreDNS’s periodic cleanup, an idle Proxy retains expired
sockets until another Query or shutdown. Upstream TSIG Messages retain their
original ID rather than rewriting the signed Message. Proxy metric RCODE
series are initialized on first observation, allocating once per distinct RCODE.
Connections rotate FIFO within each worker shard rather than in
one global FIFO.

## Forward

Encrypted Upstreams (`tls://`, `quic://` and `https://`) and `tls` or
`tls_servername` options fail setup rather than silently downgrade; TLS is
deferred to M3. Hostname Upstreams resolve at setup using the system resolver
or the configured `resolver`. `doh_method` has no effect on plain DNS.
Upstream and resolver ports must be numeric and fit in 16 bits; CoreDNS can
also accept service names and out-of-range ports at setup.
Like CoreDNS, IPv6 scopes are stripped from numeric Upstreams, including
resolv.conf entries. Non-IP nameservers from resolv.conf are retained, but
currently fail without health probes rather than being resolved at dial time as
in CoreDNS. Numeric Upstreams are deduplicated by normalized socket address;
CoreDNS preserves textual address spelling and distinct scopes in its keys.
Some option argument and
Domain edge cases remain more restrictive than CoreDNS. Upstream Metadata
uses the normalized numeric socket address, which may differ from CoreDNS's
configured address text. Health checks start on exchange failure, and proxy
connections and checks are stopped on Shutdown.
Forward reuses Upstream Response buffers from a pool; a new buffer is allocated
when concurrent Queries exceed the pool's previous high-water mark, and the pool
retains that peak allocation until the Plugin is dropped.
