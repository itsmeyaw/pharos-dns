# CoreDNS compatibility

## acl

- [acl Plugin notes](../crates/pharos-plugins/src/acl/README.md)

## any

- [any Plugin notes](../crates/pharos-plugins/src/any/README.md)

## auto

- [auto Plugin notes](../crates/pharos-plugins/src/auto/README.md)

## autopath

- [autopath Plugin notes](../crates/pharos-plugins/src/autopath/README.md)

## bind

- [bind Plugin notes](../crates/pharos-plugins/src/bind/README.md)

## bufsize

- [bufsize Plugin notes](../crates/pharos-plugins/src/bufsize/README.md)

## cache

- [cache Plugin notes](../crates/pharos-plugins/src/cache/README.md)

## cancel

- [cancel Plugin notes](../crates/pharos-plugins/src/cancel/README.md)

## chaos

- [chaos Plugin notes](../crates/pharos-plugins/src/chaos/README.md)

## debug

- [debug Plugin notes](../crates/pharos-plugins/src/debug/README.md)

## dns64

- [dns64 Plugin notes](../crates/pharos-plugins/src/dns64/README.md)

## dnssec

- [dnssec Plugin notes](../crates/pharos-plugins/src/dnssec/README.md)

## dynupdate

- [dynupdate Plugin notes](../crates/pharos-plugins/src/dynupdate/README.md)

## errors

- [errors Plugin notes](../crates/pharos-plugins/src/errors/README.md)

## erratic

- [erratic Plugin notes](../crates/pharos-plugins/src/erratic/README.md)

## file

- [file Plugin notes](../crates/pharos-plugins/src/file/README.md)

## secondary

- [secondary Plugin notes](../crates/pharos-plugins/src/secondary/README.md)

## forward

- [forward Plugin notes](../crates/pharos-plugins/src/forward/README.md)

## header

- [header Plugin notes](../crates/pharos-plugins/src/header/README.md)

## health

- [health Plugin notes](../crates/pharos-plugins/src/health/README.md)

## hosts

- [hosts Plugin notes](../crates/pharos-plugins/src/hosts/README.md)

## k8s_external

- [k8s_external Plugin notes](../crates/pharos-plugins/src/k8s_external/README.md)

## kubernetes

- [kubernetes Plugin notes](../crates/pharos-plugins/src/kubernetes/README.md)

## loadbalance

- [loadbalance Plugin notes](../crates/pharos-plugins/src/loadbalance/README.md)

## local

- [local Plugin notes](../crates/pharos-plugins/src/local/README.md)

## log

- [log Plugin notes](../crates/pharos-plugins/src/log/README.md)

## metadata

- [metadata Plugin notes](../crates/pharos-plugins/src/metadata/README.md)

## loop

- [loop Plugin notes](../crates/pharos-plugins/src/loop/README.md)

## minimal

- [minimal Plugin notes](../crates/pharos-plugins/src/minimal/README.md)

## multisocket

- [multisocket Plugin notes](../crates/pharos-plugins/src/multisocket/README.md)

## nsid

- [nsid Plugin notes](../crates/pharos-plugins/src/nsid/README.md)

## prometheus

- [prometheus Plugin notes](../crates/pharos-plugins/src/prometheus/README.md)

## ready

- [ready Plugin notes](../crates/pharos-plugins/src/ready/README.md)

## reload

- [reload Plugin notes](../crates/pharos-plugins/src/reload/README.md)

## rewrite

- [rewrite Plugin notes](../crates/pharos-plugins/src/rewrite/README.md)

## siit

- [siit Plugin notes](../crates/pharos-plugins/src/siit/README.md)

## sign

- [sign Plugin notes](../crates/pharos-plugins/src/sign/README.md)

## tsig

- [tsig Plugin notes](../crates/pharos-plugins/src/tsig/README.md)

## transfer

- [transfer Plugin notes](../crates/pharos-plugins/src/transfer/README.md)

## root

- [root Plugin notes](../crates/pharos-plugins/src/root/README.md)

## shed

- [shed Plugin notes](../crates/pharos-plugins/src/shed/README.md)

## timeouts

- [timeouts Plugin notes](../crates/pharos-plugins/src/timeouts/README.md)

## template

- [template Plugin notes](../crates/pharos-plugins/src/template/README.md)

## view

- [view Plugin notes](../crates/pharos-plugins/src/view/README.md)

## whoami

- [whoami Plugin notes](../crates/pharos-plugins/src/whoami/README.md)

## Expressions and templates

- The shared [expression engine](../crates/pharos-plugins/src/expression/README.md) supports only the documented subset; unsupported expressions fail compilation. Expressions are limited to 1,024 tokens and 16 parse/evaluation levels.
- The shared [template engine](../crates/pharos-plugins/src/gotemplate/README.md) supports only the documented subset. Templates are limited to eight combined action/parenthesis levels and 64 live argument values. All `range` iterations share a 65,535-iteration budget per render, exceeding which returns a render error, unlike CoreDNS; some invalid fields or function arguments fail at render time. Default rendering serializes concurrent renders of the same template; caller-owned scratch permits parallel rendering.

## General

- Only `root`, `cancel`, `timeouts`, `debug`, `shed`, `acl`, `any`, `auto`, `autopath`, `bind`, `bufsize`, `cache`, `chaos`, `dns64`, `dnssec`, `errors`, `erratic`, `file`, `forward`, `header`, `health`, `hosts`, `k8s_external`, `kubernetes`, `loadbalance`, `local`, `log`, `loop`, `metadata`, `minimal`, `multisocket`, `nsid`, `prometheus`, `ready`, `reload`, `rewrite`, `secondary`, `siit`, `sign`, `template`, `transfer`, `tsig`, `view` and `whoami` are implemented. Other built-in Directives are disabled by default; explicitly enabling their Cargo features makes setup fail with a not-implemented error rather than accepting their configuration.
- CoreDNS v1.15.0 (coredns/caddy v1.1.4) re-scans a token after each `{$VAR}` / `{%VAR%}` replacement, so a value that contains its own reference loops forever. Pharos reports an error instead, and also stops after 10,000 replacements or 16 MiB of expanded text.
- A first Zone record with an omitted owner is rejected: miekg/dns accepts it with an empty owner, which cannot be encoded as a valid DNS name without inventing one.
- Zone records whose parsed data cannot be encoded on the wire are rejected. miekg/dns can accept such records during parsing, including invalid base64, duplicate SVCB keys and RDATA over 65,535 octets, but then fails to pack them.
- LOC altitude rounding follows the default Go architecture behavior; an x86-64 Go binary built with `GOAMD64=v3` may fuse floating-point operations and differ at rounding boundaries.

## CLI

- Pharos uses POSIX-style flags rather than CoreDNS's single-dash long flags; legacy spellings report their replacements.
- The Corefile lookup also checks `/etc/pharos/pharos.conf` before `./Corefile`.
- Version and startup banners identify Pharos and include Rust rather than Go build information.
- `--log-format json` switches log lines to JSON; the startup banner stays text.
- SIGUSR2 upgrades are not yet implemented.
- After SIGINT's Shutdown hooks, Pharos drains Listeners before exiting; Caddy exits without calling `Stop()` on SIGINT.
- Exit codes, compared with CoreDNS v1.15.0's `coremain/run.go` and coredns/caddy v1.1.4's `sigtrap.go`, `sigtrap_posix.go` and `caddy.go`: 0 for help, version, Plugin listing, SIGQUIT, or successful shutdown; 1 for configuration, startup, or log-format error; 2 for invalid flag or second SIGINT during shutdown; 3 for Listener stop failure on SIGTERM (Caddy's `Stop()` currently always returns nil); 4 for Shutdown hook failure.

## Logging

- Pharos writes UTC RFC3339 timestamps, unbracketed levels and Plugin names to stdout; CoreDNS uses the Go logger's date and time and bracketed levels such as `[INFO] plugin/x:`.
- Pharos also supports JSON lines selected at startup.

## Metrics

- Pharos exports the six core process metrics on Linux when their `/proc` data is available.
- On macOS it exports the open-file count; other process metrics are omitted.
- CoreDNS's Prometheus Go client also collects process metrics on macOS.
- Pharos does not export Go runtime metrics.
- The build information label `goversion` is named `rustc` in Pharos.
- The current Listener reports the encoded Query size; CoreDNS's metrics Plugin reports the decoded Message length.
- Malformed Messages that cannot be parsed are not counted.
- View names are currently empty, and a wildcard Listener is labelled as an unbound address even when explicitly bound to an unspecified IP.
- Plugin attribution identifies the Plugin that returned the Response; CoreDNS's nested writers can attribute the outer Plugin instead.
- Pharos counts dropped Queries only on a Listener with at least one `prometheus` Server Block; CoreDNS's server-level error reporting counts them unconditionally.
- Concurrent scrapes can observe histogram buckets and sums at slightly different instants, unlike the Go client's synchronized histogram snapshot.

## Server

- View-aware routing and metrics perform per-Query dispatch checks and initialize Metadata before routing even when no View is configured; no View filters run in that case.
- The Rust `Server` API stores its Router in an `Arc`; callers adding blocks after construction must obtain unique access with `Arc::get_mut`.
- The Rust Plugin API's `Context` has separate Query and Metadata lifetimes to support allocation-free internal Query rewrites.
- Without `multisocket`, Pharos uses the CPU-quota-aware worker count for UDP; CoreDNS uses one socket.
- CoreDNS v1.15.0 uses miekg/dns v1.1.73.
- TSIG accepts RFC 8945-permitted truncated MACs and enforces their minimum length and optional local policy; miekg/dns v1.1.73's default provider compares only full-length MACs.
- TSIG rejects misplaced, duplicate, non-ANY, nonzero-TTL, or malformed TSIG records and compressed algorithm names; miekg/dns does not enforce all of these checks.
- TSIG maps an unsupported algorithm on a known key to BADSIG, as CoreDNS does, rather than RFC 8945's BADKEY. Each `TsigKey` is pinned to one supported algorithm; CoreDNS accepts any supported algorithm for a configured secret.
- Stream verification includes unsigned intermediate Messages in the running MAC and requires signed first and last Messages, following RFC 8945; miekg/dns does not accumulate unsigned intermediates.
- Subsequent stream TSIGs with an Error or Other Data are rejected because those fields are not authenticated by the stream MAC; miekg/dns does not reject them.
- Stream signatures reject decreasing Time Signed values; miekg/dns does not track previous times. The stream API also permits callers to feed unsigned intermediate Messages for legacy interoperability, although RFC 8945 requires senders to sign every Response.
- TSIG uses the supplied zero Time Signed or Fudge literally; miekg/dns substitutes the current time or 300 seconds. Signed NOTAUTH Responses can be verified by Pharos, whereas miekg/dns rejects NOTAUTH before checking the MAC.
- BADTIME Responses retain the Query's Fudge as RFC 8945 requires; CoreDNS's TSIG Plugin defaults it to 300 seconds.
- TSIG error Responses retain the Query TSIG's Original ID; CoreDNS's TSIG Plugin uses the Response header ID.
- TSIG key-file parsing takes UTF-8 input, reads lines beyond Go's 64 KiB scanner limit, and uses Rust Unicode lowercasing, which can differ from Go for names such as a word-final capital sigma. CoreDNS can silently stop reading an overlong key-file line.
- TSIG Response signing and verification require a valid-length Query MAC. The RFC 8945 exception for a signed Response to an unsigned TKEY Query is not supported by this API; miekg/dns allows generating a Response without a Query MAC.
- Pharos rejects compression pointers that do not point backwards, while miekg/dns follows them until its hop limit.
- Pharos also rejects targets whose encoding overlaps the pointer; miekg/dns accepts them.
- Pharos permits up to 255 pointer hops; miekg/dns permits 126.
- Pharos also rejects decimal name escapes above 255 instead of wrapping them to an octet as miekg/dns does.
- The protocol parser rejects duplicate OPT records, OPT records outside Additional, and non-root OPT owners as invalid Messages intended for FORMERR.
- The DNS Listener returns FORMERR for these malformed Messages and drops short headers. CoreDNS v1.15.0 accepts them when its header-count policy allows them, and selects the last OPT in Additional.
- CoreDNS returns FORMERR on option unpacking errors; HTTP and QUIC report transport errors.
- Pharos returns a header-only FORMERR for malformed Messages, whereas CoreDNS may retain a partially decoded Question.
- For a header-only Message claiming one Question, Pharos returns FORMERR; CoreDNS returns SERVFAIL.
- For pass-through Responses, Pharos truncates the encoded Message without recompression; CoreDNS may fit more records by recompressing first.
- If an OPT precedes other Additional records, Pharos drops the following records and sets TC rather than shifting their compression pointers.
- Pharos removes OPT from a Response to a non-EDNS Query, as RFC 6891 requires; CoreDNS may preserve a Plugin-supplied OPT in that case.
- Pharos answers Plugin errors with SERVFAIL. CoreDNS ignores returned errors and bases the Response on the separately returned RCODE; without `errors` it does not log ordinary chain errors. Pharos likewise logs those errors only when `errors` is configured, while logging recovered panics at the Listener.
- A UDP IXFR that reaches a Zone Transfer stream returns the current SOA only, following RFC 1995 §2; CoreDNS's `transfer` returns REFUSED instead.
- The AXFR client API supports TSIG; CoreDNS v1.15.0's `secondary` does not sign transfer requests, even when a TSIG key is configured. Pharos's `secondary` Plugin matches this.
- Signed transfer producers must leave room for TSIG within the 65,535-octet Message limit; otherwise the Listener closes the connection rather than emitting an unsigned Message.
- Pharos also rejects Client Subnet address lengths that do not match the prefix and non-zero host bits, which miekg/dns accepts. It validates the supported typed options and framing; other option codes are passed through without the additional type-specific validation miekg/dns applies to some of them.
- Invalid UTF-8 in Extended DNS Error text is rendered with replacement characters.
- The requested record-data families are complete: the typed RDATA parser supports A, AAAA, NS, CNAME, PTR, MX, SOA, TXT, HINFO, CAA, URI, SRV, NAPTR, DS, CDS, DNSKEY, CDNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, SVCB, HTTPS, TLSA, SSHFP, ZONEMD and TSIG.
- Unsupported name-bearing types are rejected by the typed parser; other types remain opaque, preserve their bytes and print in RFC 3597 form rather than using their CoreDNS presentation.
- Zone-file presentation parsing is separate from the wire RDATA parser.
- A record without RDATA (for example `www IN A`, `www IN TXT` or `www IN MX`) is rejected with its line and column (RFC 1035 §5.1). miekg/dns accepts it and packs empty or zero-filled RDATA, its form for dynamic update records, so such a Zone file loads in CoreDNS and serves malformed answers. Write `\# 0` (RFC 3597 §5) where an empty RDATA is meant; APL may still hold zero items (RFC 3123 §4).
- A record missing trailing RDATA fields is rejected (RFC 1035 §3.3.13, RFC 6698 §2.1, RFC 4255 §3.1). miekg/dns zero-fills a SOA's missing serial and timers, and accepts TLSA and SSHFP without association data or fingerprint. When a record lacks its last field and another line follows, miekg/dns takes that line's first item as the field (`a IN MX 2` then `b` reads as `a IN MX 2 b`).
- A comment may touch the item before it (RFC 1035 §5.1), so `a 60 TXT;c` followed by RDATA inside parentheses reads `TXT` as the type. miekg/dns does not recognize a type mnemonic directly before `;` and rejects the record. After a comment inside parentheses, miekg/dns also reads a following class or type mnemonic as a header field and rejects the record; Pharos reads it as RDATA.
- An empty APL written as `TYPE42` at the end of a line is accepted (RFC 3123 §4, RFC 3597 §5). miekg/dns rejects it because its lexer does not recognize numeric type mnemonics at a newline; adding a space after `TYPE42` works.
- An unmatched `)` is always rejected. miekg/dns ignores it at the end of an NSEC, NSEC3 or CSYNC type bitmap and drops the item touching it (`NSEC = A x)` gives bitmap `A`).
- Pharos rejects a name ending in a lone backslash (RFC 1035 §5.1); miekg/dns accepts it in names and X25 data but rejects it in TXT data. It also skips the 63-octet label check (RFC 1035 §2.3.4) for a final label ending that way.
- A lone HINFO or ISDN string containing an escaped blank (`HINFO \ b`) is rejected: miekg/dns splits it at the blank, leaving a lone backslash that it accepts as an empty string, while Pharos rejects the lone backslash (RFC 1035 §5.1).
- Type bitmaps require known type mnemonics or `TYPE` followed by a decimal code (RFC 3597 §5). miekg/dns accepts a token with any first four bytes when its remaining bytes are a decimal code, for example `I2000` as `TYPE0` in NXT RDATA (`scan.go:typeToInt`).
- Escapes in a `$GENERATE` template keep their RFC 1035 §5.1 meaning: `\t` is `t` and `\065` is `A`. miekg/dns drops the escaped character (`\t` becomes nothing, `\065` becomes `65`) and rejects `\\`; only `\$` matches.
- An unterminated quote is always rejected. miekg/dns accepts one in a `$GENERATE` template, copying the following lines into the generated RDATA, and one touching the previous item in the last record of the file (`w IN HTTPS 0" `).
- A quoted string where a domain name is expected is rejected. miekg/dns accepts `""` followed by a blank in MINFO RDATA and reads the quote and blank characters as names.
- Numeric RDATA fields decode valid escapes before parsing (RFC 1035 §5.1): `MX \049\048 a` is `MX 10 a`. A malformed escape, a backslash with one or two digits such as `\9`, is rejected there. miekg/dns rejects any backslash in a numeric field.
- A Zone file without a final newline is parsed as if it had one. miekg/dns treats an incomplete last line differently at end of file: it accepts `www` or `www IN A ` (dropping the line or emitting empty RDATA) and rejects `www IN A`, the reverse of its result when the line ends with a newline. Complete last lines parse the same. miekg/dns re-parses each `$GENERATE` template the same way, so it also accepts incomplete templates such as `$GENERATE 1-1 a\\` that Pharos rejects.
- Unlike miekg/dns, incomplete typed records are rejected rather than accepted as partial values.
- Pharos rejects a zero-length TXT RDATA, which lacks the required character string; miekg/dns accepts it. TXT strings of length zero are accepted.
- Pharos rejects empty and non-alphanumeric CAA tags as required by RFC 8659; miekg/dns accepts them.
- CAA and URI presentation follows miekg/dns's octet-string escaping, including its interpretation of backslashes in wire values, which can make the displayed value differ from the original octets.
- SRV targets and NAPTR replacements may be decoded from compressed names, but are always written uncompressed. RRSIG signer names and NSEC next names have the same behavior.
- TLSA and SSHFP accept empty tails like miekg/dns's wire decoder and domain 0.12.3.
- ZONEMD digests shorter than 12 octets are rejected as required by RFC 8976; miekg/dns v1.1.73's `zmsg.go` unpacker accepts them, while domain also rejects them.
- TSIG algorithm names accept compression on decode but are written literally.
- `Record::display_tsig()` renders the full miekg/dns pseudo-section; `Rdata` display contains only its data fields.
- SVCB and HTTPS targets likewise accept compressed names on decode and are written uncompressed. Their parameters must be ordered with no duplicate or reserved keys.
- As required by RFC 9460 and ADR-0002, mandatory lists must be nonempty, strictly ordered, and contain neither mandatory itself nor the reserved key; ALPN IDs must be present and nonempty. miekg/dns v1.1.73 unpacking accepts these malformed mandatory and ALPN values.
- Domain 0.12.3 wire decoding checks parameter framing and order but not individual values or the reserved key, so it also accepts empty hints and IPv4-mapped IPv6 hints that miekg/dns and Pharos reject.
- Neither cross-key dependencies nor AliasMode semantics are enforced by this wire codec; consumers must ignore AliasMode parameters.
- NSEC and NSEC3 bitmap windows must be ordered, nonempty, at most 32 octets, complete, and have a nonzero final octet (RFC 4034 section 4.1.2; ADR-0002). miekg/dns and domain 0.12.3 accept trailing zero octets and all-zero windows; domain also accepts duplicate or disordered windows. Both accept empty NSEC bitmaps; Pharos rejects them but accepts empty NSEC3 bitmaps (RFC 6840 section 6.4).
- CoreDNS v1.15.0 has no connection cap or per-connection in-flight cap (`core/dnsserver/server.go`, `tcpMaxQueries = -1`). Pharos limits a Listener to 1,024 simultaneous TCP connections and 16 in-flight Queries per connection. Excess connections wait in the TCP backlog; excess Queries wait for a slot.
- The default TCP read, write, and idle timeouts are 3, 5, and 10 seconds, respectively, matching CoreDNS v1.15.0 `core/dnsserver/server.go`.
- On Linux, each `sendmmsg` sends one Response (nix-rust/nix#2797).
- Self Lookup is limited to 10 nested Self Lookups; CoreDNS v1.15.0 does not enforce a depth limit. This prevents unbounded recursion, for example from a cycle of ExternalName Services. Exceeding the limit returns a Plugin error, normally answered with SERVFAIL.
- Copying a Query for Self Lookup re-encodes its records. It fails if RDATA is malformed, contains an unsupported name-bearing type, or the resulting Message exceeds 65,535 bytes; CoreDNS copies its decoded Message instead.
