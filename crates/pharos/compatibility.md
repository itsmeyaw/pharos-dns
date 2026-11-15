# CoreDNS compatibility

## acl

- [acl Plugin notes](../crates/pharos-plugins/src/acl/README.md)

## any

- [any Plugin notes](../crates/pharos-plugins/src/any/README.md)

## auto

- [auto Plugin notes](../crates/pharos-plugins/src/auto/README.md)
- RFC 4343 §3: Auto uses case-insensitive name matching; no case-dependent Zone Cut logic remains.

## autopath

- [autopath Plugin notes](../crates/pharos-plugins/src/autopath/README.md)

## bind

- [bind Plugin notes](../crates/pharos-plugins/src/bind/README.md)
- RFC 5625 §6.2: the default listener uses an unspecified address and can expose a `forward` proxy on every interface; configure `bind` to restrict listener addresses (conf/infra #105).

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
- Seed, stored, and candidate dynamic Zones require apex NS (RFC 2181 §6.1). The server ignores a final-apex-NS deletion (RFC 2136 §3.4.2.4; §2.5.4 defines single-RR deletion syntax).
- Before upgrading a persistent NS-less database:
  1. Back up the database.
  2. Run the previous build and UPDATE to add apex NS; if UPDATE is unavailable, AXFR the full Zone, add apex NS to the export, and recreate the database from it.
  3. Verify apex NS, then upgrade. Alternatively, recreate the database from a corrected complete seed.
  Startup fails fast rather than load-with-warning; the error names the database path and repair. Serving an NS-less authoritative Zone violates RFC 2181 §6.1.

## errors

- [errors Plugin notes](../crates/pharos-plugins/src/errors/README.md)

## erratic

- [erratic Plugin notes](../crates/pharos-plugins/src/erratic/README.md)

## file

- [file Plugin notes](../crates/pharos-plugins/src/file/README.md)
- Pharos intentionally differs from CoreDNS where RFC-conformant Zone behavior requires it:
  - Zone construction requires apex NS and confines owners to the Zone (RFC 1034 §4.2; RFC 2181 §6.1; for AXFR, see RFC 5936 §3.1). CoreDNS v1.15.0's file parser checks SOA ownership but does not require apex NS.
  - At an apex, conflicting ZONEMD records with the same Scheme/Hash Algorithm are rejected, while identical duplicates are deduplicated (RFC 8976 §2.5); CoreDNS v1.15.0 retains duplicate tree entries.
  - QCLASS=ANY Zone replies can contain selected-class records but clear AA; CoreDNS v1.15.0 keeps file replies authoritative (RFC 1035 §6.2).
  - An apex query for an absent type returns NOERROR/NODATA with the SOA (RFC 2308 §2.2); CoreDNS v1.15.0 returns NXDOMAIN for an SOA/NS-only apex.
  - Master-file loading rejects multiple SOAs, CNAME RRsets with multiple targets, and DNAME descendant data; CoreDNS retains the last SOA and can retain conflicting aliases.
  - Pharos stops an NS-QTYPE CNAME chain after one alias before target referral processing; RFC 1034 §3.6.2 otherwise restarts for QTYPEs other than CNAME.
  - DNAME substitution restarts at its target even for QTYPE=ANY (RFC 6672 §3.2); a target CNAME then answers ANY without another restart (RFC 1034 §§3.4.1, 3.6.2).
  - SOA serial 0 is valid for initial load and refresh (RFC 1982 §7); CoreDNS's file loader uses 0 as its initial no-change sentinel.
  - When an SVCB/HTTPS RRset contains AliasMode and ServiceMode, Zone queries ignore ServiceMode records as RFC 9460 §2.4.1 requires; CoreDNS can return the mixed RRset.
  - Overlong DNAME substitution returns YXDOMAIN with exactly one DNAME and no Self Lookup (RFC 6672 §2.2); the older Pharos path returned SERVFAIL and could recurse through Self Lookup.

## secondary

- [secondary Plugin notes](../crates/pharos-plugins/src/secondary/README.md)
- AXFR snapshots without apex NS or with out-of-zone owners are rejected before publish (RFC 1034 §4.2; RFC 2181 §6.1; see RFC 5936 §3.1 for AXFR processing); CoreDNS v1.15.0's file Zone insertion does not enforce those boundaries.

## forward

- [forward Plugin notes](../crates/pharos-plugins/src/forward/README.md)

## header

- [header Plugin notes](../crates/pharos-plugins/src/header/README.md)

## health

- [health Plugin notes](../crates/pharos-plugins/src/health/README.md)

## hosts

- [hosts Plugin notes](../crates/pharos-plugins/src/hosts/README.md)
- RFC 4592 §§2.2.1, 3.3: `hosts` replaces only the leftmost QNAME label for wildcard lookup and does not search closest-encloser ancestors, matching CoreDNS v1.15.0 (ADR 0002).
- RFC 1035 §6.2 / RFC 2308 §2: `hosts` answers positive QCLASS=ANY hits with selected IN data and AA clear; missing/negative names pass through instead of asserting denial from IN-only data. A terminal miss maps to SERVFAIL ([Listener mapping](../pharos-server/src/server.rs#L583)), matching CoreDNS v1.15.0's unmapped-host response; CoreDNS leaves AA set on positive answers.

## k8s_external

- [k8s_external Plugin notes](../crates/pharos-plugins/src/k8s_external/README.md)

## kubernetes

- [kubernetes Plugin notes](../crates/pharos-plugins/src/kubernetes/README.md)

## loadbalance

- [loadbalance Plugin notes](../crates/pharos-plugins/src/loadbalance/README.md)

## local

- [local Plugin notes](../crates/pharos-plugins/src/local/README.md)
- RFC 1035 §6.2 / RFC 2308 §2: `local` answers positive QCLASS=ANY hits with selected IN data and AA clear; negative/NODATA cases pass through rather than asserting a denial from IN-only data. A terminal pass-through maps to SERVFAIL ([Listener mapping](../pharos-server/src/server.rs#L583)); this matches CoreDNS for names outside intercepted zones. For recognized `localhost.` NODATA, CoreDNS returns a synthetic SOA instead.

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
- The signer rejects source Zones without apex NS or with out-of-zone owners, following the shared Zone invariant (RFC 2181 §6.1; RFC 1034 §4.2).

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
- RFC 1034 §§3.4.1, 3.6.2: template CNAME targets restart for every QTYPE except CNAME and ANY; CoreDNS v1.15.0 restarts only A/AAAA ([`plugin/template/template.go`](https://github.com/coredns/coredns/blob/v1.15.0/plugin/template/template.go)).
- RFC 2308 §3: an authoritative NXDOMAIN template SOA is placed in Authority even if configured as Answer; CoreDNS v1.15.0 keeps the configured section ([`plugin/template/template.go`](https://github.com/coredns/coredns/blob/v1.15.0/plugin/template/template.go)).
- RFC 2308 §§2.2, 3: Pharos moves a configured NODATA SOA from Answer to Authority; CoreDNS v1.15.0 preserves the configured section ([`plugin/template/template.go`](https://github.com/coredns/coredns/blob/v1.15.0/plugin/template/template.go)). Positive QTYPE=SOA answers stay in Answer.
- RFC 1035 §6.2: QCLASS=ANY template replies can contain selected-class records but clear AA; CoreDNS v1.15.0 marks template replies authoritative.

## view

- [view Plugin notes](../crates/pharos-plugins/src/view/README.md)

## whoami

- [whoami Plugin notes](../crates/pharos-plugins/src/whoami/README.md)

## Expressions and templates

- The shared [expression engine](../crates/pharos-plugins/src/expression/README.md) supports only the documented subset; unsupported expressions fail compilation. Expressions are limited to 1,024 tokens and 16 parse/evaluation levels.
- The shared [template engine](../crates/pharos-plugins/src/gotemplate/README.md) supports only the documented subset. Templates are limited to eight combined action/parenthesis levels and 64 live argument values. All `range` iterations share a 65,535-iteration budget per render, exceeding which returns a render error, unlike CoreDNS; some invalid fields or function arguments fail at render time. Default rendering serializes concurrent renders of the same template; caller-owned scratch permits parallel rendering.

## General

- Deviation policy: ADR 0003 governs Corefile key/import semantics (CoreDNS behavior wins); ADR 0002 governs RFC behavior (RFCs win unless deployment reliance is evidenced).
- CoreDNS v1.15.0 uses miekg/dns v1.1.73, whose `IsDomainName` accepts four 63-octet labels with `off == 256`; `off` excludes root, so wire name is 257 octets (`defaults.go`). Pharos rejects it under RFC 1035 §2.3.4 per ADR 0002; no DNS Message can carry it.
- CoreDNS v1.15.0's `plugin.SplitHostPort` caps server-block key presentation at 255 bytes before DNS wire-length validation (`plugin/normalize.go`, `core/dnsserver/register.go`). Pharos preserves this under ADR 0003 (CoreDNS wins), so some RFC 1035 §2.3.4-valid escaped names with longer presentation remain rejected.
- CoreDNS v1.15.0 normalizes server-block names with Go 1.26.0 `strings.ToLower` and rejects IPv6 CIDRs beginning with `:` or `0` followed by `:` (`plugin/normalize.go`). Pharos preserves those Corefile behaviors under ADR 0003 (CoreDNS wins), despite RFC 4343 §3 and RFC 4291 §2.3.
- CoreDNS v1.15.0's caddy v1.1.4 import parser rejects patterns with multiple `*` or `?` wildcards and all bracket expressions (`caddyfile/parse.go`); Pharos preserves those limits under ADR 0003 (CoreDNS wins).
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
- View metrics use the last matching nonempty View name. A DS Query at a cut evaluates only the exact child-apex block and records once under the selected authoritative Zone.
- A wildcard Listener is labelled as an unbound address even when explicitly bound to an unspecified IP.
- Plugin attribution identifies the Plugin that returned the Response; CoreDNS's nested writers can attribute the outer Plugin instead.
- Pharos counts dropped Queries only on a Listener with at least one `prometheus` Server Block; CoreDNS's server-level error reporting counts them unconditionally.
- Concurrent scrapes can observe histogram buckets and sums at slightly different instants, unlike the Go client's synchronized histogram snapshot.

## Server

- Each UDP worker handles up to 256 waiting Queries concurrently and retains one
  active or spare slot plus at most 16 completed slots for reuse. Each plain slot reserves 65,535
  bytes each for its Query and Response, plus coroutine storage; shed Responses
  use the shared stack. Forwarded Responses may exceed the client's UDP limit.
  At capacity one ordinary Query waits; further ordinary datagrams are dropped,
  with a shed counter only for shed-eligible Queries when the stack is full.
  Forwarding-loop probes remain serviceable.
  Linux may have already received a batch of up to 16 datagrams. Ready Queries
  remain inline; Listener shutdown cancels in-flight Queries.
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
- Pharos permits up to 255 pointer hops per name and 8192 aggregate pointer hops across Message QNAME/owner-name parsing; this bounds repeated pointer traversal. miekg/dns v1.1.73 permits 126 per name (RFC 1035 §4.1.4; conf/server #101).
- Pharos rejects decimal name escapes above 255 instead of wrapping them to an octet as miekg/dns v1.1.73 does in `defaults.go`; RFC 1035 §5.1 governs per ADR 0002.
- SIG(0) and TSIG must be the final Additional RR; OPT may precede them (RFCs 6891 §6.1.1, 2931 §3.1, 8945 §§5.1–5.2).
- The protocol parser rejects duplicate OPT records, OPT records outside Additional, and non-root OPT owners as invalid Messages intended for FORMERR.
- DSO session Primary TLVs are unsupported; the Listener suppresses ID-zero DSO requests without inspecting their Primary TLV (RFC 8490 §5.4.1).
- The DNS Listener returns FORMERR for malformed Messages with at least four octets and drops shorter datagrams. CoreDNS v1.15.0 accepts malformed OPTs when its header-count policy allows them, and selects the last OPT in Additional.
- The DNS Listener ignores the reserved header Z bit on receipt, as RFC 6895 §2.1 recommends, and clears it in generated Responses (conf/server #101).
- Zero-question QUERY Messages route to the root Server Block when configured; CoreDNS's standard query path also permits QDCOUNT=0 (RFC 9619 §4; conf/server #101).
- For DS at a configured zone cut, Pharos uses the parent Server Block; if no parent is configured, it routes to the child and returns authoritative NODATA, as RFC 4035 §3.1.4.1 requires (conf/server #101).
- Response OPT advertises Pharos's 4096-octet responder capacity, as RFC 6891 §§6.2.3–6.2.4 and RFC 3226 §3 recommend. The UDP send limit remains the normalized request size capped at 4096 (512 when OPT is absent). CoreDNS `bufsize` echoes its reduced size in the response OPT; Pharos keeps server capacity in the OPT instead (conf/server #101).
- AD is preserved on ordinary upstream and local Responses. When a valid client TSIG is re-signed after forwarding, the Listener clears AD as RFC 8945 §5.5 requires; the `forward` Plugin has no upstream TSIG mode.
- Message-level RRSIG inception and expiration validation uses RFC 4034 §3.1.5 serial arithmetic from RFC 1982 §3.2; logging and offline signer refresh comparisons remain open (conf/server #101).
- DNS RCODE 16 metrics use BADVERS. TSIG Error 16 is BADSIG and is not a DNS RCODE label (RFC 6895 §2.3; RFC 8945 §3; conf/server #101).
- CoreDNS returns FORMERR on option unpacking errors; HTTP and QUIC report transport errors.
- Pharos returns a header-only FORMERR for malformed Messages, whereas CoreDNS may retain a partially decoded Question.
- For a header-only Message claiming one Question, Pharos returns FORMERR; CoreDNS returns SERVFAIL.
- For pass-through Responses, Pharos truncates the encoded Message without recompression; CoreDNS may fit more records by recompressing first.
- If an OPT precedes other Additional records, Pharos drops the following records rather than shifting their compression pointers; Listener size truncation does not set TC solely for optional Additional omission (RFC 2181 §9). The `nsid` plugin instead drops records after OPT and sets TC.
- TC is set when truncation omits required Answer or Authority data; RRset completeness limits remain as recorded in the RFC conformance table.
- Pharos removes OPT from a Response to a non-EDNS Query, as RFC 6891 requires; CoreDNS may preserve a Plugin-supplied OPT in that case.
- Pharos answers Plugin errors with SERVFAIL. CoreDNS ignores returned errors and bases the Response on the separately returned RCODE; without `errors` it does not log ordinary chain errors. Pharos likewise logs those errors only when `errors` is configured, while logging recovered panics at the Listener.
- A UDP IXFR that reaches a Zone Transfer stream returns the current SOA only, following RFC 1995 §2; CoreDNS's `transfer` returns REFUSED instead.
- The AXFR client API supports TSIG; CoreDNS v1.15.0's `secondary` does not sign transfer requests, even when a TSIG key is configured. Pharos's `secondary` Plugin matches this.
- Signed transfer producers must leave room for TSIG within the 65,535-octet Message limit; otherwise the Listener closes the connection rather than emitting an unsigned Message.
- Pharos also rejects Client Subnet address lengths that do not match the prefix and non-zero host bits, which miekg/dns accepts. It validates the supported typed options and framing; other option codes are passed through without the additional type-specific validation miekg/dns applies to some of them.
- Invalid UTF-8 in Extended DNS Error text is rendered with replacement characters.
- The requested record-data families are complete: the typed RDATA parser supports A, AAAA, NS, CNAME, PTR, MX, SOA, TXT, HINFO, CAA, URI, SRV, NAPTR, DS, CDS, DNSKEY, CDNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, SVCB, HTTPS, TLSA, SSHFP, ZONEMD and TSIG.
- Unsupported name-bearing types are rejected by the typed parser; other types remain opaque, preserve their bytes and print in RFC 3597 form rather than using their CoreDNS presentation. CoreDNS v1.15.0's `miekg/dns` v1.1.73 accepts malformed generic RDATA layouts and short NSEC3/ZONEMD cases that Pharos rejects under RFC 3597 §§3, 5, RFC 5155 §3.1.6, and RFC 8976 §2.2.3; see the live differential tests.
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
- SPF (TYPE99) and DLV (TYPE32769) zone records remain accepted for compatibility: live miekg/dns v1.1.74-0.20261103100211-b2d6c9f4480a accepts both, despite RFC 7208 §14.1 and RFC 8749 §4 discouraging or retiring these types.
- Pharos rejects empty and non-alphanumeric CAA tags as required by RFC 8659; miekg/dns accepts them.
- CAA and URI presentation follows miekg/dns's octet-string escaping, including its interpretation of backslashes in wire values, which can make the displayed value differ from the original octets.
- SRV targets and NAPTR replacements may be decoded from compressed names, but are always written uncompressed. RRSIG signer names and NSEC next names have the same behavior.
- TLSA and SSHFP accept empty tails like miekg/dns's wire decoder and domain 0.12.3.
- ZONEMD digests shorter than 12 octets are rejected as required by RFC 8976; miekg/dns v1.1.73's `zmsg.go` unpacker accepts them, while domain also rejects them.
- TSIG algorithm names accept compression on decode but are written literally.
- `Record::display_tsig()` renders the full miekg/dns pseudo-section; `Rdata` display contains only its data fields.
- SVCB and HTTPS targets likewise accept compressed names on decode and are written uncompressed. Their parameters must be ordered with no duplicate or reserved keys.
- As required by RFC 9460 and ADR-0002, wire parsing enforces mandatory-list ordering, key presence, and `no-default-alpn` dependencies; miekg/dns v1.1.73 unpacking accepts malformed mandatory values. The Zone-file parser still accepts `alpn=` with an empty list; this remains a conformance gap (RFC 9460 §7.1.1).
- Domain 0.12.3 wire decoding checks parameter framing and order but not individual values or the reserved key, so it accepts empty hints and IPv4-mapped IPv6 hints. Pharos still rejects empty hints but now accepts IPv4-mapped IPv6 hints (RFC 9460 §7.3; conf/proto #99).
- AliasMode semantics are not enforced by the wire codec; consumers must ignore parameters in AliasMode records.
- NSEC and NSEC3 bitmap windows must be ordered, nonempty, at most 32 octets, complete, and have a nonzero final octet (RFC 4034 §4.1.2; ADR-0002). miekg/dns and domain 0.12.3 accept trailing zero octets and all-zero windows; domain also accepts duplicate or disordered windows. Pharos's zone parser also accepts an NSEC bitmap with no blocks, and accepts empty NSEC3 bitmaps (RFC 6840 §6.4; see `docs/conformance.md`).
- CoreDNS v1.15.0 has no connection cap or per-connection in-flight cap (`core/dnsserver/server.go`, `tcpMaxQueries = -1`). Pharos limits a Listener to 1,024 simultaneous TCP connections and 16 in-flight Queries per connection. Excess connections wait in the TCP backlog; excess Queries wait for a slot.
- The default TCP read, write, and idle timeouts are 3, 5, and 10 seconds, respectively, matching CoreDNS v1.15.0 `core/dnsserver/server.go`.
- On Linux, each `sendmmsg` sends one Response (nix-rust/nix#2797).
- Self Lookup is limited to 10 nested Self Lookups; CoreDNS v1.15.0 does not enforce a depth limit. This prevents unbounded recursion, for example from a cycle of ExternalName Services. Exceeding the limit returns a Plugin error, normally answered with SERVFAIL.
- Copying a Query for Self Lookup re-encodes its records. It fails if RDATA is malformed, contains an unsupported name-bearing type, or the resulting Message exceeds 65,535 bytes; CoreDNS copies its decoded Message instead.

## Conformance branch compatibility notes

- These entries document behavior changed or explicitly retained by conformance branches. Source evidence is included when reports provide it; unsupported CoreDNS comparisons are omitted.

- **Zone and file**

- The apex remains an existing name when it lacks the queried QTYPE, so lookup returns NOERROR/NODATA under RFC 2308 §2.2 (conf/zone #95).
- Primary Zone loading rejects multiple SOAs, multi-target CNAME RRsets, and DNAME descendant data (RFC 1035 §5.2; RFC 2181 §10.1; RFC 6672 §§2.3–2.4). The offline signer retains the last SOA to match CoreDNS v1.15.0 `plugin/sign`; the primary Zone path rejects it.
- SOA serial zero is accepted on initial load and reload (RFC 1982 §7); CoreDNS's file loader uses zero as its initial no-change sentinel.
- Overlong DNAME substitution returns YXDOMAIN with one DNAME and no Self Lookup (RFC 6672 §2.2). The earlier Pharos path returned SERVFAIL and could recurse through Self Lookup.
- Zone RRset TTLs are normalized to the minimum, duplicate RRs are suppressed, and available sibling nameserver glue is included (RFC 2181 §§5.1–5.2; RFC 9471 §3.2).

- **Cache**

- A positive configured minimum TTL raises zero-TTL records before cache admission; default is five seconds. This retains the selected minimum-TTL compatibility policy despite RFC 1035 §3.2.1 and RFC 8767 §4 (ADR 0002; conf/cache #97).
- `denial_min_ttl` is accepted for configuration compatibility but ignored, because RFC 2308 §3 does not permit raising a negative TTL above its SOA-derived lifetime.
- REFUSED is cached as a resolution failure under RFC 9520 §§2.2 and 3.2; this differs from the previous cache behavior (conf/cache #97).
- `servfail 0` disables failure caching and sub-second values truncate to zero; this behavior remains unchanged despite RFC 9520 §3.2's one-second minimum (conf/cache #97).
- ECS-bearing queries and responses bypass the cache. This conservative subset does not implement RFC 7871 §7.3 prefix-aware scope matching.
- Failure-cache keys omit the upstream address because the cache context does not expose the selected upstream (RFC 2308 §7.1; conf/cache #97).
- SOA-less NODATA is classified as negative but is not cached (RFC 2308 §2.2; conf/cache #97).
- Failure TTLs use whole-second durations, and repeated failures back off exponentially up to five minutes (RFC 9520 §3.2; conf/cache #97).
- Expired resolution failures are never served stale (RFC 9520 §3.2; conf/cache #97).
- The #97 report contains no before/after `pharos-bench` run for `ndots` amplification; p99 latency and negative-cache hit throughput remain unverified.

- **DNSSEC**

- SPF (TYPE99) and DLV (TYPE32769) remain accepted in zone files for migration compatibility. CoreDNS v1.15.0, using miekg/dns v1.1.73 (`go.mod`), loaded sample records and answered `TYPE99` and `TYPE32769` UDP queries with RCODE 0 and one Answer (RFC 7208 §14.1; RFC 8749 §4).
- Dynamic UPDATE rejects SPF (TYPE99) even though ordinary zone-file data remains accepted, following RFC 7208 §14.1; the proto decision retains static-zone compatibility only (conf/dynupdate #96; conf/proto #99).
- Algorithm 10 signing is rejected under RFC 9904 §3's NOT RECOMMENDED policy; the public SHA-1 DS/CDS digest API is removed under RFC 9904 §4 and RFC 9905 §5.
- DNSSEC NXDOMAIN answers use NOERROR with a synthetic NXNAME NSEC in Authority. CoreDNS v1.15.0 also maps NXDOMAIN to NOERROR but puts its black-lie NSEC in Answer (RFC 9824 §3.1; see the DNSSEC README). Owner-specific NODATA bitmaps remain open under §3.2.
- Synthetic black-lie NSEC spans are not checked against authoritative zone contents and may cover existing descendant names; the signer lacks a zone inventory (RFC 4470 §3; DNSSEC README; conf/dnssec #100).
- A DO negative response without SOA fails with SERVFAIL rather than returning an unsigned denial. CoreDNS returns the upstream negative response.
- Only DNAME-synthesized CNAMEs are unsigned; real CNAME RRsets remain signed (RFC 6672 §5.3.1).
- A sole apex CDS/CDNSKEY delete signal is retained and signed; CoreDNS drops it while replacing publication records (RFC 8078 §4).
- Offline NSEC TTL is `min(SOA TTL, SOA.MINIMUM)` (RFC 9077 §3.1); apex NS RRSIG TTL matches the NS RRset TTL (RFC 4034 §3).
- `dnssec` keys are bound to their owner zone; a private key cannot sign another configured zone (RFC 8080 §8).
- Signing cache-miss and RSA allocations remain open in issue #106; cache memory budget and miss-path scans remain open in issue #107.
- NSEC3 chain construction requires zero iterations and empty salt. Full end-to-end NSEC3 zone signing remains unsupported (RFC 9276 §3.1; conf/dnssec #100).

- **Server and protocol**

- DSO Primary-TLV parsing remains unsupported; ID-zero DSO requests are suppressed without inspecting Primary TLVs (RFC 8490 §5.4.1; conf/server #101).
- Secondary SOA timers retain a one-second floor to prevent an immediate refresh/retry loop; zero-timer semantics remain deferred (RFC 1034 §4.3.5; conf/secondary #98).
- When the DNSSEC plugin is in-chain, any explicit QTYPE 128 receives FORMERR, including names outside signed zones (RFC 9824 §3.5).

- **Corefile and plugin behavior**

- `any` uses CPU `RFC8482`; its OS remains `See RFC 8482` for CoreDNS compatibility (RFC 8482 §4.2; CoreDNS v1.15.0 `plugin/any`).
- `any` passes non-IN ANY questions through rather than returning IN HINFO; local, hosts, and whoami also pass through non-IN questions (RFC 1034 §4.3.1; CoreDNS v1.15.0 plugin READMEs).
- `any` synthesizes HINFO before checking CNAME and cannot sign the generated answer when DO=1 (RFC 8482 §4.2); CoreDNS v1.15.0 `plugin/any` has the same behavior.
- `hosts` returns authoritative NXDOMAIN with a synthetic SOA for unmapped names instead of CoreDNS's SERVFAIL (RFC 1034 §4.3.2; RFC 2308 §3; CoreDNS v1.15.0 `plugin/hosts/hosts_test.go` `hostsExample`).
- `hosts` authoritative NODATA also includes a synthetic SOA for negative caching (RFC 2308 §3).
- The local plugin returns positive `localhost.` apex NS/SOA data for CoreDNS compatibility (RFC 6761 §6.3).
- Local answers set AA; local NS and SOA MNAME use resolvable `localhost.`, and SOA RNAME is `nobody.invalid.` (RFC 1034 §4.3.2; RFC 2181 §7.3; RFC 6303 §3; CoreDNS v1.15.0 `plugin/local`).
- DNS64 and SIIT reject non-/96 RFC 6052 Well-Known Prefixes and nonzero /96 reserved octets; CoreDNS v1.15.0 DNS64 setup tests accept `64:ff9b::/32` (`plugin/dns64/setup_test.go`). DNS64 synthesized AA/RA come from the initial AAAA response (RFC 6052 §§2.1–2.2; RFC 6147 §5.4; CoreDNS v1.15.0 `plugin/dns64` and `plugin/siit`).
- A successful empty A lookup returns the original AAAA response (RFC 6147 §5.4); this differs from the former Pharos behavior.
- The `header` plugin can override AA on Queries and non-authoritative Responses; this retains CoreDNS v1.15.0 `plugin/header` behavior (RFC 1035 §4.1.1).

- **Kubernetes and forwarding**

- Kubernetes ExternalName returns a CNAME for every QTYPE; CoreDNS limits it to CNAME/A/AAAA (Kubernetes DNS spec §2.5).
- Unnamed Service ports produce no SRV records in Kubernetes and k8s_external queries or AXFR; CoreDNS v1.15.0 behavior differs (Kubernetes DNS spec §2.3.2; `plugin/kubernetes/kubernetes.go`, `plugin/kubernetes/transfer.go`).
- k8s_external suppresses SRV when a hostname target lacks a non-CNAME A/AAAA RRset (RFC 2782); AXFR still cannot resolve hostname targets synchronously.
- Multicluster accepts only `clusterset.local`; two-label source-cluster IDs are encoded as separate DNS labels, while CoreDNS v1.15.0 parses one cluster label (`plugin/kubernetes/parse.go`; KEP-1645 §§2.1,2.4.1–2.4.2).
- `ignore empty_service` is accepted but does not suppress ClusterIP/ClusterSetIP records. `key!=value` selectors and repeated-key conjunctions are supported (conf/k8s #103).
- Chased A/AAAA RCODE is NOERROR if any target answers; otherwise the final failed cycle determines RCODE (RFC 6604 §3; conf/k8s #103).
- `tolerate-unready-endpoints=true` enables ordinary Service endpoint answers/transfers; ServiceImport endpoints ignore the annotation (KEP-752; conf/k8s #103).
- Malformed multicluster names such as `bad..zone` are rejected; CoreDNS accepts and drops the malformed token (conf/k8s #103).
- `forward` clamps `max_connect_attempts` to 1–3 per upstream/transport; zero means one. Unsigned ECS Queries reserve one attempt for the RFC 7871 §7.1.3 retry. Configured three therefore allows only two ECS-bearing attempts (RFC 9520 §3.1; CoreDNS default is `2n`).
- Mismatched upstream responses are discarded; if no valid response arrives, clients receive SERVFAIL rather than FORMERR (RFC 1035 §4.1.1).
- ECS response FAMILY/SOURCE/ADDRESS are validated, longer SCOPE is accepted, outgoing SCOPE is zero, and REFUSED retries without ECS. TSIG-signed Queries are not rewritten and do not receive the ECS retry (RFC 7871 §§6,7.1.3,7.3; RFC 7828 §3.2.1).
- Cross-section repeated RRsets are relayed unchanged because RFC 2181 §5.5 is SHOULD NOT. Mixed-TTL RRsets are normalized to their lowest TTL.
- UDP source sockets remain pooled and reuse ports for warmed zero-allocation forwarding; unpredictable source-port rotation remains deferred to issue #109 (RFC 5452 §9.2).
