# CoreDNS compatibility

## bind

- Interface enumeration uses `getifaddrs`; scoped IPv6 Listener labels use the numeric interface index rather than CoreDNS's interface name.
- Unspecified addresses are labelled as unbound addresses.
- An unbound Listener and an explicit `bind ::` on the same port share one Listener. CoreDNS groups them separately, so its competing sockets can direct Queries to the wrong Server Block.
- Reload binds new Listeners before removing old ones, so switching between a wildcard and a specific address on the same port can fail rather than replacing the socket.

## cache

- Negative Responses use the SOA MINIMUM as well as the record TTLs to bound the cache lifetime, following RFC 2308; CoreDNS's `MinimalTTLWithMaximum` checks only record TTLs.
- The cache hashes the same Query fields with FNV-1a rather than CoreDNS's FNV-1, so shard placement and eviction choices differ.
- Configured Domains must be representable as DNS names; CoreDNS can normalize some malformed `disable` names without validating them.
- Very large TTLs are bounded to the DNS TTL range during use rather than reproducing Go duration overflow.
- Queries with compressed Questions, and Responses with compressed or multiple Questions or an OPT before other Additional records, are not cached: removing those encodings could invalidate compression pointers. CoreDNS re-encodes them.
- On a miss, Queries whose encoded names point into the header, or whose non-OPT RDATA might contain a compression pointer, also bypass the cache rather than changing AD.
- Opaque EDNS option data is not treated as name compression.
- On a hit, Pharos rewrites the Question's case in the stored wire Message; record names compressed against it therefore acquire the current Query's case, whereas CoreDNS rebuilds records from the cached Response.
- If a UDP caller's Response buffer is too small for a cached Message, Pharos falls through to Next instead of growing it on the hit; TCP buffers are grown as needed.
- TSIG-signed Queries and Responses bypass caching so that ID, flags and TTL rewrites cannot invalidate their signatures.
- Wildcard source Metadata is not saved with cache entries.
- Background refreshes use a fresh Metadata map and retain Listener state for Self Lookup.
- A `verify` refresh on a routed Server Block runs as a background task, even without a verify timeout, and concurrent verifies are coalesced.
- Direct use of an unbound Plugin cannot launch a background refresh; its verify mode does not enforce the configured timeout.
- Stale age is evaluated in whole seconds, but fractional configured windows are not truncated as they are in CoreDNS.
- A refresh is not stored if a newer cache entry was installed while it was in flight.
- A hit that launches a background refresh allocates for the task and its Query and Response buffers; ordinary warmed hits do not allocate.
- Cache metric series are initialized at setup, including zero-valued series; CoreDNS initializes individual labelled series on first use.

## errors

- The `errors` Plugin uses Rust's `regex` syntax rather than Go's RE2 syntax. For example, `\w`, `\d`, `\s` and word boundaries are Unicode-aware in Rust but ASCII-only in Go; some expressions are accepted by only one engine.
- Rust's regex compiler also imposes its own compiled-size limit.
- Pharos emits `debug` consolidation messages without CoreDNS's separate debug switch.
- The Plugin contract represents an error as SERVFAIL without an independent RCODE, so error logs always report `2`.
- Rust panic traces and Pharos's text/JSON logging format differ from CoreDNS's Go stack and log format.
- Pharos selects `stacktrace` per routed Server Block; CoreDNS's last Server Block setting applies to the whole Listener.
- Replacing Rust's process-wide panic hook after Listener setup disables Pharos's stacktrace capture.

## forward

- Plain UDP and TCP Upstream exchange is available for `forward`.
- DNS-over-TLS is reserved for M3.
- The proxy retries a truncated UDP Response over TCP only when `prefer_udp` is set, as CoreDNS's `forward` does.
- Idle sockets are swept across shards at most once per expiry interval on Query traffic. Unlike CoreDNS’s periodic cleanup, an idle Proxy retains expired sockets until another Query or shutdown.
- Upstream TSIG Messages retain their original ID rather than rewriting the signed Message.
- Proxy metric RCODE series are initialized on first observation, allocating once per distinct RCODE.
- Connections rotate FIFO within each worker shard rather than in one global FIFO.
- Encrypted Upstreams (`tls://`, `quic://` and `https://`) and `tls` or `tls_servername` options fail setup rather than silently downgrade; TLS is deferred to M3.
- Hostname Upstreams resolve at setup using the system resolver or the configured `resolver`.
- `doh_method` has no effect on plain DNS.
- Upstream and resolver ports must be numeric and fit in 16 bits; CoreDNS can also accept service names and out-of-range ports at setup.
- Like CoreDNS, IPv6 scopes are stripped from numeric Upstreams, including resolv.conf entries.
- Non-IP nameservers from resolv.conf are retained, but currently fail without health probes rather than being resolved at dial time as in CoreDNS; retries of such entries pause for 1 ms to avoid a busy loop.
- Numeric Upstreams are deduplicated by normalized socket address; CoreDNS preserves textual address spelling and distinct scopes in its keys.
- Some option argument and Domain edge cases remain more restrictive than CoreDNS.
- Upstream Metadata uses the normalized numeric socket address, which may differ from CoreDNS's configured address text.
- Health checks start on exchange failure, and proxy connections and checks are stopped on Shutdown.
- Forward reuses Upstream Response buffers from a pool; a new buffer is allocated when concurrent Queries exceed the pool's previous high-water mark, and the pool retains that peak allocation until the Plugin is dropped.

## health

- Health addresses are shared once per exact configured address, using the first Lameduck duration; CoreDNS creates one Listener and probe per Server Block and can share ports using SO_REUSEPORT.
- Pharos reports bind errors, requires numeric ports, and uses a five-second total HTTP connection lifetime and a 1,024-connection limit.
- Unlike Go's ServeMux, it does not redirect unclean paths or decode escaped path segments, and its 404 responses omit Go's `X-Content-Type-Options` header.
- The self-probe opens a fresh connection for every check and exports classic histogram buckets, not Prometheus native histogram samples.

## hosts

- Relative hosts file paths resolve against the working directory; `root` is not implemented yet, so CoreDNS's join with a configured `root` is not applied.
- Pharos discards names that are not valid DNS names or UTF-8; CoreDNS retains arbitrary fields in its hosts maps.
- Pharos lowercases ASCII name bytes, while CoreDNS applies Go's Unicode lowercasing.
- Configured Domains that cannot be represented as DNS names are ignored for matching; CoreDNS keeps its normalized strings.
- On a file read error, an unfinished field is discarded; CoreDNS processes the last partial chunk before logging the error.
- Responses require a preallocated UDP buffer, as with Whoami.
- Hosts-file reloads stop during configuration Restart and resume if that Restart fails.
- File parsing runs on a Tokio worker, so a large or slow hosts file can delay other tasks on that worker.

## kubernetes

- The Kubernetes data crate ignores addresses in EndpointSlices with address types other than IPv4 or IPv6; CoreDNS retains them.
- With `namespace_labels` and `multicluster`, Pharos watches all ServiceImports and exposes those in matching Namespaces; CoreDNS matches the ServiceImports' own labels against `namespace_labels`, hiding imports in exposed Namespaces.
- As in CoreDNS v1.15.0, Kubernetes NS discovery snapshots local addresses per Plugin instance.
- CoreDNS's CIDR-only selection yields no local NS addresses for explicit `bind` IP literals; Pharos matches that behavior.
- API client creation and kubeconfig validation occur during Startup rather than Corefile setup.
- Kubeconfig OIDC credentials use the configured ID token without refreshing it; CoreDNS includes the client-go OIDC authentication provider.
- Kubeconfig proxy URLs are not supported; CoreDNS can connect through them.
- An unreadable or invalid in-cluster CA file fails client creation; client-go logs the CA error and proceeds without that CA file.
- DNS programming latency observations for lists occur after the whole resource batch is installed, rather than after each individual EndpointSlice.
- Kubernetes REST request duration ends when response headers arrive, rather than after processing the response body.
- Kube's internal retries are counted once per request rather than once per attempt as in client-go.
- Client-side rate-limit waits are capped at 100 years for extremely small QPS.
- CoreDNS parses `NaN` and positive infinity for `apiserver_qps`; Pharos accepts them in the Corefile but rejects them when creating the API client.
- Pharos treats non-positive `startup_timeout` as an immediate timeout; CoreDNS's startup ticker panics for those values.
- Pharos lowercases the zone when matching NS queries at the zone and `ns.dns.<zone>`, so mixed-case queries are answered (RFC 4343). CoreDNS compares the lowercased name with the zone in the query's case (`handler.go:22,53`, `ns.go:11`) and answers NODATA or NXDOMAIN.
- Glue for NS answers and `ns.dns.<zone>` addresses are deduplicated (RFC 2181 §5); CoreDNS repeats glue when a local address is in several EndpointSlices of one Service.
- The initial list is a consistent paginated list of 500 objects per page (kube-runtime default), served from etcd; CoreDNS uses a streaming WatchList or a `resourceVersion=0` read from the API server's cache. This never returns older data, but costs more etcd load when many DNS Pods restart together.
- The CA file is read once when the API client is created; a rotated CA needs a restart.
- An ExternalName name returns its CNAME for every query type (RFC 1034 §4.3.2 step 3a). CoreDNS returns it only for CNAME, A and AAAA queries and answers NODATA for other types such as TXT, SRV, MX and HTTPS (`kubernetes.go:116-121,168-185`). Pharos follows the CNAME only for A and AAAA, as CoreDNS does; for other types the client follows it.
- Shared with CoreDNS v1.15.0: names with no records of their own (`dns.<zone>`, `_tcp.<service>.<namespace>.svc.<zone>`, and TXT at the zone, `svc.<zone>` and `<namespace>.svc.<zone>`) get NXDOMAIN instead of NODATA (RFC 8020; kept for CoreDNS parity, #43).
- Shared with CoreDNS v1.15.0: `dns-version.<zone>` A and non-PTR queries for existing reverse names get NXDOMAIN instead of NODATA (RFC 2308 §2.2; kept for CoreDNS parity, #43).
- Shared with CoreDNS v1.15.0: a SOA query for a name that does not exist gets NOERROR instead of NXDOMAIN (RFC 2308; kept for CoreDNS parity, #43).
- Shared with CoreDNS v1.15.0: `dns-version` in a multicluster zone returns `1.1.0`; the multicluster DNS specification 1.0.0 (KEP-1645) says `1.0.0`.
- Shared with CoreDNS v1.15.0: a ServiceImport without ports gets NXDOMAIN for A/AAAA, and a ServiceImport port without a protocol never matches `_tcp`; the MCS API defaults the protocol to TCP only in its documentation.
- Shared with CoreDNS v1.15.0: ANY queries get NODATA, even at the zone (RFC 8482 §4 recommends at least one RRset).

## loadbalance

- Pharos permutes encoded records and relocates compression pointers without re-encoding names. It leaves a Response unchanged if relocation would create a forward or overlapping pointer, exceed the 14-bit pointer range, or if name encodings cannot be safely relocated. Signed TSIG Responses are not reordered. CoreDNS re-encodes its records and does not have these restrictions.
- Other RDATA is opaque, so pointers in types outside the compression-receiving list are not relocated even if a sender encodes them contrary to the RFCs.
- Relative weight file paths use the working directory until `root` is implemented.
- Weight files must be UTF-8; CoreDNS accepts arbitrary bytes.
- Pharos compares file contents directly instead of CoreDNS's MD5 checksum and keeps the last valid weights when parsing fails.
- Weight file Domains that cannot be parsed as DNS names cannot match Responses.
- Negative reload durations are accepted as zero; CoreDNS's negative ticker interval panics when started.
- Random choices use a thread-local xorshift generator rather than CoreDNS's generators.
- Equivalent escaped Domain spellings can match in Pharos, while CoreDNS compares presentation strings exactly.
- Weight file reads and parsing run on a Tokio worker and can delay other tasks.
- Successful reloads are not logged.
- When both policies are configured, subnet preference runs after weighted selection, as in CoreDNS, and can change which address appears first.

## log

- The `log` Plugin's body uses CoreDNS's common format by default, preceded by Pharos's timestamp and `INFO log:` rather than CoreDNS's `[INFO]` prefix.
- JSON entries use Pharos's generic log fields rather than CoreDNS's access-log fields.
- `{local}` reports the configured Listener address; for wildcard Listeners it does not report the connection's actual local address.
- For unanswered errors, the logged Response size includes the Listener's synthesized EDNS OPT, whereas CoreDNS's logging-only synthetic Message has no OPT.
- For a returned Response, `{rsize}` is the size before truncation, as in CoreDNS.
- `{rflags}` also describes the Message before truncation; CoreDNS scrubs its recorded Message in place, so its `{rflags}` shows `tc` when the Listener truncates.
- A Drop is logged with `-` RCODE and flags and zero size; a Plugin error is logged as a synthesized SERVFAIL.
- Zone Transfer streams are not yet served and are logged as a Message-less outcome.
- The formatter cannot expand compressed names in unsupported RDATA when calculating Message size.

## loop

- The `loop` Plugin probes only the first Domain in a Server Block at startup and after Reload, as CoreDNS does.
- Fatal loop detection logs and exits immediately with status 1, without running Shutdown hooks or removing the pidfile, as CoreDNS's fatal logger does.
- Probe Queries may allocate while running concurrently with UDP reception; ordinary Queries do not.
- Like CoreDNS, a configured port 0 is probed as port 0 rather than the actual ephemeral Listener port.

## multisocket

- With `multisocket` and no argument, Pharos uses that same worker count rather than Go's GOMAXPROCS, and does not honor the `GOMAXPROCS` environment variable.
- Pharos always uses one TCP listening socket per Listener; CoreDNS opens one per configured server. These differences affect performance, not Responses.
- Changing the UDP count on Reload briefly stages new reuseport sockets before replacing the old ones; Queries arriving during staging or rollback can be lost.

## nsid

- Adding NSID requires sufficient preallocated Response buffer capacity and a Message of at most 65,535 octets; otherwise the Plugin returns an error, answered as SERVFAIL. CoreDNS allocates when encoding and may instead fail to write an oversized Response.
- If the Response OPT precedes other Additional records, Pharos drops those records and sets TC before modifying NSID to avoid invalidating compression pointers; CoreDNS re-encodes them. This is the same restriction as Listener scrubbing.

## prometheus

- The `prometheus` Directive accepts `runtime_metrics`, but has no effect: Go runtime metrics do not exist in Pharos.
- The `tls` option is parsed, but any TLS configuration fails startup rather than silently serving unprotected HTTP; Prometheus exporter-toolkit TLS and authentication are not implemented.
- Blocks sharing a metrics address must use the same TLS configuration.
- Metrics HTTP connections are capped at five seconds total, rather than CoreDNS's separate per-request read, write and idle deadlines, and at 1,024 simultaneous connections.
- Only GET requests are served at `/metrics`; other HTTP methods return 404.
- Pharos requires a numeric metrics port at startup; CoreDNS can also resolve service names supported by the host.
- Bind and startup errors are reported, whereas CoreDNS's shared Listener setup currently discards errors from its `uniq.ForEach` callback.

## ready

- The `ready` endpoint serves GET only; CoreDNS also accepts other methods.
- HTTP connections use the same five-second total lifetime and 1,024-connection limit as the metrics endpoint.
- Pharos requires numeric ports at startup and reports bind errors; CoreDNS supports service names and currently discards errors from shared Listener startup.
- Pharos does not log unready Plugin names on every readiness request.
- Readiness state is reset on Reload.
- During Lameduck Pharos keeps `/ready` available with 503 `Shutting down`. CoreDNS v1.15.0 normally closes the readiness Listener before the health Lameduck delay, so subsequent requests fail to connect instead.

## reload

- Like CoreDNS, HTTP Listeners close and reopen on Reload; probes and scrapes can briefly fail, and re-opening an old Listener can fail if another process takes its port.
- DNS Listeners with unchanged keys and UDP counts keep their sockets.
- New Listeners are bound before existing handlers are swapped; separate Listeners are swapped individually rather than in one process-wide atomic operation.
- Pharos hashes a canonical representation of parsed, import-expanded Server Blocks instead of CoreDNS's JSON encoding, so the hash values differ.
- Pharos omits source paths and absolute line numbers from the hash; CoreDNS includes them, so adding comment lines can trigger Reload in CoreDNS but not Pharos.
- Line boundaries that affect Directive argument grouping are retained.
- The last attempted hash is reported even when a Reload fails, as in CoreDNS.
- Candidate setup can register metric series before a failed Reload is rolled back.
- Shutdown waits for Queries on replaced states to finish, so a stuck Query can delay processing subsequent signals.

## whoami

- Whoami reports an error if adding the protocol label would make its SRV owner name exceed the DNS name length limit. CoreDNS ignores the resulting write error.
- The UDP caller must supply a Response buffer with enough capacity; otherwise Pharos reports an error instead of allocating on the UDP Query path.

## General

- Only `bind`, `cache`, `errors`, `forward`, `health`, `hosts`, `kubernetes`, `loadbalance`, `log`, `loop`, `multisocket`, `nsid`, `prometheus`, `ready`, `reload` and `whoami` are implemented. Other built-in Directives are disabled by default; explicitly enabling their Cargo features makes setup fail with a not-implemented error rather than accepting their configuration.
- CoreDNS v1.15.0 (coredns/caddy v1.1.4) re-scans a token after each `{$VAR}` / `{%VAR%}` replacement, so a value that contains its own reference loops forever. Pharos reports an error instead, and also stops after 10,000 replacements or 16 MiB of expanded text.

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

- Without `multisocket`, Pharos uses the CPU-quota-aware worker count for UDP; CoreDNS uses one socket.
- CoreDNS v1.15.0 uses miekg/dns v1.1.73.
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
- Zone Transfer streams are not yet served by the Listener.
- Pharos also rejects Client Subnet address lengths that do not match the prefix and non-zero host bits, which miekg/dns accepts. It validates the supported typed options and framing; other option codes are passed through without the additional type-specific validation miekg/dns applies to some of them.
- Invalid UTF-8 in Extended DNS Error text is rendered with replacement characters.
- The requested record-data families are complete: the typed RDATA parser supports A, AAAA, NS, CNAME, PTR, MX, SOA, TXT, HINFO, CAA, URI, SRV, NAPTR, DS, CDS, DNSKEY, CDNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, SVCB, HTTPS, TLSA, SSHFP, ZONEMD and TSIG.
- Unsupported name-bearing types are rejected by the typed parser; other types remain opaque, preserve their bytes and print in RFC 3597 form rather than using their CoreDNS presentation.
- Presentation parsing is deferred to the zone-file parsing issue (see the existing `shortcut:` comment in `rdata.rs`).
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
