# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/itsmeyaw/pharos-dns/compare/pharos-server-v0.2.0...pharos-server-v0.3.0) - 2026-11-20

### Added

- *(proxyproto)* proxyproto Plugin on every Transport ([#170](https://github.com/itsmeyaw/pharos-dns/pull/170))
- *(tls)* ACME certificate management (DNS-01) ([#169](https://github.com/itsmeyaw/pharos-dns/pull/169))
- *(prometheus)* exporter-toolkit TLS and authentication ([#168](https://github.com/itsmeyaw/pharos-dns/pull/168))
- *(grpc)* grpc Plugin ([#167](https://github.com/itsmeyaw/pharos-dns/pull/167))
- *(https3)* https3 Plugin and https3:// Transport ([#165](https://github.com/itsmeyaw/pharos-dns/pull/165))
- *(grpc_server)* grpc_server Plugin and grpc:// Transport ([#164](https://github.com/itsmeyaw/pharos-dns/pull/164))
- *(forward)* DNS-over-HTTPS Upstreams ([#163](https://github.com/itsmeyaw/pharos-dns/pull/163))
- *(forward)* DNS-over-QUIC Upstreams ([#162](https://github.com/itsmeyaw/pharos-dns/pull/162))
- *(quic)* quic Plugin and quic:// Transport ([#161](https://github.com/itsmeyaw/pharos-dns/pull/161))
- *(https)* https Plugin and https:// Transport ([#160](https://github.com/itsmeyaw/pharos-dns/pull/160))
- *(forward)* DNS-over-TLS Upstreams ([#158](https://github.com/itsmeyaw/pharos-dns/pull/158))
- *(tls)* tls Plugin and tls:// Transport ([#157](https://github.com/itsmeyaw/pharos-dns/pull/157))

### Fixed

- *(m3)* standards and spec review findings ([#183](https://github.com/itsmeyaw/pharos-dns/pull/183))

### Other

- *(test)* move large inline test modules to separate files

## [0.2.0](https://github.com/itsmeyaw/pharos-dns/compare/pharos-server-v0.1.0...pharos-server-v0.2.0) - 2026-11-18

### Added

- *(server)* admit opted-in UPDATE messages
- *(server)* match CoreDNS AXFR acceptance
- *(server)* route queries through views
- *(metrics)* add template counters
- *(server)* sketch view selection hooks
- *(server)* support NOTIFY source address
- *(template)* call bound Query utilities
- *(dnssec)* sign responses and cache results
- *(server)* authenticate AXFR client streams
- *(server)* sign transfer stream messages
- *(server)* send NOTIFY with retries
- *(server)* receive unsigned AXFR streams
- *(server)* handle UDP transfer queries
- *(server)* route transfer streams to TCP
- *(server)* write lazy TCP message streams
- *(tsig)* expose validated key to Next
- *(tsig)* verify and sign valid queries
- *(autopath)* count successful searches
- *(autopath)* follow search suffixes
- *(rewrite)* set local EDNS options
- *(server)* reborrow queries for Next
- *(siit)* count translated queries
- *(siit)* synthesize IPv4 answers
- *(dns64)* count translated responses
- *(acl)* count policy outcomes
- *(shed)* bound UDP response queues
- *(debug)* enable process-wide debug mode
- *(timeouts)* configure TCP connection limits

### Fixed

- *(server)* avoid OPT encoding allocations
- *(server)* encode selected response OPT
- *(secondary)* harden refresh paths
- *(server)* warn when TCP_NODELAY fails
- *(secondary)* reuse SOA connection for AXFR
- *(server)* clamp RFC3339 year range
- *(server)* truncate over-long bounded log entries
- *(server)* bound TCP FIN drain, cancel Transfers
- *(server)* drop sub-header datagrams
- *(http)* document lazy metrics validators
- *(http)* honor RFC 9110 operations
- *(server)* validate RFC 1035 TCP frame length
- *(secondary)* bound RFC 1996 §3.10 logging
- *(transfer)* bind RFC 1996 §3.4 TCP source
- *(http)* enforce RFC 9110 endpoint semantics
- *(server)* preserve complete RRsets on truncation
- *(server)* order UPDATE and TKEY admission
- *(transfer)* write TCP frames per RFC 7766 §8
- *(server)* cancel queries after TCP reset
- *(server)* keep required RRsets complete
- *(server)* reject zero UDP workers
- *(server)* return NOTIMP for TKEY queries
- *(server)* return FORMERR for malformed input
- *(server)* type forwarded AD marker
- *(dns)* bound parser walks and enforce controls
- *(edns)* advertise responder capacity
- *(dns)* preserve TSIG and bound error recovery
- *(dns)* ignore NOTIFY ancillary sections
- *(server)* cap UDP response size
- *(dns)* tighten protocol edge handling
- *(server)* scope AD clearing to signed forwarding
- *(server)* close DNS protocol edge cases
- *(dnssec)* tighten review tests and citations
- *(server)* honor clamped EDNS payload size
- *(dns)* bound parsing and correct DS routing
- *(dnssec)* prepare signing keys before queries
- *(server)* distinguish unhandled UPDATE zones
- *(server)* label extended RCODE 16
- *(server)* bound log timestamp years
- *(server)* keep one UDP worker
- *(server)* enforce response metadata rules
- *(server)* route DS and UPDATE by authority
- *(server)* answer malformed DNS queries correctly
- *(server)* report NOTIFY fallback failures
- *(server)* validate NOTIFY and AXFR responses
- *(udp)* log panics during shutdown
- *(udp)* recover probe panics and count drops
- *(udp)* recycle buffers and admit probes
- *(shed)* wake buffer waiters individually
- *(udp)* await cancellation before shutdown
- *(auto)* label metrics with discovered Zones
- *(server)* contain panics of inline TCP Queries
- *(transfer)* accept CoreDNS NOTIFY replies
- *(server)* reduce routed query stack usage
- *(view)* share routed chain future
- *(server)* reduce routed query stack usage
- *(transfer)* report NOTIFY response codes
- *(view)* satisfy workspace lint checks
- *(metrics)* label ACL and cache by view
- *(server)* inherit DS metric views
- *(server)* keep absent metadata disabled
- *(server)* route root DS through all views
- *(reload)* stop removed listeners concurrently
- *(reload)* bound drain and handle signals
- *(server)* report transfer signing failures
- *(tsig)* fail closed and truncate safely
- *(server)* contain transfer producer panics
- *(server)* close failed transfer streams
- *(tsig)* admit UPDATE for signature policy
- *(tsig)* sign after Listener finalization
- *(tsig)* sign unanswered outcomes
- *(tsig)* finalize EDNS before signing
- adapt merged plugins to Context lifetimes
- *(autopath)* group lookup flags
- *(rewrite)* carry EDNS into CNAME lookup
- *(server)* isolate borrowed self lookups
- *(rewrite)* register EDNS codes globally
- *(server)* retain nested query changes
- *(server)* support non-Tokio self lookup
- *(server)* bound self lookup stack depth
- *(siit)* retain lookup state compactly
- *(timeouts)* defer idle timer until work ends
- *(shed)* wake all waiting buffer users

### Other

- *(server)* warm tokio budget in shed allocation test
- *(server)* poll instead of fixed sleeps in tcp tests
- retry same-port TCP/UDP binds on AddrInUse
- drop hand-written CHANGELOG.md stubs
- *(release)* add per-crate CHANGELOG.md for release-plz
- *(server)* run view allocation cases serially
- *(server)* run outcome allocation cases serially
- *(server)* cite tokio coop/defer source in reload_allocations test
- *(server)* warm tokio coop defer Vec before alloc window
- *(server)* cite SHA-256 vector sources
- *(server)* reuse aws-lc for ETag hashing
- fix/secondary RFC conformance fixes
- fix/server RFC conformance fixes
- *(server)* cover maximum future SystemTime
- *(server)* cover far-future timestamp saturation
- *(server)* verify listener restores EDNS OPT
- *(server)* format year boundary test
- rem/secondary RFC conformance fixes
- rem/server RFC conformance fixes
- *(transfer)* 1232-octet NOTIFY buffer, share source bind, fix RFC 1996 cites
- *(server)* satisfy clippy in allocation test
- *(server)* cover TKEY NOTIMP over TCP
- *(server)* fmt
- *(server)* compute UDP workers once per reload
- *(server)* truncate contiguous RRsets without allocating
- *(http)* cover HTTPS target casing
- *(server)* cite TCP half-close behavior
- *(server)* reject zero workers on registry reload
- *(server)* match NOTIFY question per RFC 1996
- Merge branch 'conf/server' into integrate
- Merge branch 'conf/dnssec' into integrate
- *(server)* document DSO admission shortcut
- *(server)* cover DS cut allocations
- *(server)* share UDP response sizing
- *(server)* clarify UDP worker rationale
- *(router)* borrow configured domain names
- *(dns)* centralize response OPT sizing
- cite EDNS and upstream AD rules
- *(server)* pin zero-question query handling
- clarify DNS edge-case citations
- *(server)* clarify AXFR compatibility alias
- *(pharos-server)* cite spec sections above protocol logic
- *(udp)* stress slots across runtime threads
- *(udp)* cover concurrent slot responses
- *(udp)* strengthen mixed slot coverage
- *(udp)* refill idle slots on pending path
- *(udp)* assert idle slot invariant
- *(udp)* describe retained query slots
- *(udp)* keep ready coroutine pinned
- *(udp)* cover reused slot after drop
- *(udp)* reuse pinned query coroutine
- *(udp)* inspect batch without indexing
- *(udp)* clarify unwind state risk
- *(shed)* synchronize waiter cancellation
- *(udp)* avoid manual panic assertion
- *(udp)* cover reuse and delayed panics
- *(udp)* explain buffer reclamation
- *(udp)* cover concurrent shed queries
- *(udp)* run waiting queries concurrently
- *(tcp)* cover pending queries on stop and EOF
- *(server)* construct metadata in context
- Merge branch 'main' into m2-auto
- UDP first memory allocation
- Merge branch 'main' into m2-auto
- *(metrics)* compact response code counters
- *(server)* grow fd table before runtime threads
- *(server)* allocate UDP receive buffers on first datagram
- *(server)* answer ready TCP Queries inline
- *(server)* keep TCP connection past first-read timeout
- *(server)* reuse one idle timer per TCP connection
- *(server)* give each TCP connection its own stop channel
- *(server)* cite RFC 7766 §7 for TCP_NODELAY
- *(server)* disable Nagle and write TCP frames once
- *(server)* cite RFC 5936 for coredns AXFR branch
- format transfer helpers
- *(tsig)* verify cancelled query view
- *(server)* pin chain before containment
- *(tsig)* reuse context for query view
- Merge branch 'main' into m2-transfer
- Merge branch 'main' into m2-transfer
- Merge branch 'main' into m2-view
- *(server)* cite RFC 4343 for DS view label match
- *(server)* defer no-view metadata
- *(server)* mark view dispatch overhead
- *(transfer)* format transfer tests
- *(server)* remove unfinished view hook
- Merge branch 'main' into m2-engines
- main into m2-dnssec
- *(interop)* require tools during checks
- *(server)* relocate EDNS options in place
- *(dnssec)* include metrics in registry check
- *(server)* handle transfer errors explicitly
- *(server)* document signed transfer limits
- *(server)* fail closed on bad stream signing
- *(server)* verify signed transfer interop
- *(server)* reject unauthenticated AXFR tails
- Merge branch 'main' into m2-tsig-dnssec
- *(server)* fix transfer RFC citations, log README
- *(server)* cover AXFR read timeout
- *(server)* cover transfer backpressure
- *(server)* transfer to CoreDNS secondary
- *(tsig)* keep CoreDNS UPDATE admission
- *(server)* verify AXFR interop and SOA
- *(server)* exercise transfers with dig
- *(server)* cover NOTIFY routing
- main into m2-query-plugins
- main into m2-server-plugins
- *(shed)* note shed_query error-path allocation
- *(timeouts)* cite RFC 7766 §6.2.3
- allow inline query views in fixture
