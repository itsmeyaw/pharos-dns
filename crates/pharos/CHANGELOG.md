# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0](https://github.com/itsmeyaw/pharos-dns/compare/pharos-dns-v0.2.0...pharos-dns-v0.3.0) - 2026-11-20

### Added

- *(proxyproto)* proxyproto Plugin on every Transport ([#170](https://github.com/itsmeyaw/pharos-dns/pull/170))
- *(tls)* ACME certificate management (DNS-01) ([#169](https://github.com/itsmeyaw/pharos-dns/pull/169))
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
- *(differential)* encrypted Transport scenarios and M3 exit docs ([#172](https://github.com/itsmeyaw/pharos-dns/pull/172))

## [0.2.0](https://github.com/itsmeyaw/pharos-dns/compare/pharos-dns-v0.1.0...pharos-dns-v0.2.0) - 2026-11-18

### Added

- *(dynupdate)* store Zone in pharos-kv, import bbolt on first open
- *(secondary)* cap AXFR records, bytes and duration
- *(auto)* serve discovered Zones
- *(secondary)* serve transferred Zones
- *(k8s_external)* serve external services
- *(expression)* evaluate boolean literals

### Fixed

- *(autopath)* pass exact first-suffix query to Next
- *(cache)* bound stored wire bytes
- *(tsig)* forward unknown keys and log errors
- *(transfer)* NOTIFY skips CIDR ACLs; document IXFR, TSIG choices (RFC 1996 §2.1)
- *(server)* bound TCP FIN drain, cancel Transfers
- *(server)* drop sub-header datagrams
- *(acl)* fail closed for scoped filters
- *(http)* document lazy metrics validators
- *(zone)* scope raw UTF-8 rejection to names
- *(http)* honor RFC 9110 operations
- *(names)* reject raw non-ASCII presentation
- *(corefile)* escape Unicode server-block keys
- *(plugins)* handle special-use DNS names
- *(transfer)* enforce RFC 1995 §3 and RFC 5936 §5
- *(http)* enforce RFC 9110 endpoint semantics
- *(forward)* clear unsecured upstream AD
- *(dns)* bound parser walks and enforce controls
- *(edns)* advertise responder capacity
- *(proto)* honor wire-format RFC rules
- *(dns)* tighten protocol edge handling
- *(corefile)* align DNS key validation
- *(udp)* recover probe panics and count drops
- *(udp)* recycle buffers and admit probes
- *(udp)* await cancellation before shutdown
- *(k8s_external)* prioritize startup validation
- *(k8s_external)* validate dependency in check
- *(k8s_external)* validate dependency on startup
- *(pharos)* set Tokio worker stack to 8 MiB
- *(template)* bound total range iterations
- *(reload)* stop removed listeners concurrently
- *(reload)* bound drain and handle signals

### Other

- retry same-port TCP/UDP binds on AddrInUse
- *(pharos)* derive version from CARGO_PKG_VERSION
- drop hand-written CHANGELOG.md stubs
- *(release)* add per-crate CHANGELOG.md for release-plz
- add pre-commit rustfmt hook
- *(pharos)* use mimalloc as global allocator
- fix/secondary RFC conformance fixes
- *(compatibility)* clarify partial RFC behavior
- *(server)* mark Nagle rationale unbenchmarked
- *(compatibility)* note missing notify set
- *(whoami)* record SRV compatibility deviation
- *(server)* record Nagle latency tradeoff
- rem/special RFC conformance fixes
- rem/zone RFC conformance fixes
- rem/synth RFC conformance fixes
- rem/secondary RFC conformance fixes
- rem/fwdtsig RFC conformance fixes
- rem/cache RFC conformance fixes
- rem/server RFC conformance fixes
- rem/http RFC conformance fixes
- rem/dnssec RFC conformance fixes
- clarify TSIG and AD compatibility
- document DNS review follow-ups
- *(plugins)* clarify special-use precedence
- *(dnssec)* clarify class and NSEC behavior
- *(cache)* cite DNAME synthesis requirement
- *(pharos)* update EDNS large-RRset wire fixture
- *(acl)* cover wildcard block ordering
- *(server)* compute UDP workers once per reload
- record zone compatibility and upgrade notes
- *(plugins)* explain special-use behavior
- *(compatibility)* update synth RFC exceptions
- *(proto)* clarify RCODE and EDE differences
- record zone and plugin compatibility
- *(proto)* record RFC compatibility notes
- *(compatibility)* record synth RFC behavior
- *(dnssec)* record CoreDNS compatibility edges
- *(hosts)* record wildcard lookup behavior
- *(cache)* record RFC compatibility limits
- *(server)* record protocol edge behavior
- *(cache)* record compatibility limits
- *(bind)* wait for IPv6 listener after reload
- *(server)* update EDNS response fixtures
- *(compat)* index conformance notes
- Merge branch 'conf/docs' into integrate
- Merge branch 'conf/server' into integrate
- Merge branch 'conf/zone' into integrate
- Merge branch 'conf/proto' into integrate
- *(compat)* record conformance decisions
- record DNS protocol compatibility
- *(zone)* record CoreDNS compatibility differences
- *(corefile)* pin reviewed DNS behavior
- note CoreDNS name length behavior
- *(corefile)* pin CoreDNS glob limits
- note wildcard listener exposure
- *(pharos)* cite spec sections above protocol logic
- *(udp)* account for spare slot memory
- *(udp)* describe retained slot memory
- *(udp)* describe retained query slots
- *(udp)* preserve compatibility format
- *(udp)* note loop probe exception
- *(udp)* cover concurrent shed queries
- *(udp)* run waiting queries concurrently
- *(dynupdate)* record compatibility notes
- *(sign)* drop stale secondary note
- *(sign)* record compatibility and sources
- Merge branch 'main' into m2-auto
- *(server)* grow fd table before runtime threads
- *(runtime)* restore default worker stack
- Merge branch 'main' into m2-file
- *(file)* index compatibility notes
- integrate main
- *(erratic)* compare CoreDNS scenarios
- Merge branch 'main' into m2-transfer
- *(compatibility)* drop stale not-implemented notes
- Merge branch 'main' into m2-transfer
- Merge branch 'main' into m2-view
- Merge branch 'main' into m2-template
- *(server)* clarify no-view overhead
- *(server)* note view dispatch cost
- *(transfer)* index compatibility notes
- *(template)* record compatibility limits
- *(view)* update compatibility index
- Merge branch 'main' into m2-engines
- *(template)* record integer range cap
- *(engines)* record compatibility limits
- *(reload)* wait for the new Listener
- *(reload)* exercise hung listener drain
- *(tsig)* satisfy fixture lint
- *(tsig)* pin unsigned Listener wire bytes
- *(server)* document signed transfer limits
- Merge branch 'main' into m2-tsig-dnssec
- *(tsig)* index compatibility notes
- *(server)* sync transfer compatibility notes
- record engine subset and gaps
- cite Plugin compatibility layout
- verify Plugin notes index
- move Plugin notes into folders
- main into m2-server-plugins
- *(cli)* update compatibility expectations
