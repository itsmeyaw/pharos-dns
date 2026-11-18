# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/itsmeyaw/pharos-dns/compare/pharos-proto-v0.1.0...pharos-proto-v0.2.0) - 2026-11-18

### Added

- *(proto)* write uncompressed Zone RDATA
- *(tsig)* verify and sign valid queries
- *(proto)* build messages in fixed storage
- *(rewrite)* rewrite DNAME targets
- *(proto)* parse names into fixed storage
- *(rewrite)* add exact name rewrite
- *(rewrite)* add type and class rules

### Fixed

- *(proto)* walk original questions for flag safety
- *(tsig)* honor response MAC length
- *(proto)* snapshot RRSIG parse time
- *(rcode)* isolate BADVERS display override
- *(zone)* scope raw UTF-8 rejection to names
- *(rcode)* display value 16 as BADVERS
- *(zone)* encode NXT TYPE30 bitmap
- *(rdata)* preserve NAPTR wire octets
- *(edns)* preserve received EDE text bytes
- *(names)* reject raw non-ASCII presentation
- *(proto)* reject ambiguous RRSIG time window
- *(proto)* validate RFC 6742 §2.4.1.2 names
- *(proto)* display RFC 6895 §2.3 RCODE 16
- *(proto)* validate RFC 8914 and RFC 7871 options
- *(proto)* validate RFC master-file formats
- *(proto)* preserve RFC 1035 §5.1 octets
- *(proto)* bound RFC 4034 RRSIG timestamps
- *(proto)* skip TKEYs in NOTIFY ignored sections
- *(proto)* normalize ignored wire fields
- *(dns)* bound parser walks and enforce controls
- *(edns)* advertise responder capacity
- *(proto)* cap TTLs and relax ISDN minimum
- *(proto)* honor wire-format RFC rules
- *(dns)* preserve TSIG and bound error recovery
- *(dnssec)* keep Additional signature groups atomic
- *(dns)* ignore NOTIFY ancillary sections
- *(server)* cap UDP response size
- *(dns)* tighten protocol edge handling
- *(dnssec)* omit optional Additional RRsets atomically
- *(server)* honor clamped EDNS payload size
- *(dns)* bound parsing and correct DS routing
- *(proto)* ignore sections on NOTIFY requests
- *(proto)* filter response ECS options
- *(proto)* correct response OPT fields
- *(proto)* classify DNS responses correctly
- *(proto)* remove compression hop limit
- *(proto)* validate NOTIFY and SIG0 messages
- *(proto)* enforce builder wire rules
- *(proto)* reject duplicate TKEY records
- *(proto)* validate RDATA encodings
- *(proto)* enforce zone record rules
- *(rewrite)* register EDNS codes globally

### Other

- *(proto)* expect RFC rejects in miekg differential
- format
- Merge branch 'fix-129'
- *(proto)* format compression lookup
- *(proto)* avoid reparsing compression targets
- *(proto)* compare compression with original
- *(proto)* remove redundant AMTRELAY mask
- *(proto)* verify AMTRELAY encoding bounds
- rem/secondary RFC conformance fixes
- rem/fwdtsig RFC conformance fixes
- rem/dnssec RFC conformance fixes
- *(proto)* verify truncated response MAC
- *(proto)* size copied Name exactly (RFC 1035 §3.1)
- *(proto)* exclude LP from opaque round-trip data
- *(zone)* cover generic NSEC zero windows
- *(proto)* inject RRSIG timestamp reference
- *(proto)* format RFC 3597 §5 changes
- Merge branch 'conf/server' into integrate
- Merge branch 'conf/dnssec' into integrate
- *(proto)* compare generic oracle mutations
- *(proto)* format live oracle assertion
- *(proto)* restore DNSSEC coverage
- *(server)* share UDP response sizing
- *(router)* borrow configured domain names
- *(dns)* centralize response OPT sizing
- *(dnssec)* avoid Additional group buffers
- *(plugins)* cover negative response consumers
- cite EDNS and upstream AD rules
- clarify DNS edge-case citations
- *(proto)* cover reserved Z masking
- *(pharos-proto)* cite spec sections above protocol logic
- UDP first memory allocation
- format transfer helpers
- *(proto)* cover RDATA error variants
- *(proto)* [**breaking**] type zone RDATA errors
- *(interop)* require tools during checks
- *(proto)* cite response classification
- *(proto)* cite name encoding standards
- *(proto)* cite zone parsing standards
- main into m2-query-plugins
