# Conformance report

Date: 2026-11-14. Audited commit: `5e03984ad459c8ed30d11896117b7cd6ebc44752` (all line numbers refer to it). Documents: 117.

Code-only audit (no compile or live testing). Each document was walked section by section (spec-down) and each source file behaviour by behaviour (code-up); rows found by only one sweep were re-audited, then every fragment was verified. Only requirements identified as non-conformant in the audited commit are listed below; later branch status appears in the row notes. Per-section coverage ledgers stay in `target/conformance/`.

Summary counts describe the audited commit and do not include later branch fixes. Row notes track those fixes; `Fixed` means the named branch contains the fix and is not a claim that it has merged. `Documented` is independent of status and means a README, ADR, or compatibility note records the behavior.

## Summary (audited commit)

| Document | Conformant | N/A | Deviation | Violation | Partial | Missing | Documented: No (audited commit) | Cite lines |
|---|---|---|---|---|---|---|---|---|
| RFC 1034: Domain names - concepts and facilities | 45 | 46 | 8 | 35 | 10 | 0 | 41 | 42 |
| RFC 1035: Domain names - implementation and specification | 131 | 58 | 10 | 45 | 23 | 0 | 67 | 285 |
| RFC 1183: New DNS RR Definitions | 19 | 10 | 0 | 5 | 2 | 2 | 9 | 7 |
| RFC 1348: DNS NSAP RRs | 1 | 5 | 0 | 0 | 1 | 0 | 1 | 2 |
| RFC 1706: DNS NSAP Resource Records | 4 | 12 | 1 | 2 | 2 | 0 | 4 | 1 |
| RFC 1712: DNS Encoding of Geographical Location | 5 | 8 | 0 | 2 | 3 | 0 | 5 | 3 |
| RFC 1876: A Means for Expressing Location Information in the Domain Name System | 9 | 12 | 0 | 3 | 2 | 0 | 4 | 3 |
| RFC 1982: Serial Number Arithmetic | 15 | 13 | 0 | 4 | 1 | 0 | 5 | 4 |
| RFC 1995: Incremental Zone Transfer in DNS | 11 | 21 | 0 | 3 | 2 | 0 | 3 | 8 |
| RFC 1996: A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY) | 13 | 12 | 0 | 11 | 6 | 0 | 14 | 11 |
| RFC 2136: Dynamic Updates in the Domain Name System (DNS UPDATE) | 127 | 53 | 0 | 6 | 18 | 1 | 25 | 30 |
| RFC 2163: Using the Internet DNS to Distribute MIXER Conformant Global Address Mapping (MCGAM) | 9 | 34 | 0 | 1 | 1 | 0 | 2 | 2 |
| RFC 2181: Clarifications to the DNS Specification | 22 | 21 | 1 | 15 | 8 | 1 | 24 | 21 |
| RFC 2230: Key Exchange Delegation Record for the DNS | 8 | 23 | 0 | 0 | 1 | 2 | 3 | 2 |
| RFC 2308: Negative Caching of DNS Queries (DNS NCACHE) | 13 | 16 | 3 | 17 | 7 | 1 | 25 | 18 |
| RFC 2535: Domain Name System Security Extensions | 1 | 155 | 0 | 1 | 0 | 0 | 1 | 1 |
| RFC 2606: Reserved Top Level DNS Names | 2 | 7 | 0 | 5 | 2 | 0 | 5 | 0 |
| RFC 2782: A DNS RR for specifying the location of services (DNS SRV) | 7 | 27 | 0 | 2 | 2 | 0 | 4 | 20 |
| RFC 2930: Secret Key Establishment for DNS (TKEY RR) | 3 | 42 | 0 | 2 | 6 | 0 | 8 | 2 |
| RFC 3007: Secure Domain Name System (DNS) Dynamic Update | 19 | 27 | 0 | 0 | 5 | 0 | 5 | 16 |
| RFC 3110: RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS) | 5 | 15 | 0 | 3 | 0 | 0 | 1 | 0 |
| RFC 3123: A DNS RR Type for Lists of Address Prefixes (APL RR) | 27 | 11 | 0 | 0 | 0 | 0 | 0 | 14 |
| RFC 3225: Indicating Resolver Support of DNSSEC | 11 | 8 | 0 | 3 | 1 | 0 | 3 | 8 |
| RFC 3226: DNSSEC and IPv6 A6 aware server/resolver message size requirements | 3 | 18 | 0 | 1 | 1 | 0 | 2 | 2 |
| RFC 3339: Date and Time on the Internet: Timestamps | 9 | 22 | 0 | 2 | 0 | 0 | 2 | 5 |
| RFC 3403: Dynamic Delegation Discovery System (DDDS) Part Three: The Domain Name System (DNS) Database | 11 | 32 | 0 | 2 | 1 | 0 | 3 | 9 |
| RFC 3425: Obsoleting IQUERY | 1 | 8 | 0 | 0 | 0 | 0 | 0 | 2 |
| RFC 3596: DNS Extensions to Support IP Version 6 | 8 | 10 | 0 | 4 | 0 | 0 | 4 | 14 |
| RFC 3597: Handling of Unknown DNS Resource Record (RR) Types | 12 | 11 | 0 | 3 | 6 | 0 | 6 | 13 |
| RFC 3849: IPv6 Address Prefix Reserved for Documentation | 1 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC 4007: IPv6 Scoped Address Architecture | 2 | 19 | 2 | 2 | 5 | 0 | 7 | 4 |
| RFC 4025: A Method for Storing IPsec Keying Material in DNS | 14 | 21 | 0 | 1 | 3 | 0 | 4 | 9 |
| RFC 4033: DNS Security Introduction and Requirements | 6 | 31 | 0 | 1 | 4 | 0 | 4 | 5 |
| RFC 4034: Resource Records for the DNS Security Extensions | 91 | 24 | 3 | 12 | 6 | 0 | 12 | 54 |
| RFC 4035: Protocol Modifications for the DNS Security Extensions | 61 | 157 | 3 | 19 | 6 | 0 | 23 | 36 |
| RFC 4255: Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints | 4 | 14 | 1 | 0 | 0 | 0 | 0 | 4 |
| RFC 4291: IP Version 6 Addressing Architecture | 6 | 26 | 0 | 0 | 1 | 0 | 1 | 9 |
| RFC 4343: Domain Name System (DNS) Case Insensitivity Clarification | 11 | 7 | 1 | 4 | 4 | 0 | 7 | 23 |
| RFC 4398: Storing Certificates in the Domain Name System (DNS) | 7 | 26 | 0 | 1 | 2 | 0 | 3 | 3 |
| RFC 4408: Sender Policy Framework (SPF) for Authorizing Use of Domains in E-Mail, Version 1 | 2 | 79 | 0 | 0 | 0 | 0 | 0 | 1 |
| RFC 4431: The DNSSEC Lookaside Validation (DLV) DNS Resource Record | 7 | 5 | 0 | 0 | 0 | 0 | 0 | 5 |
| RFC 4470: Minimally Covering NSEC Records and DNSSEC On-line Signing | 2 | 6 | 4 | 2 | 1 | 0 | 3 | 1 |
| RFC 4509: Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records (RRs) | 8 | 12 | 0 | 0 | 1 | 0 | 1 | 6 |
| RFC 4592: The Role of Wildcards in the Domain Name System | 24 | 20 | 1 | 5 | 3 | 0 | 8 | 15 |
| RFC 4632: Classless Inter-domain Routing (CIDR): The Internet Address Assignment and Aggregation Plan | 2 | 25 | 0 | 0 | 0 | 0 | 0 | 5 |
| RFC 4648: The Base16, Base32, and Base64 Data Encodings | 18 | 16 | 1 | 0 | 1 | 0 | 1 | 11 |
| RFC 4701: A DNS Resource Record (RR) for Encoding Dynamic Host Configuration Protocol (DHCP) Information (DHCID RR) | 5 | 22 | 0 | 0 | 0 | 0 | 0 | 3 |
| RFC 5001: DNS Name Server Identifier (NSID) Option | 9 | 14 | 0 | 0 | 1 | 0 | 1 | 10 |
| RFC 5155: DNS Security (DNSSEC) Hashed Authenticated Denial of Existence | 57 | 89 | 0 | 12 | 6 | 0 | 17 | 25 |
| RFC 5452: Measures for Making DNS More Resilient against Forged Answers | 6 | 27 | 0 | 2 | 6 | 2 | 9 | 6 |
| RFC 5625: DNS Proxy Implementation Guidelines | 14 | 14 | 2 | 2 | 3 | 0 | 4 | 9 |
| RFC 5702: Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC | 10 | 19 | 0 | 2 | 0 | 0 | 2 | 4 |
| RFC 5737: IPv4 Address Blocks Reserved for Documentation | 0 | 10 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC 5936: DNS Zone Transfer Protocol (AXFR) | 86 | 22 | 2 | 14 | 8 | 0 | 22 | 54 |
| RFC 5952: A Recommendation for IPv6 Address Text Representation | 15 | 34 | 0 | 0 | 0 | 0 | 0 | 7 |
| RFC 5958: Asymmetric Key Packages | 2 | 18 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC 6052: IPv6 Addressing of IPv4/IPv6 Translators | 9 | 43 | 0 | 3 | 2 | 0 | 5 | 5 |
| RFC 6147: DNS64: DNS Extensions for Network Address Translation from IPv6 Clients to IPv4 Servers | 29 | 36 | 0 | 9 | 6 | 3 | 16 | 15 |
| RFC 6303: Locally Served DNS Zones | 8 | 14 | 0 | 4 | 3 | 5 | 11 | 7 |
| RFC 6604: xNAME RCODE and Status Bits Clarification | 1 | 7 | 0 | 2 | 0 | 0 | 2 | 4 |
| RFC 6605: Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC | 8 | 12 | 0 | 0 | 1 | 0 | 1 | 4 |
| RFC 6672: DNAME Redirection in the DNS | 20 | 36 | 0 | 13 | 2 | 2 | 17 | 14 |
| RFC 6698: The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA | 13 | 56 | 0 | 0 | 1 | 0 | 1 | 8 |
| RFC 6742: DNS Resource Records for the Identifier-Locator Network Protocol (ILNP) | 32 | 37 | 0 | 4 | 5 | 0 | 9 | 8 |
| RFC 6761: Special-Use Domain Names | 4 | 34 | 0 | 10 | 4 | 3 | 15 | 3 |
| RFC 6781: DNSSEC Operational Practices, Version 2 | 7 | 55 | 1 | 0 | 16 | 1 | 17 | 5 |
| RFC 6840: Clarifications and Implementation Notes for DNS Security (DNSSEC) | 6 | 41 | 0 | 2 | 0 | 0 | 2 | 7 |
| RFC 6891: Extension Mechanisms for DNS (EDNS(0)) | 32 | 52 | 0 | 6 | 2 | 0 | 8 | 26 |
| RFC 6895: Domain Name System (DNS) IANA Considerations | 20 | 21 | 1 | 5 | 5 | 0 | 10 | 13 |
| RFC 7043: Resource Records for EUI-48 and EUI-64 Addresses in the DNS | 11 | 11 | 0 | 0 | 2 | 0 | 2 | 3 |
| RFC 7208: Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1 | 0 | 129 | 0 | 2 | 0 | 0 | 2 | 1 |
| RFC 7344: Automating DNSSEC Delegation Trust Maintenance | 13 | 47 | 1 | 0 | 1 | 0 | 1 | 12 |
| RFC 7468: Textual Encodings of PKIX, PKCS, and CMS Structures | 7 | 43 | 0 | 0 | 2 | 0 | 2 | 3 |
| RFC 7477: Child-to-Parent Synchronization in DNS | 11 | 51 | 0 | 2 | 0 | 0 | 2 | 5 |
| RFC 7553: The Uniform Resource Identifier (URI) DNS Resource Record | 10 | 24 | 0 | 2 | 0 | 0 | 1 | 6 |
| RFC 7757: Explicit Address Mappings for Stateless IP/ICMP Translation | 3 | 26 | 0 | 0 | 4 | 0 | 3 | 1 |
| RFC 7766: DNS Transport over TCP - Implementation Requirements | 27 | 23 | 3 | 7 | 2 | 0 | 8 | 24 |
| RFC 7828: The edns-tcp-keepalive EDNS0 Option | 8 | 23 | 0 | 4 | 3 | 1 | 8 | 6 |
| RFC 7871: Client Subnet in DNS Queries | 20 | 59 | 0 | 16 | 10 | 10 | 36 | 9 |
| RFC 7929: DNS-Based Authentication of Named Entities (DANE) Bindings for OpenPGP | 5 | 64 | 0 | 0 | 2 | 0 | 2 | 1 |
| RFC 8005: Host Identity Protocol (HIP) Domain Name System (DNS) Extension | 24 | 27 | 0 | 2 | 0 | 0 | 2 | 8 |
| RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2 | 17 | 48 | 1 | 0 | 0 | 0 | 0 | 11 |
| RFC 8020: NXDOMAIN: There Really Is Nothing Underneath | 2 | 17 | 2 | 0 | 2 | 1 | 3 | 3 |
| RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA) | 15 | 45 | 0 | 0 | 0 | 0 | 0 | 5 |
| RFC 8078: Managing DS Records from the Parent via CDS/CDNSKEY | 2 | 24 | 0 | 0 | 1 | 0 | 1 | 1 |
| RFC 8080: Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC | 3 | 14 | 0 | 1 | 0 | 0 | 1 | 5 |
| RFC 8162: Using Secure DNS to Associate Certificates with Domain Names for S/MIME | 3 | 29 | 0 | 0 | 0 | 0 | 0 | 2 |
| RFC 8482: Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY | 8 | 26 | 5 | 2 | 2 | 0 | 4 | 3 |
| RFC 8490: DNS Stateful Operations | 8 | 165 | 0 | 9 | 0 | 0 | 9 | 4 |
| RFC 8659: DNS Certification Authority Authorization (CAA) Resource Record | 9 | 41 | 0 | 2 | 2 | 0 | 4 | 5 |
| RFC 8749: Moving DNSSEC Lookaside Validation (DLV) to Historic Status | 0 | 15 | 0 | 0 | 1 | 0 | 1 | 0 |
| RFC 8767: Serving Stale Data to Improve DNS Resiliency | 7 | 17 | 1 | 3 | 0 | 0 | 1 | 9 |
| RFC 8777: DNS Reverse IP Automatic Multicast Tunneling (AMT) Discovery | 11 | 84 | 0 | 5 | 1 | 0 | 6 | 5 |
| RFC 8914: Extended DNS Errors | 15 | 34 | 0 | 2 | 5 | 0 | 7 | 10 |
| RFC 8945: Secret Key Transaction Authentication for DNS (TSIG) | 79 | 32 | 5 | 4 | 7 | 3 | 14 | 46 |
| RFC 8976: Message Digest for DNS Zones | 14 | 84 | 0 | 3 | 1 | 0 | 3 | 9 |
| RFC 9077: NSEC and NSEC3: TTLs and Aggressive Use | 0 | 18 | 0 | 2 | 0 | 0 | 2 | 0 |
| RFC 9110: HTTP Semantics | 93 | 323 | 1 | 18 | 6 | 0 | 24 | 42 |
| RFC 9276: Guidance for NSEC3 Parameter Settings | 3 | 30 | 0 | 2 | 0 | 0 | 2 | 1 |
| RFC 9293: Transmission Control Protocol (TCP) | 2 | 324 | 0 | 1 | 0 | 0 | 0 | 0 |
| RFC 9432: DNS Catalog Zones | 25 | 20 | 0 | 4 | 5 | 2 | 11 | 20 |
| RFC 9460: Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records) | 50 | 144 | 1 | 8 | 4 | 0 | 10 | 24 |
| RFC 9471: DNS Glue Requirements in Referral Responses | 6 | 18 | 0 | 1 | 1 | 0 | 2 | 2 |
| RFC 9499: DNS Terminology | 0 | 21 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC 9520: Negative Caching of DNS Resolution Failures | 5 | 23 | 0 | 2 | 3 | 1 | 5 | 8 |
| RFC 9540: Discovery of Oblivious Services via Service Binding Records | 1 | 27 | 0 | 0 | 0 | 0 | 0 | 2 |
| RFC 9606: DNS Resolver Information | 2 | 33 | 0 | 1 | 3 | 0 | 4 | 2 |
| RFC 9619: In the DNS, QDCOUNT Is (Usually) One | 2 | 18 | 0 | 0 | 0 | 0 | 0 | 1 |
| RFC 9824: Compact Denial of Existence in DNSSEC | 10 | 17 | 0 | 2 | 3 | 1 | 6 | 9 |
| RFC 9904: DNSSEC Cryptographic Algorithm Recommendation Update Process | 13 | 30 | 0 | 1 | 2 | 0 | 3 | 7 |
| RFC 9905: Deprecating the Use of SHA-1 in DNSSEC Signature Algorithms | 7 | 17 | 0 | 1 | 0 | 0 | 1 | 0 |
| KEP-563: IPv4/IPv6 dual-stack | 11 | 99 | 0 | 0 | 0 | 0 | 0 | 15 |
| KEP-752: EndpointSlice API | 12 | 78 | 0 | 0 | 1 | 0 | 1 | 18 |
| KEP-1645: Multi-Cluster Services API | 38 | 87 | 3 | 1 | 3 | 0 | 2 | 28 |
| KEP-1672: Tracking terminating endpoints | 1 | 62 | 0 | 0 | 0 | 0 | 0 | 1 |
| KEP-2433: Topology aware hints | 0 | 61 | 0 | 0 | 0 | 0 | 0 | 0 |
| k8s-dns: Kubernetes DNS-Based Service Discovery | 11 | 3 | 0 | 4 | 17 | 0 | 6 | 22 |
| **Total** | 1834 | 4601 | 68 | 428 | 315 | 42 | 721 | 1372 |

## RFC 1034: Domain names - concepts and facilities

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.2 AXFR Response | `crates/pharos-server/src/transfer.rs:195-217`, `crates/pharos-plugins/src/secondary/update.rs:87-130` | **Fixed**: AXFR clients validate the closing SOA against the opening SOA before publishing the transfer. Fixed on `conf/secondary` (#98). | No |
| §2.2 AXFR Response | `crates/pharos-plugins/src/secondary/update.rs:92-127`, `crates/pharos-plugins/src/zone/mod.rs:135-198` | **Fixed**: The secondary validates AXFR framing and drops duplicate records; Zone construction suppresses duplicate RRs. Fixed on `conf/secondary` (#98) and `conf/zone` (#95). | No |
| §3 Negative Answers from Authoritative Servers | `crates/pharos-plugins/src/zone/mod.rs:827-853`, `crates/pharos-plugins/src/zone/mod.rs:445-457` | **Fixed**: Negative SOA and matching SOA RRSIG TTLs use the minimum of SOA TTL and SOA.MINIMUM. Fixed on `conf/zone` (#95). | No |
| §3.1 Name space specifications and terminology | `crates/pharos-plugins/src/zone/mod.rs:140-151,173-182` | **Fixed**: Zone owners, apex, and name-bearing RDATA preserve case while DNS comparisons remain ASCII case-insensitive. Fixed on `conf/zone` (#95). | No |
| §3.1.3.4 Including NSEC RRs: Wildcard No Data Response | `crates/pharos-plugins/src/zone/mod.rs:855-867,931-949` | **Fixed**: Wildcard NODATA includes the closest-encloser proof. Fixed on `conf/zone` (#95). | No |
| §3.2 Glue for Sibling Domain Name Servers | `crates/pharos-plugins/src/zone/mod.rs:963-982` | **Fixed**: Available sibling nameserver glue is included. Fixed on `conf/zone` (#95). | No |
| §3.3.1 Closest Encloser and the Source of Synthesis | `crates/pharos-plugins/src/zone/mod.rs:541-580` | **Fixed**: An existing empty non-terminal blocks wildcard synthesis. Fixed on `conf/zone` (#95). | No |
| §3.6 Resource Records — zero TTL | `crates/pharos-plugins/src/cache/mod.rs:593-618,625-652`; `crates/pharos-plugins/src/cache/setup.rs:49-56` | **Deviation**: The configured positive minimum raises zero-TTL answers before cache admission; default is five seconds. This retained CoreDNS-compatible behavior is documented in `docs/compatibility.md` (RFC 1035 §3.2.1; RFC 8767 §4; conf/cache #97). | Yes |
| §3.6.2 Aliases and canonical names — CNAME exclusivity | `crates/pharos-plugins/src/zone/mod.rs:135-188` | **Fixed**: Static zone loading enforces CNAME exclusivity and a single target, while allowing permitted DNSSEC records. Fixed on `conf/zone` (#95). | No |
| §3.6.2 Aliases and canonical names — CNAME restart QTYPEs | `crates/pharos-plugins/src/template/mod.rs:665-675` | **Partial**: Template follows a CNAME target only for A and AAAA queries; RFC 1034 requires restarting every non-CNAME query at the target. | Yes |
| §3.6.2 Aliases and canonical names — bounded CNAME chains | `crates/pharos-plugins/src/rewrite/mod.rs:2171-2173,2219-2232` | **Partial**: Rewrite follows CNAME targets only through its self-lookup depth limit; later targets are skipped, so long chains are not fully followed. The README documents the CoreDNS-compatible depth limit. | Yes |
| §3.6.2 Aliases and canonical names — loops | `crates/pharos-plugins/src/zone/mod.rs:599-627,664-687` | **Violation**: Self-loops return SERVFAIL, but multi-name loops can still return a partial CNAME chain with NOERROR. Existing README documentation covers only the depth limit, not multi-name cycles; Documented is No. | No |
| §3.6.2 Aliases and canonical names — matching class | `crates/pharos-plugins/src/zone/mod.rs:612-627`, `crates/pharos-plugins/src/autopath/mod.rs:338-343` | **Partial**: Zone lookup now falls through on a mismatched class (fixed on `conf/zone`, #95); autopath's CNAME class handling remains open and is outside that branch's scope. | No |
| §3.6.2 Aliases and canonical names — rewrite-loop errors | `crates/pharos-plugins/src/rewrite/mod.rs:2166-2173,2219-2232`, `crates/pharos-plugins/tests/functional/rewrite.rs:409-457` | **Violation**: A CNAME loop that reaches the depth limit returns the last successful response with NOERROR instead of signaling an error. The README documents the limit, not this response behavior. | No |
| §3.7.1 Standard queries — QCLASS matching | `crates/pharos-plugins/src/zone/mod.rs:277-287,639-666,796-810`, `crates/pharos-plugins/src/k8s_external/mod.rs:181-207,258-275,335-347,858-899` | **Partial**: Zone and local handlers now fall through on non-IN queries (conf/zone #95; conf/plugins-synth #102); the `k8s_external` class path remains unverified and open. | No |
| §3.7.1 Standard queries — QCLASS=* authority | `crates/pharos-plugins/src/zone/mod.rs:705-709` | **Fixed**: QCLASS=* responses no longer set AA. Fixed on `conf/zone` (#95). | No |
| §4 Behavior of DNS Responders | `crates/pharos-plugins/src/any/mod.rs:10-17,32-47` | **Deviation**: `Any` synthesizes HINFO without checking whether QNAME exists, bypassing normal NXDOMAIN and wildcard processing for nonexistent names. The README documents that HINFO is synthesized before consulting a Backend. | Yes |
| §4 Serving Stale Data | `crates/pharos-plugins/src/cache/setup.rs:60,139-179`, `crates/pharos-plugins/src/cache/store.rs:179-187` | **Fixed**: Stale answers use a positive TTL; the default is 30 seconds. Fixed on `conf/cache` (#97). | No |
| §4.1 DNS Output Case Preservation | `crates/pharos-plugins/src/zone/mod.rs:147-151,794-810` | **Fixed**: Zone answers preserve configured name case. Fixed on `conf/zone` (#95). | No |
| §4.2 Answer with a Synthesized HINFO RRset | `crates/pharos-plugins/src/any/mod.rs:10-17,32-47` | **Deviation**: The plugin synthesizes HINFO even when QNAME owns a CNAME. RFC 8482 §4.2 only permits this synthesis when no CNAME is present. The README records this CoreDNS-compatible behavior. | Yes |
| §4.2 Answer with a Synthesized HINFO RRset | `crates/pharos-plugins/src/any/mod.rs:37-47` | **Deviation**: For DO queries at signed names, the synthesized HINFO has no RRSIG, contrary to the MUST requirement. The README records that this plugin cannot include an RRSIG. | Yes |
| §4.2 Answer with a Synthesized HINFO RRset | `crates/pharos-plugins/src/any/mod.rs:37-47` | **Partial**: CPU now uses `RFC8482`; OS remains `See RFC 8482` as a documented CoreDNS-compatible value (conf/plugins-synth #102; RFC 8482 §4.2). | Yes |
| §4.2 Answer with a Synthesized HINFO RRset | `crates/pharos-plugins/src/any/mod.rs:39-45`, `crates/pharos-plugins/src/any/setup.rs:1-12` | **Fixed**: HINFO TTL is configurable. Fixed on `conf/plugins-synth` (#102). | No |
| §4.2 DNS Input Case Preservation | `crates/pharos-plugins/src/zone/mod.rs:147-151,173-174` | **Fixed**: Zone construction preserves case in owners and name-bearing RDATA. Fixed on `conf/zone` (#95). | No |
| §4.2 How the database is divided into zones | `crates/pharos-plugins/src/zone/mod.rs:277-286`, `crates/pharos-server/src/admission.rs:53-56` | **Fixed**: Mixed-class master files are rejected and queries do not cross zone classes. Fixed on `conf/zone` (#95). | No |
| §4.2.1 Technical considerations — zone apex records | `crates/pharos-plugins/src/zone/mod.rs:135-190`, `crates/pharos-plugins/src/dynupdate/update.rs:23-83` | **Partial**: Apex NS enforcement remains deferred on `conf/zone` (#95) because it needs fixture updates in unowned Auto tests; dynamic zones also lack the check. | No |
| §4.3.1 Queries and responses — QCLASS selection | `crates/pharos-plugins/src/zone/mod.rs:277-287,639-666,796-810`, `crates/pharos-plugins/src/local/mod.rs:120-132,169-195` | **Fixed**: Zone and local handlers pass non-IN questions to the next plugin. Fixed on `conf/zone` (#95) and `conf/plugins-synth` (#102). | No |
| §4.3.1 Queries and responses — recursion availability | `crates/pharos-plugins/src/zone/mod.rs:698-721`, `crates/pharos-plugins/src/local/mod.rs:161-165`, `crates/pharos-plugins/src/any/mod.rs:28-32`, `crates/pharos-plugins/src/chaos/mod.rs:106-111`, `crates/pharos-server/src/admission.rs:77-86` | **Partial**: RA remains deferred on `conf/plugins-synth` (#102): plugin Context lacks per-server recursion availability, and shared error-response paths need role propagation. | No |
| §4.3.2 Algorithm — ANY handling | `crates/pharos-plugins/src/any/mod.rs:18-47` | **Deviation**: The handler synthesizes HINFO without the zone/cache lookup needed for name errors, referrals, or CNAME processing. The plugin README records this CoreDNS-compatible pre-backend response. | Yes |
| §4.3.2 Algorithm — Kubernetes CNAME response | `crates/pharos-plugins/src/kubernetes/mod.rs:1085-1097` | **Fixed**: ExternalName CNAMEs are returned for every QTYPE, including when target Self Lookup fails. Fixed on `conf/k8s` (#103). | Yes |
| §4.3.2 Algorithm — RA flag | `crates/pharos-plugins/src/header/mod.rs:61-72,85-90` | **Deviation**: Header rules can make RA misstate recursive-service availability. The README describes configurable response-flag changes. | Yes |
| §4.3.2 Algorithm — RD flag | `crates/pharos-plugins/src/header/mod.rs:61-72,85-87` | **Deviation**: Header rules can set RD before later plugins process a query whose original RD bit was clear. The README describes query-flag rewriting as intentional header-plugin behavior. | Yes |
| §4.3.2 Algorithm — apex name with absent QTYPE | `crates/pharos-plugins/src/zone/mod.rs:541-544,676-688`, `crates/pharos-plugins/tests/functional/file_coredns.rs:1007-1015` | **Deviation**: An apex-only zone returns NOERROR/NODATA for an absent QTYPE, following the RFC rather than CoreDNS v1.15.0's NXDOMAIN behavior for an SOA/NS-only apex. Recorded in `docs/compatibility.md` (RFC 2308 §2.2; conf/zone #95). | Yes |
| §4.3.2 Algorithm — authoritative local name errors | `crates/pharos-plugins/src/local/mod.rs:135,161-166` | **Fixed**: Local-zone name errors set AA. Fixed on `conf/plugins-synth` (#102). | No |
| §4.3.2 Algorithm — missing hosts names | `crates/pharos-plugins/src/hosts/mod.rs:303-316` | **Deviation**: Unmapped names return authoritative NXDOMAIN with synthetic SOA instead of CoreDNS's SERVFAIL. Recorded in `docs/compatibility.md` (RFC 1034 §4.3.2; RFC 2308 §3; conf/plugins-synth #102). | Yes |
| §4.3.2 Algorithm — rewrite CNAME depth limit | `crates/pharos-plugins/src/rewrite/mod.rs:2171-2173,2219-2232` | **Partial**: Rewrite follows a CNAME with self-lookup only through depth 8; deeper targets are skipped instead of continuing the canonical-name lookup. The README records the CoreDNS-compatible limit. | Yes |
| §4.3.3 Wildcards | `crates/pharos-plugins/src/zone/mod.rs:563-580` | **Fixed**: Existing empty non-terminals block wildcard synthesis. Fixed on `conf/zone` (#95). | No |
| §4.3.3 Wildcards | `crates/pharos-plugins/src/cache/mod.rs:153-169,625-647` | **Fixed**: Explicit wildcard QNAMEs bypass cache admission. Fixed on `conf/cache` (#97). | No |
| §4.3.5 Zone maintenance and transfers — Kubernetes serial updates | `crates/pharos-kubernetes/src/store.rs:1322-1336,1381-1390,1540-1547` | **Deviation**: Service IP and endpoint target-name changes signal readers but do not advance the SOA serial. The Kubernetes plugin README records these CoreDNS-compatible cases; ADR 0002 permits compatibility where deployments depend on CoreDNS. | Yes |
| §4.3.5 Zone maintenance and transfers — Namespace serial updates | `crates/pharos-kubernetes/src/store.rs:870-877,1473-1498` | **Fixed**: Namespace membership changes advance the SOA serial when `require_namespace` is enabled. Fixed on `conf/k8s` (#103). | No |
| §4.3.5 Zone maintenance and transfers — expiry after failed SOA check | `crates/pharos-plugins/src/secondary/update.rs:208-210,227-232,316-328` | **Fixed**: Failed SOA checks enter retry and expiry handling; a successful unchanged check clears expired state. Fixed on `conf/secondary` (#98). | No |
| §4.3.5 Zone maintenance and transfers — retry after failed SOA check | `crates/pharos-plugins/src/secondary/update.rs:208-210,227-232,334-357` | **Fixed**: Failed SOA checks schedule RETRY rather than restarting REFRESH. Fixed on `conf/secondary` (#98). | No |
| §4.3.5 Zone maintenance and transfers — serial resolution | `crates/pharos-kubernetes/src/store.rs:862-868` | **Deviation**: SOA serial uses Unix time in whole seconds, so two changes in one second can reuse a value. The Kubernetes plugin README records this CoreDNS-compatible limitation. | Yes |
| §4.3.5 Zone maintenance and transfers — zero SOA timers | `crates/pharos-plugins/src/secondary/update.rs:258-265,317-320` | **Partial**: SOA timers retain a one-second floor to prevent immediate refresh/retry loops. Zero-timer semantics remain deferred on `conf/secondary` (#98). | No |
| §5 Caching Negative Answers | `crates/pharos-plugins/src/cache/mod.rs:767-779` | **Fixed**: NXDOMAIN keys and lookups use QNAME/QCLASS without QTYPE. Fixed on `conf/cache` (#97). | No |
| §5 Caching Negative Answers | `crates/pharos-plugins/src/cache/mod.rs:593-618`, `crates/pharos-plugins/src/cache/setup.rs:49-56,90-113` | **Fixed**: Negative TTLs are never raised above their SOA-derived lifetime. `denial_min_ttl` remains accepted but ignored; this compatibility behavior is recorded in `docs/compatibility.md`. Fixed on `conf/cache` (#97). | Yes |
| §5.2 RRSet TTLs | `crates/pharos-plugins/src/zone/mod.rs:145-188,445-457` | **Fixed**: Zone construction normalizes each RRset to its lowest TTL, including matching RRSIGs. Fixed on `conf/zone` (#95). | No |
| §5.3.2 Resolver resources | `crates/pharos-plugins/plugin.cfg:50-65`, `crates/pharos-plugins/src/cache/mod.rs:163-213` | **Partial**: Cache-before-file precedence remains; changing plugin order belongs to unowned `plugin.cfg` and was deferred on `conf/cache` (#97). | No |
| §5.3.3 Algorithm | `crates/pharos-plugins/src/cache/mod.rs:767-779`, `crates/pharos-plugins/src/cache/store.rs:157-161` | **Fixed**: NXDOMAIN hits are reusable across QTYPEs for the same QNAME/QCLASS. Fixed on `conf/cache` (#97). | No |
| §5.3.3 Algorithm — configured resolver | `crates/pharos-plugins/src/forward/resolve.rs:83-104` | **Fixed**: Resolver lookup validates ID/QR/Question/RCODE, follows CNAMEs up to 16 hops, and filters foreign-owner addresses. Fixed on `conf/forward` (#104). | No |
| §6 Negative Answers from the Cache | `crates/pharos-plugins/src/cache/store.rs:179-187`, `crates/pharos-plugins/src/cache/setup.rs:238-243` | **Fixed**: Negative TTLs age under `keepttl`. Fixed on `conf/cache` (#97). | No |
| §6 Zone Integrity | `crates/pharos-server/src/transfer.rs:195-217`, `crates/pharos-plugins/src/secondary/update.rs:135-154` | **Fixed**: The secondary rejects a transfer whose closing SOA differs from its opening SOA. Fixed on `conf/secondary` (#98). | No |
| §6.1 Zone authority | `crates/pharos-plugins/src/zone/mod.rs:189-191` | **Partial**: Requiring an apex NS remains deferred on `conf/zone` (#95): enforcement also requires updating SOA-only fixtures in unowned Auto tests. | No |

## RFC 1035: Domain names - implementation and specification

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.2 Common configurations | `crates/pharos-plugins/src/secondary/mod.rs:60-65`, `crates/pharos-plugins/src/secondary/setup.rs:90-100` | **Partial**: Pharos can retrieve and serve configured secondary zones, but it permits primary zones without a secondary and does not verify that every zone has redundant support. | No |
| §2.3.4 Size limits | `crates/pharos-corefile/src/key.rs:35,108-156` | **Deviation**: Wire names are limited to 255 octets, but CoreDNS's 255-byte presentation cap is retained for keys; it rejects some RFC-valid escaped names. CoreDNS v1.15.0 `plugin/normalize.go` and `core/dnsserver/register.go` establish the cap. Recorded in `docs/compatibility.md` under ADR 0003. | Yes |
| §3.1 Name space definitions | `crates/pharos-plugins/src/zone/mod.rs:145-151,173-183` | **Fixed**: Zone input preserves owner and name-bearing RDATA case; comparisons remain ASCII case-insensitive. Fixed on `conf/zone` (#95). | No |
| §3.2.1 Format | `crates/pharos-plugins/src/cache/mod.rs:593-650` | **Deviation**: When configured minimum TTL is positive, cache raises zero-TTL records to that minimum and caches them. The cache README records this CoreDNS-compatible behavior; RFC 1035 §3.2.1 says zero-TTL records are transaction-only and must not be cached. RFC 2181 §7.2 only removes the requirement to send SOA records with zero TTL. | Yes |
| §3.2.1 Format | `crates/pharos-plugins/src/zone/mod.rs:135-188,445-457` | **Fixed**: Zone RRsets are normalized to the minimum TTL. Fixed on `conf/zone` (#95). | No |
| §3.2.1 Format | `crates/pharos-plugins/src/zone/mod.rs:192-223,445-457` | **Fixed**: Duplicate RRs are suppressed during Zone construction. Fixed on `conf/zone` (#95). | No |
| §3.2.3 QTYPE values | `crates/pharos-plugins/src/any/mod.rs:15-47` | **Deviation**: RFC 8482 §4.2 permits synthesized HINFO only when no CNAME exists at QNAME. The plugin returns HINFO without checking for a CNAME; its README records this behavior. | Yes |
| §3.2.3 QTYPE values | `crates/pharos-plugins/src/any/mod.rs:18-48` | **Deviation**: RFC 8482 §4.2 requires a valid RRSIG when DO=1 for a known signed zone. The plugin returns HINFO without a signature; its README documents this limitation. | Yes |
| §3.2.3 QTYPE values | `crates/pharos-plugins/src/any/mod.rs:6-11,37-46`, `crates/pharos-plugins/src/any/setup.rs:1-12` | **Fixed**: The synthesized HINFO TTL is configurable. Fixed on `conf/plugins-synth` (#102). | No |
| §3.3.1 CNAME RDATA format (RFC 2181 §10.1) | `crates/pharos-plugins/src/zone/mod.rs:201-223`, `crates/pharos-plugins/src/file/tests.rs:169-180` | **Fixed**: Static Zone construction rejects multiple CNAME targets. Fixed on `conf/zone` (#95). | No |
| §3.3.1 CNAME RDATA format (RFC 2181 §10.1) | `crates/pharos-plugins/src/zone/mod.rs:135-223` | **Fixed**: Static Zone construction enforces CNAME exclusivity while permitting specified DNSSEC records. Fixed on `conf/zone` (#95). | No |
| §3.3.2 HINFO RDATA format | `crates/pharos-proto/src/zone/rdata.rs:167-193` | **Fixed**: HINFO master-file records require both CPU and OS character-strings. Fixed on `conf/proto` (#99). | No |
| §3.3.2 HINFO RDATA format (RFC 8482 §4.2 CPU field) | `crates/pharos-plugins/src/any/mod.rs:37-46` | **Fixed**: Synthesized HINFO uses CPU `RFC8482`. Fixed on `conf/plugins-synth` (#102). | No |
| §3.3.2 HINFO RDATA format (RFC 8482 §4.2 OS field) | `crates/pharos-plugins/src/any/mod.rs:37-46` | **Deviation**: Synthesized HINFO uses OS `See RFC 8482`, not RFC 8482's recommended null string; `any/README.md` records the CoreDNS-compatible synthesis. | Yes |
| §3.3.3 MB RDATA format | `crates/pharos-plugins/src/zone/mod.rs:984-996` | **Violation**: MB requires additional-section processing that looks up A records for MADNAME. The target selection omits MB. | No |
| §3.3.4 MD RDATA format | `crates/pharos-plugins/src/zone/mod.rs:984-996` | **Fixed**: RFC 1035 obsolete MD zone records are rejected instead of served without additional processing. Fixed on `conf/proto` (#99). | No |
| §3.3.4 MD RDATA format | `crates/pharos-proto/src/zone/rdata/legacy.rs:34-36` | **Fixed**: Obsolete MD master-file records are rejected. Fixed on `conf/proto` (#99). | No |
| §3.3.5 MF RDATA format | `crates/pharos-plugins/src/zone/mod.rs:984-996` | **Fixed**: Obsolete MF zone records are rejected instead of served without additional processing. Fixed on `conf/proto` (#99). | No |
| §3.3.5 MF RDATA format | `crates/pharos-proto/src/zone/rdata/legacy.rs:34-36` | **Fixed**: Obsolete MF master-file records are rejected under the section's published text. Fixed on `conf/proto` (#99). | No |
| §3.3.8 MR RDATA format | `crates/pharos-proto/src/rdata.rs:9-32,963-965`, `crates/pharos-proto/src/zone/rdata/legacy.rs:33-37` | **Partial**: Zone parsing accepts MR as one domain name, and generic RDATA can relocate it, but typed `Rdata::parse_in_message` rejects MR through `unsupported_name_type`. | No |
| §3.3.9 MX RDATA format | `crates/pharos-plugins/src/zone/mod.rs:145-187,984-1022` | **Fixed**: Zone loading rejects MX targets that are CNAME aliases. Fixed on `conf/zone` (#95). | No |
| §3.3.9 MX RDATA format | `crates/pharos-plugins/src/zone/mod.rs:984-1022` | **Partial**: Alias checks are fixed on `conf/zone` (#95); requiring address RRsets remains deferred because targets can be out of zone and need cross-zone validation. | No |
| §3.3.9 MX RDATA format | `crates/pharos-proto/src/zone/rdata.rs:409-501` | **Fixed**: Malformed generic MX RDATA layouts are rejected instead of normalized. Fixed on `conf/proto` (#99). | No |
| §3.3.11 NS RDATA format | `crates/pharos-plugins/src/zone/mod.rs:145-187,984-1022` | **Fixed**: Zone loading rejects NS targets that are CNAME aliases. Fixed on `conf/zone` (#95). | No |
| §3.3.11 NS RDATA format | `crates/pharos-plugins/src/zone/mod.rs:984-1022` | **Partial**: Alias checks are fixed on `conf/zone` (#95); requiring address RRsets remains deferred because targets can be out of zone and need cross-zone validation. | No |
| §3.3.12 PTR RDATA format | `crates/pharos-plugins/src/zone/mod.rs:145-187` | **Fixed**: Zone loading rejects PTR targets that are CNAME aliases. Fixed on `conf/zone` (#95). | No |
| §3.3.13 SOA RDATA format | `crates/pharos-plugins/src/zone/mod.rs:445-457, 827-853` | **Fixed**: Negative SOA TTLs are capped at `min(SOA TTL, SOA.MINIMUM)`, including the SOA RRSIG. Fixed on `conf/zone` (#95). | No |
| §3.4.1 A RDATA format | `crates/pharos-plugins/src/whoami/mod.rs:24-30,71-80` | **Fixed**: `whoami` emits IN-class A records and passes non-IN Questions through. Fixed on `conf/plugins-synth` (#102). | No |
| §3.4.1 A RDATA format | `crates/pharos-proto/src/zone/rdata.rs:409-477` | **Fixed**: Malformed generic A RDATA layouts are rejected. Fixed on `conf/proto` (#99). | No |
| §3.4.2 WKS RDATA format | `crates/pharos-proto/src/codes.rs:97-188`, `crates/pharos-proto/src/zone.rs:912-920`, `crates/pharos-proto/src/rdata.rs:963-965` | **Partial**: WKS mnemonic and opaque generic RDATA are supported (conf/proto #99); typed WKS RDATA and wire parsing remain deferred because they need a larger typed `Rdata` change. | No |
| §4 Standards Action | `crates/pharos-plugins/src/cache/mod.rs:591-618,625-652`, `crates/pharos-plugins/src/cache/README.md:28-30` | **Deviation**: The cache raises a zero record TTL to the configured minimum, then inserts the Response; default minimum is 5 seconds. RFC 8767 retains the rule that zero-TTL records must not be cached. The README records this behavior but gives no standards rationale. | Yes |
| §4 Standards Action | `crates/pharos-plugins/src/cache/store.rs:163-187`, `crates/pharos-plugins/src/cache/mod.rs:218-290` | **Fixed**: Stale answers use a positive TTL; the default is 30 seconds. Fixed on `conf/cache` (#97). | No |
| §4 Standards Action | `crates/pharos-plugins/src/cache/setup.rs:53-56,87-93,259-263` | **Fixed**: Cached TTLs are capped at 604,800 seconds. Fixed on `conf/cache` (#97). | No |
| §4.1.1 CD | `crates/pharos-plugins/src/dnssec/mod.rs:104-106` | **Fixed**: Intercepted DNSKEY responses clear CD. Fixed on `conf/dnssec` (#100). | No |
| §4.1.1 Header section format | `crates/pharos-plugins/src/forward/mod.rs:345-363` | **Fixed**: Mismatched upstream responses are discarded; if no valid response arrives, the client receives SERVFAIL rather than FORMERR. Fixed on `conf/forward` (#104). | No |
| §4.1.1 Header section format | `crates/pharos-plugins/src/minimal/mod.rs:50-58` | **Violation**: The plugin clears section counts but leaves question and answer octets after the declared sections. | No |
| §4.1.1 Header section format | `crates/pharos-plugins/src/secondary/update.rs:197-210` | **Fixed**: SOA responses validate QR, opcode, ID, RCODE, and echoed Question. Fixed on `conf/secondary` (#98). | No |
| §4.1.1 Header section format | `crates/pharos-plugins/src/dnssec/signing.rs:151-157`, `crates/pharos-plugins/tests/functional/dnssec.rs:592-626`, `crates/pharos-plugins/tests/allocations/dnssec_allocations.rs:131-138` | **Deviation**: The DNSSEC black-lie path clears NXDOMAIN to NOERROR and returns synthetic NSEC data; the plugin README and ADR 0002 document CoreDNS compatibility. | Yes |
| §4.1.1 Header section format | `crates/pharos-plugins/src/header/mod.rs:61-72,85-90`, `crates/pharos-plugins/tests/functional/header.rs:63-70,120-181` | **Fixed**: Header rules cannot set AA on Queries or add it to non-authoritative Responses. Fixed on `conf/plugins-synth` (#102). | No |
| §4.1.1 Header section format | `crates/pharos-plugins/src/header/mod.rs:61-72,85-90`, `crates/pharos-plugins/tests/functional/header.rs:65,120-164` | **Violation**: Header rules can rewrite RD instead of copying its query value; the header README records only in-place flag edits, and ADR 0002 gives no evidence of reliance on this. | No |
| §4.1.1 Header section format | `crates/pharos-plugins/src/header/mod.rs:61-72,85-90`, `crates/pharos-plugins/tests/functional/header.rs:63-69,170-181` | **Partial**: Header rules no longer set AA on unauthorized messages (conf/plugins-synth #102); RA availability remains deferred because Plugin Context has no per-server recursion state. | No |
| §4.1.1 Header section format | `crates/pharos-plugins/src/erratic/mod.rs:45,109-110,117-120` | **Violation**: `erratic` sets TC by a query-counter mask and can stop adding records without TC, independent of the transmission limit; no justification is recorded. | No |
| §4.1.1 Header section format | `crates/pharos-plugins/src/nsid/mod.rs:121-126`, `crates/pharos-plugins/src/nsid/README.md:10` | **Deviation**: NSID drops records after OPT and sets TC to avoid invalidating compression pointers; the README records this limitation. | Yes |
| §4.1.1 QDCOUNT | `crates/pharos-server/src/admission.rs:39-43` | **Fixed**: QUERY with QDCOUNT=0 reaches the root Server Block when configured; counts above one still receive FORMERR. Fixed on `conf/server` (#101). | No |
| §4.1.1 RCODE | `crates/pharos-plugins/src/k8s_external/lookup.rs:59-62` | **Violation**: An empty relative name is a valid DNS name, not evidence of a server failure, but the parser returns SERVFAIL. | No |
| §4.1.1 RCODE | `crates/pharos-plugins/src/kubernetes/mod.rs:804-838,849-863,1083-1113`, `crates/pharos-plugins/src/k8s_external/mod.rs:795-820,197-205,497-528` | **Fixed**: Chased A/AAAA responses use NOERROR when any target answers; otherwise they use the final failed cycle's RCODE. Fixed on `conf/k8s` (#103). | No |
| §4.1.1 TC | `crates/pharos-proto/src/builder.rs:328-334`, `crates/pharos-server/src/outcome.rs:267-302` | **Partial**: Optional Additional-only truncation no longer sets TC (conf/server #101; conf/dnssec #100); required Answer/Authority RRset completeness remains open and was not covered by those fixes. | No |
| §4.1.1 Z | `crates/pharos-server/src/admission.rs:28-45`, `crates/pharos-proto/src/builder.rs:143-156` | **Fixed**: The Listener ignores Z on receipt and generated Responses clear it. Fixed on `conf/server` (#101). | No |
| §4.1.2 Question section format; §4.1.3 Resource record format | `crates/pharos-plugins/src/local/mod.rs:120-130,161-194` | **Fixed**: Local passes non-IN Questions through instead of returning IN records. Fixed on `conf/plugins-synth` (#102). | No |
| §4.1.3 Resource record format | `crates/pharos-plugins/src/cache/mod.rs:593-620,625-652`, `crates/pharos-plugins/src/cache/setup.rs:49-69` | **Deviation**: TTL-zero responses are raised to the default five-second minimum and cached. This follows CoreDNS behavior, recorded in ADR 0002 and the cache README. | Yes |
| §4.1.4 Message compression | `crates/pharos-proto/src/name.rs:520-532` | **Deviation**: Pharos caps pointer chains at 255 hops per name and 8,192 per Message to bound parsing work; CoreDNS v1.15.0's miekg/dns v1.1.73 uses 126 per name. Recorded in `docs/compatibility.md` (conf/server #101). | Yes |
| §4.1.4 Message compression | `crates/pharos-proto/src/zone/rdata.rs:727-752`, `crates/pharos-proto/tests/zone_differential_live.rs:886-910` | **Fixed**: Forward compression pointers are rejected. Fixed on `conf/proto` (#99). | No |
| §4.2.1 UDP usage | `crates/pharos-server/src/udp_linux.rs:22-52,57-71`, `crates/pharos-server/src/udp.rs:133-143,462-472,566-578`, `crates/pharos-server/src/lib.rs:877-905` | **Partial**: Wildcard-bound UDP listeners retain the peer address but not the request's destination address, then reply through the wildcard socket. On a multihomed host, this does not ensure the reply source matches the query destination as RFC 2181 §4.1 requires. | No |
| §4.2.2 TCP usage | `crates/pharos-server/src/lib.rs:946-980` | **Partial**: Shutdown aborts unfinished tasks after five seconds, so outstanding TCP requests may be dropped instead of being satisfied before close. | No |
| §5.1 Format | `crates/pharos-proto/src/zone.rs:443-474` | **Fixed**: Omitted classes inherit the prior explicit class. Fixed on `conf/proto` (#99). | No |
| §5.1 Format | `crates/pharos-proto/src/codes.rs:97-116`, `crates/pharos-proto/src/zone.rs:913-921` | **Partial**: WKS type mnemonic is recognized; typed WKS RDATA remains deferred on `conf/proto` (#99). | No |
| §5.1 Format | `crates/pharos-proto/src/zone.rs:587-601`, `crates/pharos-proto/src/zone/rdata.rs:786-809,872-899`, `crates/pharos-proto/tests/zone_strictness.rs:199-208` | **Deviation**: Pharos rejects decimal escapes above 255; miekg/dns v1.1.73 wraps them to one octet. The stricter RFC 1035 §5.1 behavior is recorded in `docs/compatibility.md` under ADR 0002 (conf/proto #99; conf/infra #105). | Yes |
| §5.1 Format | `crates/pharos-proto/src/rdata.rs:347-370,1346-1359` | **Violation**: Display formatting decodes literal backslash-digit and backslash-dot bytes, changing CAA/URI wire values instead of escaping each raw octet. | No |
| §5.1 Format | `crates/pharos-proto/src/zone/rdata/advanced.rs:190-202`, `crates/pharos-proto/tests/zone_advanced.rs:52-54` | **Fixed**: TKEY algorithm names resolve relative to the zone origin and presentation length constraints are validated. Fixed on `conf/proto` (#99). | No |
| §5.1 Format | `crates/pharos-proto/tests/zone_final_line.rs:224-240,265-270` | **Violation**: The lexer rejects escaped blanks in HINFO character-strings, although `\X` quotes any non-digit character. | No |
| §5.1 Format | `crates/pharos-plugins/src/template/mod.rs:627-636`, `crates/pharos-plugins/src/template/README.md:29` | **Deviation**: Rendered zone text cannot resolve `$INCLUDE` files during a query; the plugin README records this limitation. | Yes |
| §5.2 Use of master files to define zones | `crates/pharos-plugins/src/zone/mod.rs:104-120, 135-198` | **Fixed**: Zone loading rejects mixed-class master files. Fixed on `conf/zone` (#95). | No |
| §5.2 Use of master files to define zones | `crates/pharos-plugins/src/zone/mod.rs:104-120,144-198`, `crates/pharos-plugins/src/sign/signer.rs:58-70` | **Partial**: Primary Zone loading rejects multiple SOAs (conf/zone #95); the offline signer intentionally retains the last SOA for CoreDNS compatibility, recorded in `docs/compatibility.md` (conf/dnssec #100). | Yes |
| §5.2 Use of master files to define zones | `crates/pharos-plugins/src/zone/mod.rs:189-191` | **Partial**: Apex NS enforcement remains deferred on `conf/zone` (#95) because it needs fixture updates in unowned Auto tests. | No |
| §5.2 Use of master files to define zones | `crates/pharos-plugins/src/zone/mod.rs:963-982`, `crates/pharos-plugins/src/zone/mod.rs:104-120` | **Partial**: Available sibling glue is included (conf/zone #95), but required-glue validation remains deferred because it needs glue/occlusion classification and fixture changes beyond the safe patch. | No |
| §5.2 Use of master files to define zones | `crates/pharos-plugins/src/zone/mod.rs:135-230`, `crates/pharos-plugins/src/zone/transfer.rs:83-103` | **Partial**: Out-of-zone owners and required glue remain unvalidated; deferred on `conf/zone` (#95) because correct classification needs cross-zone glue/occlusion analysis. | No |
| §6.1.2 Database | `crates/pharos-plugins/src/secondary/mod.rs:37-46,52-55,93-100`, `crates/pharos-plugins/src/secondary/catalog.rs:133-135`, `crates/pharos-plugins/src/dynupdate/store.rs:73-80` | **Partial**: Secondary snapshots and catalog membership remain memory-only. Persistent snapshots were deferred on `conf/secondary` (#98) because they need storage support. | No |
| §6.2 Standard query processing | `crates/pharos-server/src/admission.rs:53-55`, `crates/pharos-plugins/src/lib.rs:506-511`, `crates/pharos-plugins/src/zone/mod.rs:705-706`, `crates/pharos-plugins/src/hosts/mod.rs:284-328`, `crates/pharos-plugins/src/template/mod.rs:357-361,692-700` | **Violation**: Zone, hosts, and template handlers can answer QCLASS=ANY with only selected-class data while setting AA, without guaranteeing coverage of all classes. | No |
| §6.2 Standard query processing | `crates/pharos-server/src/outcome.rs:244-267,297-299` | **Fixed**: Scrubbing optional Additional-only data no longer sets TC. Fixed on `conf/server` (#101). | No |
| §6.3 Zone refresh and reload processing | `crates/pharos-plugins/src/secondary/mod.rs:198-204`, `crates/pharos-plugins/src/file/mod.rs:75-115,381-384` | **Partial**: Secondary expiry handling is fixed (conf/secondary #98), but file reload failure retains the last valid snapshot to avoid discarding served data; changing that recovery behavior was deferred on `conf/zone` (#95). | No |
| §7.3 Processing responses | `crates/pharos-proto/src/message.rs:203-239`, `crates/pharos-plugins/src/proxy/mod.rs:522-567` | **Partial**: Message parsing checks section bounds and record framing, but leaves type-specific RDATA validation lazy. The proxy accepts a parsed response without validating every RR's RDATA. | No |
| §7.3 Processing responses | `crates/pharos-plugins/src/forward/resolve.rs:83-88` | **Fixed**: Configured resolver rejects query-shaped messages and validates response status. Fixed on `conf/forward` (#104). | No |
| §7.4 Using the cache | `crates/pharos-plugins/src/cache/mod.rs:214-291` | **Partial**: Cache-before-file precedence remains; changing plugin order belongs to unowned `plugin.cfg` and was deferred on `conf/cache` (#97). | No |
| §7.4 Using the cache | `crates/pharos-plugins/src/cache/store.rs:94-118` | **Partial**: The cache still does not rank source trust. Deferred on `conf/cache` (#97) because safe filtering needs provenance and section policy. | No |
| §7.4 Using the cache | `crates/pharos-plugins/src/cache/mod.rs:595-609, 648-652`, `crates/pharos-plugins/src/cache/store.rs:317-324` | **Partial**: Cache response filtering remains deferred on `conf/cache` (#97); filtering unrelated sections needs safe response re-encoding and provenance rules. | No |
| §7.4 Using the cache | `crates/pharos-plugins/src/cache/setup.rs:49-66`, `crates/pharos-plugins/src/cache/mod.rs:591-618, 651-652` | **Deviation**: The default five-second minimum raises received TTLs below five seconds, including zero, before caching. RFC 8767 §7 says zero-TTL data must not be cached; the README records this TTL-raising behavior. | Yes |
| §7.4 Using the cache | `crates/pharos-plugins/src/cache/setup.rs:139-148`, `crates/pharos-plugins/src/cache/store.rs:179-187` | **Fixed**: Stale answers use a positive TTL; the default is 30 seconds. Fixed on `conf/cache` (#97). | No |
| §7.4 Using the cache | `crates/pharos-plugins/src/cache/mod.rs:767-779` | **Fixed**: NXDOMAIN entries omit QTYPE from their key. Fixed on `conf/cache` (#97). | No |

## RFC 1183: New DNS RR Definitions

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §1 AFS Data Base location — additional section processing | `crates/pharos-plugins/src/zone/mod.rs:984-1023` | **Fixed**: AFSDB additional processing adds target A records. Fixed on `conf/zone` (#95). | No |
| §2.2 The Responsible Person RR | `crates/pharos-proto/src/zone.rs:559-564`, `crates/pharos-plugins/src/zone/mod.rs:145-188`, `crates/pharos-plugins/src/zone/mod.rs:222`, `crates/pharos-plugins/src/zone/mod.rs:454-457` | **Fixed**: RP records are normalized per RRset to the minimum TTL. Fixed on `conf/zone` (#95). | No |
| §3.1 The X25 RR — PSDN address syntax | `crates/pharos-proto/src/zone/rdata/legacy.rs:58-67` | **Fixed**: X25 addresses require decimal digits and a four-digit DNIC. Fixed on `conf/proto` (#99). | No |
| §3.1 The X25 RR — national prefixes | `crates/pharos-proto/src/zone/rdata/legacy.rs:58-67` | **Partial**: National-prefix detection remains deferred on `conf/proto` (#99); a digit string alone does not identify a valid country-code boundary. | No |
| §3.2 The ISDN RR — address format | `crates/pharos-proto/src/zone/rdata/legacy.rs:69-84` | **Partial**: ISDN accepts nonempty IA5 address text, but does not validate the E.163 form when supplied. Country-code boundary validation remains deferred on `conf/proto` (#99) because generic IA5 addresses do not identify that boundary. | No |
| §3.2 The ISDN RR — field count | `crates/pharos-proto/src/zone/rdata/legacy.rs:69-97` | **Fixed**: ISDN accepts one address and at most one optional subaddress. Fixed on `conf/proto` (#99). | No |
| §3.2 The ISDN RR — subaddress format | `crates/pharos-proto/src/zone/rdata/legacy.rs:85-96` | **Fixed**: ISDN subaddresses require hexadecimal text. Fixed on `conf/proto` (#99). | No |
| §3.3 The Route Through RR — additional processing | `crates/pharos-plugins/src/zone/mod.rs:984-1023` | **Fixed**: RT targets receive A, AAAA, X25, and ISDN additional processing. Fixed on `conf/zone` (#95). | No |
| §3.3 The Route Through RR — wire RDATA support | `crates/pharos-proto/src/zone/rdata/legacy.rs:45-50`, `crates/pharos-proto/src/rdata.rs:8-32,963-965`, `crates/pharos-proto/src/message.rs:87-89,178-185` | **Partial**: Zone parsing and compressed-name discovery support RT's preference/name layout, but typed RDATA parsing rejects RT; `Record::data()` and message rewriting then fail. | No |

## RFC 1348: DNS NSAP RRs

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §NSAP RR (mnemonic NSAP, type 22, `<length> <NSAP-address>` presentation) | `crates/pharos-proto/src/zone.rs:912-921`, `crates/pharos-proto/src/codes.rs:97-122` | **Partial**: The NSAP mnemonic and RFC 1706 `0x` form are supported (conf/proto #99); legacy RFC 1348 `<length> <ASCII-digit>` presentation remains deferred. | No |

## RFC 1706: DNS NSAP Resource Records

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4 Structure of NSAPs — NSel | `crates/pharos-proto/src/zone/rdata.rs:88-100,410-455` | **Violation**: Generic `TYPE22` RDATA is accepted as opaque bytes, so Pharos can publish an NSAP whose final NSel octet is nonzero. The code does not enforce the required zero NSel value. | No |
| §5 The NSAP RR — class | `crates/pharos-proto/src/zone.rs:444-465,559-565`, `crates/pharos-plugins/src/zone/mod.rs:145-188` | **Fixed**: NSAP master-file records require class IN. Fixed on `conf/proto` (#99). | No |
| §5 The NSAP RR — mnemonic | `crates/pharos-proto/src/codes.rs:97-121`, `crates/pharos-proto/src/zone.rs:912-918` | **Fixed**: The `NSAP` type mnemonic is recognized. Fixed on `conf/proto` (#99). | No |
| §5 The NSAP RR — zero TTL | `crates/pharos-plugins/src/cache/setup.rs:54-56`, `crates/pharos-plugins/src/cache/mod.rs:593-618,625-628` | **Deviation**: The default positive-cache minimum raises a zero TTL to five seconds, allowing the NSAP record to be cached. ADR 0002 allows CoreDNS-compatible behavior, and the cache README's differential-scenario note records the raise to the configured minimum. | Yes |
| §7 Master File Format | `crates/pharos-proto/src/codes.rs:97-122`, `crates/pharos-proto/src/zone.rs:912-921`, `crates/pharos-proto/src/zone/rdata.rs:88-100` | **Partial**: `NSAP` mnemonic and `0x` presentation are supported (conf/proto #99); the legacy `<length> <ASCII-digit>` syntax from RFC 1348 remains deferred. | No |

## RFC 1712: DNS Encoding of Geographical Location

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3 RDATA Format — LATITUDE | `crates/pharos-proto/src/zone/rdata/legacy.rs:99-107` | **Fixed**: GPOS latitude is range-checked. Fixed on `conf/proto` (#99). | No |
| §3 RDATA Format — LONGITUDE | `crates/pharos-proto/src/zone/rdata/legacy.rs:99-107` | **Fixed**: GPOS longitude is range-checked. Fixed on `conf/proto` (#99). | No |
| §4 The GPOS RR — field length limit | `crates/pharos-proto/src/zone/rdata/legacy.rs:106`, `crates/pharos-proto/src/zone/rdata.rs:903-907` | **Partial**: Values over 255 octets are rejected because RFC 1035 character-strings use a one-octet length; a 256-octet field cannot be represented on the wire. | No |
| §4 The GPOS RR — numeric values and ranges | `crates/pharos-proto/src/zone/rdata/legacy.rs:99-107` | **Fixed**: GPOS requires three numeric fields and enforces latitude/longitude ranges. Fixed on `conf/proto` (#99). | No |
| §4 The GPOS RR — optional owner, TTL, and class | `crates/pharos-proto/src/zone.rs:434-475, 555-558` | **Fixed**: Omitted class inherits the previous explicit class. Fixed on `conf/proto` (#99). | No |

## RFC 1876: A Means for Expressing Location Information in the Domain Name System

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 RDATA Format | `crates/pharos-proto/src/zone/rdata/advanced.rs:40-76`, `crates/pharos-proto/src/rdata.rs:643-665,963-965` | **Partial**: LOC wire VERSION/length parsing remains deferred on `conf/proto` (#99) because typed LOC RDATA support is not implemented. | No |
| §2 RDATA Format | `crates/pharos-proto/src/zone/rdata/advanced.rs:301` | **Fixed**: LOC longitude milliseconds round away from the prime meridian without binary-float carry. Fixed on `conf/proto` (#99). | No |
| §3 Master File Format | `crates/pharos-proto/src/zone/rdata/advanced.rs:49-68` | **Fixed**: LOC altitude is range-checked in 0.01-meter steps. Fixed on `conf/proto` (#99). | No |
| §3 Master File Format | `crates/pharos-proto/src/zone/rdata/advanced.rs:69-72` | **Fixed**: LOC rejects extra precision fields. Fixed on `conf/proto` (#99). | No |
| §3 Master File Format | `crates/pharos-proto/src/zone/rdata/advanced.rs:268-316` | **Partial**: LOC still rejects coordinates with minutes but omitted seconds; this grammar edge case remains deferred on `conf/proto` (#99). | No |

## RFC 1982: Serial Number Arithmetic

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 Serial Number Arithmetic | `crates/pharos-plugins/src/auto/walk.rs:48-53`, `crates/pharos-plugins/src/file/mod.rs:142-144`, `crates/pharos-plugins/src/zone/mod.rs:110-112` | **Fixed**: Serial zero is accepted during initial load/reload and used as an IXFR value. Fixed on `conf/zone` (#95) and `conf/secondary` (#98). | No |
| §3.2 Comparison | `crates/pharos-plugins/src/k8s_external/transfer.rs:548-552,589-597`, `crates/pharos-plugins/src/sign/output.rs:32-37`, `crates/pharos-proto/src/response.rs:100-106`, `crates/pharos-proto/tests/response.rs:101-105` | **Partial**: Kubernetes IXFR and shared Response RRSIG-time comparisons use RFC 1982 serial arithmetic (conf/k8s #103; conf/server #101); offline signing refresh comparisons remain open. | No |
| §7 The DNS SOA serial number (SOA.expire increment window) | `crates/pharos-plugins/src/zone/update.rs:184-195` | **Partial**: Each changed UPDATE increments by one, but the implementation does not limit cumulative increments within the SOA expire period. More than 2^31−1 changes in that period can leave secondaries misordering the zone serial. | No |
| §7 The DNS SOA serial number (serial ordering) | `crates/pharos-plugins/src/k8s_external/transfer.rs:548-552,589-597` | **Fixed**: Kubernetes IXFR uses wrap-aware RFC 1982 serial ordering. Fixed on `conf/k8s` (#103). | No |
| §7 The DNS SOA serial number (zero value) | `crates/pharos-plugins/src/file/mod.rs:142-144`, `crates/pharos-plugins/src/zone/mod.rs:110-112` | **Fixed**: File loading accepts serial zero as a valid value. Fixed on `conf/zone` (#95). | No |

## RFC 1995: Incremental Zone Transfer in DNS

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 Brief Description of the Protocol | `crates/pharos-plugins/src/dynupdate/setup.rs:214-216`, `crates/pharos-plugins/src/dynupdate/store.rs:27-31`, `crates/pharos-plugins/src/dynupdate/store.rs:73-80`, `crates/pharos-plugins/src/dynupdate/transfer.rs:11-16` | **Partial**: With `database`, updates are committed before the live Zone changes. Without it, updates remain in memory and the same live Zone serves transfers before durable storage; no documented exception. | No |
| §2 Brief Description of the Protocol | `crates/pharos-plugins/src/zone/transfer.rs:26-30`, `crates/pharos-plugins/src/kubernetes/transfer.rs:356-365`, `crates/pharos-plugins/src/k8s_external/transfer.rs:548-552`, `crates/pharos-plugins/src/k8s_external/transfer.rs:589-598` | **Violation**: Generic and Kubernetes transfers return one SOA only for an equal serial, not a newer client serial. External Kubernetes uses ordinary integer `>=`, which fails serial-number wraparound. | Yes |
| §3 Query Format | `crates/pharos-plugins/src/transfer/mod.rs:232-244` | **Partial**: The IXFR parser requires one SOA RDATA but does not verify that its owner and class match the requested zone and class, so a foreign-zone SOA is accepted as the client's version. | Yes |
| §6.3.1 Connection Reuse | `crates/pharos-plugins/src/secondary/update.rs:181-200`, `crates/pharos-server/src/transfer.rs:165-173` | **Violation**: The secondary checks the primary SOA on one TCP connection, closes it, then opens another for AXFR, contrary to RFC 9103's SHOULD to reuse an open connection. No listed exception is documented. | No |
| §6.3.4 The edns-tcp-keepalive EDNS(0) Option | `crates/pharos-server/src/outcome.rs:55-65`, `crates/pharos-plugins/src/zone/transfer.rs:57-73` | **Partial**: Streamed AXFR OPT forwarding remains deferred; it requires shared transfer/server changes outside `conf/secondary` (#98) ownership. | No |

## RFC 1996: A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §1.2 DNS NOTIFY transaction | `crates/pharos-plugins/src/secondary/mod.rs:162-192` | **Fixed**: Only SOA NOTIFY requests schedule refresh work. Fixed on `conf/secondary` (#98). | No |
| §2.1 Notify Set | `crates/pharos-plugins/src/transfer/mod.rs:54-76,114-157` | **Violation**: outgoing NOTIFY uses only explicitly configured `to` destinations; code does not implement the default NS RRset minus the SOA MNAME. | No |
| §3.2 NOTIFY message fields | `crates/pharos-plugins/src/secondary/mod.rs:162-190` | **Fixed**: Malformed NOTIFY fields are dropped, and the response uses RFC-defined flags. Fixed on `conf/secondary` (#98). | No |
| §3.2 NOTIFY message fields | `xtask/src/query.rs:98-106,316-320` | **Fixed**: `+opcode=notify` clears RD. Fixed on `conf/infra` (#105). | No |
| §3.3 NOTIFY request QR state | `crates/pharos-plugins/src/secondary/mod.rs:162-170` | **Fixed**: NOTIFY responses with QR set are dropped rather than processed as requests. Fixed on `conf/secondary` (#98). | No |
| §3.3 NOTIFY response QR state | `crates/pharos-server/src/transfer.rs:71-83`, `crates/pharos-server/tests/transfer.rs:583-601` | **Violation**: The sender accepts any same-ID NOERROR message without requiring QR set, so a query can clear the retry attempt as though it were a response. The test explicitly preserves acceptance without QR or NOTIFY opcode. | No |
| §3.4 Transport protocol | `crates/pharos-server/src/transfer.rs:62-70` | **Partial**: NOTIFY sender always uses UDP and has no TCP path when TCP is necessary, such as when a firewall blocks UDP. | No |
| §3.6 Retry parameters | `crates/pharos-plugins/src/transfer/mod.rs:93-100`, `crates/pharos-server/src/transfer.rs:67` | **Partial**: Retry timing and count are not administrator-configurable; caller fixes timeout at two seconds and sender makes three total attempts. | Yes |
| §3.6 UDP retransmission and response matching | `crates/pharos-server/src/transfer.rs:67-91` | **Partial**: Connected UDP filters source IP and port, and sender checks the response ID, but it does not check response QNAME. Socket errors, including a surfaced ICMP port-unreachable error, lead to another attempt instead of stopping. | Yes |
| §3.7 NOTIFY counts | `crates/pharos-server/src/admission.rs:41-42` | **Fixed**: NOTIFY admission accepts the permitted section counts. Fixed on `conf/server` (#101). | No |
| §3.9 Authority and Additional sections | `crates/pharos-server/src/admission.rs:41-42,45-47`, `crates/pharos-proto/src/message.rs:203-240` | **Fixed**: NOTIFY handlers ignore Authority and ordinary Additional data while retaining OPT/TSIG control records. Fixed on `conf/server` (#101). | No |
| §3.10 NOTIFY from unknown master | `crates/pharos-plugins/src/secondary/mod.rs:162-171` | **Partial**: Unknown peers are dropped before request validation (conf/secondary #98), but the required operations-log entry remains open. | No |
| §3.11 Query the NOTIFY source | `crates/pharos-plugins/src/secondary/mod.rs:191-192`, `crates/pharos-plugins/src/secondary/update.rs:178-231`, `crates/pharos-plugins/src/secondary/update.rs:75-85` | **Fixed**: The notifying source IP is mapped to its configured primary port for SOA checks and transfers. Fixed on `conf/secondary` (#98). | No |
| §3.11 SOA NOTIFY processing | `crates/pharos-plugins/src/secondary/mod.rs:162-192`, `crates/pharos-plugins/src/auto/mod.rs:107-125` | **Fixed**: Only SOA changes queue refresh; unchanged periodic Auto scans do not notify. Fixed on `conf/secondary` (#98). | No |
| §3.12 NOTIMP completes transaction | `crates/pharos-server/src/transfer.rs:65-81` | **Fixed**: NOTIMP completes the transfer transaction without retry. Fixed on `conf/secondary` (#98). | No |
| §4.4 Defer action on duplicate NOTIFY | `crates/pharos-plugins/src/secondary/mod.rs:191-192`, `crates/pharos-plugins/src/secondary/update.rs:283-297` | **Fixed**: Duplicate NOTIFY work is coalesced and deferred until the active transaction completes. Fixed on `conf/secondary` (#98). | No |
| §4.8 Master Receives a NOTIFY Response from Slave | `crates/pharos-server/src/transfer.rs:71-83`, `crates/pharos-server/tests/transfer.rs:583-601` | **Partial**: The sender accepts any same-ID `NOERROR` packet from the connected peer without requiring QR=1, NOTIFY opcode, or the matching SOA question, so a non-NOTIFY response can stop retries. The test explicitly preserves acceptance without QR or NOTIFY opcode. | No |

## RFC 2136: Dynamic Updates in the Domain Name System (DNS UPDATE)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §1.1.1 Two RRs are considered equal | `crates/pharos-plugins/src/zone/update.rs:67-83`, `crates/pharos-plugins/src/dynupdate/mod.rs:228-288` | **Fixed**: Received RDLENGTH is preserved through expansion and compared for prerequisites, adds, and deletes. Fixed on `conf/dynupdate` (#96). | No |
| §1.1.5 RR types that cannot be appended | `crates/pharos-plugins/src/dynupdate/setup.rs:63-147`, `crates/pharos-plugins/src/dynupdate/update.rs:87-133`, `crates/pharos-plugins/src/zone/update.rs:67-83,143-150` | **Fixed**: WKS is accepted, validated, and replaced by address/protocol key. Fixed on `conf/dynupdate` (#96). | No |
| §1.4 Data and message signatures | `crates/pharos-plugins/src/dynupdate/store.rs:66-80`, `crates/pharos-plugins/src/dnssec/mod.rs:27-47` | **Partial**: Signed-zone maintenance remains deferred on `conf/dynupdate` (#96) because signing is offline/file-based and crosses package ownership. | No |
| §2.2 Message Header | `crates/pharos-plugins/src/dynupdate/mod.rs:292-295` | **Fixed**: UPDATE replies clear AA and copy the UPDATE opcode. Fixed on `conf/dynupdate` (#96). | No |
| §2.2 Message Header | `crates/pharos-server/src/admission.rs:41-47,68-74` | **Partial**: UPDATE replies copy the opcode (conf/dynupdate #96); malformed-UPDATE opcode handling remains deferred because admission is in unowned `pharos-server` paths. | No |
| §2.5 Changes to the CNAME Resource Record | `crates/pharos-plugins/src/dynupdate/setup.rs:41-59`, `crates/pharos-plugins/src/sign/mod.rs:1-3` | **Partial**: Dynamic UPDATE still cannot maintain signed-zone CNAME data; signed-zone maintenance was explicitly out of scope on `conf/dynupdate` (#96). | No |
| §3.1 Standard Policies — per-name access control | `crates/pharos-plugins/src/dynupdate/setup.rs:32-38,254-294` | **Partial**: Principal-own-name/subdomain selectors need new policy syntax; deferred as an optional config feature on `conf/dynupdate` (#96). | No |
| §3.1 Standard Policies — per-type access control | `crates/pharos-plugins/src/dynupdate/setup.rs:158-185,276-293` | **Partial**: The recommended user-types selector needs new policy syntax; deferred as an optional config feature on `conf/dynupdate` (#96). | No |
| §3.1.1 Process Zone Section | `crates/pharos-server/src/server.rs:537-542` | **Violation**: NOTAUTH/NOTIMP handling remains deferred on `conf/dynupdate` (#96) because its admission/authority routing lives in unowned `pharos-server` paths. | No |
| §3.2.1 Prerequisites with CLASS ANY | `crates/pharos-plugins/src/dynupdate/update.rs:146-168` | **Fixed**: Prerequisite format is checked before lookup, including unsupported RR types. Fixed on `conf/dynupdate` (#96). | No |
| §3.2.2 Prerequisites with CLASS NONE | `crates/pharos-plugins/src/dynupdate/update.rs:146-168` | **Fixed**: Prerequisite format and name/RRset absence results are checked for unsupported RR types. Fixed on `conf/dynupdate` (#96). | No |
| §3.2.3 Prerequisites with CLASS ZCLASS | `crates/pharos-plugins/src/dynupdate/update.rs:146-178, 181-205` | **Fixed**: Unsupported RR types receive the defined existence/set result after prerequisite-format validation. Fixed on `conf/dynupdate` (#96). | No |
| §3.2.4 Table of metavalues used in Prerequisite Section | `crates/pharos-plugins/src/dynupdate/update.rs:146-205` | **Fixed**: ANY, NONE, and ZCLASS metavalues return defined results for unsupported RR types. Fixed on `conf/dynupdate` (#96). | No |
| §3.2.5 Pseudocode for Prerequisite Section Processing | `crates/pharos-plugins/src/dynupdate/update.rs:137-207` | **Fixed**: Prerequisite format is validated before lookup and unsupported-type results follow the defined processing. Fixed on `conf/dynupdate` (#96). | No |
| §3.4.1.2 Update Section Prescan | `crates/pharos-plugins/src/dynupdate/setup.rs:63-147`, `crates/pharos-plugins/src/dynupdate/update.rs:19-21,92-94` | **Fixed**: WKS is accepted as an assigned RR type and its address/protocol fields are validated. Fixed on `conf/dynupdate` (#96). | No |
| §3.4.2.1 System failure and rollback | `crates/pharos-plugins/src/zone/update.rs:91-93`, `crates/pharos-plugins/src/dynupdate/store.rs:66-80`, `crates/pharos-plugins/src/dynupdate/mod.rs:143-156` | **Partial**: Candidate changes remain private for handled errors, but infallible allocation can abort on OOM. Deferred on `conf/dynupdate` (#96): safe rollback needs fallible allocation throughout candidate construction. | No |
| §3.4.2.2 Update | `crates/pharos-plugins/src/dynupdate/setup.rs:63-147`, `crates/pharos-plugins/src/dynupdate/update.rs:92-132`, `crates/pharos-plugins/src/zone/update.rs:143-150` | **Fixed**: WKS additions replace existing records by address/protocol key. Fixed on `conf/dynupdate` (#96). | No |
| §3.4.2.2 Update | `crates/pharos-plugins/src/dynupdate/update.rs:52-64`, `crates/pharos-plugins/src/dynupdate/update.rs:115-120`, `crates/pharos-plugins/src/dynupdate/setup.rs:41-60` | **Partial**: Signed-zone CNAME coexistence remains unsupported; dynamic signed-zone maintenance was out of scope on `conf/dynupdate` (#96). | No |
| §3.4.2.6 Table Of Metavalues Used In Update Section — Add to an RRset | `crates/pharos-plugins/src/dynupdate/update.rs:92-94`, `crates/pharos-plugins/src/dynupdate/setup.rs:63-147` | **Fixed**: WKS addition uses address/protocol replacement semantics. Fixed on `conf/dynupdate` (#96). | No |
| §3.4.2.7 Pseudocode For Update Section Processing | `crates/pharos-plugins/src/dynupdate/setup.rs:63-147`, `crates/pharos-plugins/src/dynupdate/update.rs:87-131` | **Fixed**: WKS updates validate and replace by address/protocol key. Fixed on `conf/dynupdate` (#96). | No |
| §3.4.2.7 Pseudocode For Update Section Processing | `crates/pharos-plugins/src/dynupdate/setup.rs:41-60`, `crates/pharos-plugins/src/dynupdate/update.rs:46-64`, `crates/pharos-plugins/src/zone/update.rs:115-121` | **Partial**: DNSSEC records and post-update signing remain unsupported; signed-zone maintenance was explicitly out of scope on `conf/dynupdate` (#96). | No |
| §3.5 Stability | `crates/pharos-plugins/src/dynupdate/setup.rs:17-20,215-219`, `crates/pharos-plugins/src/dynupdate/store.rs:27-30,66-80,184-187` | **Partial**: Memory-only mode remains non-durable because storage is optional; requiring a database would change the current contract. Deferred on `conf/dynupdate` (#96). | No |
| §3.8 Response | `crates/pharos-plugins/src/dynupdate/mod.rs:292-310` | **Fixed**: UPDATE responses have zero counts and omit all request sections while copying the UPDATE opcode. Fixed on `conf/dynupdate` (#96). | No |
| §4.3 Non-explicit updates to SIGs | `crates/pharos-plugins/src/dynupdate/store.rs:66-80`, `crates/pharos-plugins/src/dnssec/mod.rs:42-46` | **Partial**: UPDATE commits changed RRsets without signatures; signed-zone maintenance was explicitly out of scope on `conf/dynupdate` (#96). | No |
| §4.4 Effects on the zone | `crates/pharos-plugins/src/zone/update.rs:184-196`, `crates/pharos-plugins/src/dynupdate/store.rs:66-80` | **Partial**: Dynamic updates do not regenerate denial records or signatures; signed-zone maintenance was explicitly out of scope on `conf/dynupdate` (#96). | No |

## RFC 2163: Using the Internet DNS to Distribute MIXER Conformant Global Address Mapping (MCGAM)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4 Domain Name Compression | `crates/pharos-proto/src/rdata.rs:148-199,963-965`, `crates/pharos-proto/src/message.rs:178-186`, `crates/pharos-plugins/src/loadbalance/mod.rs:490-519` | **Partial**: The receive path recognizes PX name pointers for relocation but does not decompress them; `Rdata::parse_in_message` rejects PX, so `with_question` cannot re-encode it. RFC 3597 §4 says receivers SHOULD decompress PX. | No |
| §4 PX resource record | `crates/pharos-proto/src/zone.rs:444-462,898-909`, `crates/pharos-proto/src/zone/rdata/legacy.rs:51-57` | **Violation**: Zone parsing accepts explicit non-IN classes, then parses PX RDATA by type without checking class. RFC 2163 defines PX only for class IN. | No |

## RFC 2181: Clarifications to the DNS Specification

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4.1 UDP Source Address Selection | `crates/pharos-server/src/lib.rs:877-930`, `crates/pharos-server/src/udp.rs:71-84,128-143,393-407`, `crates/pharos-server/src/udp_linux.rs:22-55,57-72` | **Partial**: UDP receive retains the remote peer, not the query's destination address, and replies use the listener socket's generic send operation. A wildcard multi-homed listener therefore cannot guarantee replies use the address the query targeted; no RFC 2181 §4.1 citation or documented justification found. | No |
| §5 Resource Record Sets | `crates/pharos-plugins/src/zone/mod.rs:68-71,194-223,445-457` | **Fixed**: Mixed-class zones are rejected, duplicate RRs are suppressed, and RRsets are normalized by owner/type/class. Fixed on `conf/zone` (#95). | No |
| §5 Resource Record Sets | `crates/pharos-plugins/src/zone/mod.rs:194-198,201-223,445-457`, `crates/pharos-plugins/src/k8s_external/scratch.rs:8-16`, `crates/pharos-plugins/src/k8s_external/mod.rs:229-275,386-431`, `crates/pharos-plugins/src/kubernetes/scratch.rs:10-24`, `crates/pharos-plugins/src/kubernetes/mod.rs:870-885,906-925,1178-1250`, `crates/pharos-plugins/tests/allocations/kubernetes_large_allocations.rs:64,181-187` | **Partial**: Zone duplicate suppression and k8s_external address/SRV dedup are fixed (conf/zone #95; conf/k8s #103); Kubernetes Service record dedup still compares textual IPs and case-sensitive DNS names. | No |
| §5.1 Sending RRs from an RRSet | `crates/pharos-plugins/src/dnssec/mod.rs:28-31,99-125` | **Violation**: DNSKEY interception ignores the query class and always emits an IN RRset. A non-IN DNSKEY query can therefore receive records outside its requested class. | No |
| §5.2 TTLs of RRs in an RRSet | `crates/pharos-plugins/src/zone/mod.rs:445-457, crates/pharos-plugins/src/dnssec/signing.rs:202-227, crates/pharos-plugins/src/cache/mod.rs:648-650` | **Partial**: Zone and offline-signing RRsets now normalize TTLs (conf/zone #95; conf/dnssec #100); cache still applies a Response-wide minimum rather than each RRset's minimum. | No |
| §5.2 TTLs of RRs in an RRSet | `crates/pharos-plugins/src/proxy/mod.rs:551-567` | **Fixed**: Mixed-TTL RRsets are normalized to their lowest TTL and the usable response is retained. Fixed on `conf/forward` (#104). | No |
| §5.2 TTLs of RRs in an RRSet | `crates/pharos-plugins/src/cache/mod.rs:595-618,625-650` | **Missing**: Cache accepts upstream RRsets without checking authority or TTL agreement, then caches them. It does not discard a malformed non-authoritative RRset and seek an authoritative source. | No |
| §5.2 TTLs of RRs in an RRSet | `crates/pharos-plugins/src/dnssec/signing.rs:46-65,202-227, crates/pharos-plugins/src/cache/mod.rs:595-618,648-650` | **Partial**: The signer uses each RRset's lowest TTL, but cache applies the minimum TTL from the whole Response to every record. It does not preserve the required per-RRset minimum when other RRsets have lower TTLs. | No |
| §5.2 TTLs of RRs in an RRSet | `crates/pharos-plugins/src/rewrite/mod.rs:1881-1894`, `crates/pharos-plugins/tests/functional/rewrite.rs:968-991,4801-4877` | **Violation**: TTL rewrite rules clamp each RR independently, so records in one RRset can retain different TTLs. Tests cover isolated records, not equal TTLs across an RRset. | No |
| §5.4.1 Ranking data | `crates/pharos-plugins/src/cache/mod.rs:473-503`, `crates/pharos-plugins/src/cache/store.rs:102-118` | **Partial**: Cache still does not rank source trust. Deferred on `conf/cache` (#97) because safe ranking needs provenance and section filtering. | No |
| §5.5 Sending RRSets (reprise) | `crates/pharos-plugins/src/forward/mod.rs:395-397`, `crates/pharos-plugins/src/cache/store.rs:300-324`, `crates/pharos-plugins/src/kubernetes/external.rs:69-91`, `crates/pharos-plugins/src/k8s_external/mod.rs:873-904` | **Partial**: `k8s_external` duplicate address records are suppressed (conf/k8s #103); cache trust filtering remains open. Forward relays cross-section duplicate RRsets unchanged because RFC 2181 §5.5 is SHOULD NOT; this choice is recorded in `docs/compatibility.md` (conf/forward #104). | Yes |
| §6.1 Zone authority | `crates/pharos-plugins/src/zone/mod.rs:153-190` | **Partial**: Apex NS enforcement remains deferred on `conf/zone` (#95) because it needs fixture updates in unowned Auto tests. | No |
| §6.2 DNSSEC issues | `crates/pharos-plugins/src/zone/mod.rs:950-961` | **Fixed**: A DO-bit no-DS referral includes parent-side NSEC proof. Fixed on `conf/zone` (#95). | No |
| §7.3 The SOA.MNAME field | `crates/pharos-plugins/src/local/mod.rs:17-18,171-193` | **Deviation**: Local SOA MNAME and apex NS target use resolvable `localhost.`; the local README records this choice (conf/plugins-synth #102). | Yes |
| §8 Time to Live (TTL) | `crates/pharos-plugins/src/cache/setup.rs:139-148`, `crates/pharos-plugins/src/cache/store.rs:179-187` | **Fixed**: Stale records use a positive TTL; the default is 30 seconds. Fixed on `conf/cache` (#97). | No |
| §8 Time to Live (TTL) | `crates/pharos-proto/src/message.rs:134`, `crates/pharos-proto/src/builder.rs:251-256`, `crates/pharos-plugins/src/cache/setup.rs:49-64`, `crates/pharos-dnssec/src/keys.rs:273-283`, `crates/pharos-plugins/src/dnssec/mod.rs:112-117`, `crates/pharos-plugins/src/rewrite/mod.rs:719-742,1881-1894` | **Partial**: RFC 8767 §4 recommends capping TTLs at 604800 seconds. Cache defaults cap cached TTLs below this, but direct forwarding, authoritative answers, DNSKEY answers, and rewrites can preserve larger TTLs, and cache caps can be raised. | No |
| §8 Time to Live (TTL) | `crates/pharos-proto/src/zone.rs:870-895` | **Fixed**: TTL parser rejects values above 2,147,483,647. Fixed on `conf/proto` (#99). | No |
| §9 The TC (truncated) header bit | `crates/pharos-proto/src/builder.rs:312-334`, `crates/pharos-server/src/outcome.rs:243-299` | **Partial**: Optional Additional-only truncation no longer sets TC (conf/server #101); required Answer/Authority RRset completeness remains open. | No |
| §9 The TC (truncated) header bit | `crates/pharos-plugins/src/proxy/mod.rs:407-425` | **Deviation**: A truncated UDP upstream response is retried over TCP only with `prefer_udp`; otherwise Pharos returns it. `crates/pharos-plugins/src/forward/README.md` documents this CoreDNS-compatible behavior. | Yes |
| §9 The TC (truncated) header bit; RFC 4035 §3.1.1 update | `crates/pharos-proto/src/builder.rs:312-334`, `crates/pharos-plugins/src/zone/mod.rs:459-468,984-1021` | **Fixed**: Optional Additional RRSIG groups are omitted transactionally without TC. Fixed on `conf/dnssec` (#100) and `conf/server` (#101). | No |
| §10.1 CNAME resource records | `crates/pharos-plugins/src/zone/mod.rs:145-229, 613-627` | **Fixed**: Primary Zone loading rejects multiple CNAME targets and enforces a singleton target. Fixed on `conf/zone` (#95). | No |
| §10.1 CNAME resource records | `crates/pharos-plugins/src/zone/mod.rs:145-187`, `crates/pharos-plugins/src/dynupdate/update.rs:52-64` | **Partial**: Static Zone loading permits only specified DNSSEC coexistence (conf/zone #95); dynamic updates still reject DNSSEC records at CNAME owners because signed-zone maintenance is deferred on `conf/dynupdate` (#96). | No |
| §10.1 CNAME resource records | `crates/pharos-plugins/src/autopath/mod.rs:334-357` | **Violation**: Rebuild inserts a CNAME at the original question name, then copies source answers without checking for an existing CNAME there. A response containing that owner can therefore emit duplicate or conflicting CNAMEs. | No |
| §10.2 PTR records | `crates/pharos-plugins/src/zone/mod.rs:145-187, 796-809` | **Fixed**: Zone loading rejects PTR targets that are CNAME aliases. Fixed on `conf/zone` (#95). | No |
| §10.3 MX and NS records | `crates/pharos-plugins/src/zone/mod.rs:145-187, 984-1021` | **Partial**: MX/NS alias targets are rejected (conf/zone #95); requiring address RRsets remains deferred because targets can be out of zone and need cross-zone validation. | No |

## RFC 2230: Key Exchange Delegation Record for the DNS

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.1 KX RDATA format — A additional processing | `crates/pharos-plugins/src/zone/mod.rs:985-991` | **Fixed**: KX exchanger A records are included in additional processing. Fixed on `conf/zone` (#95). | No |
| §3.1 KX RDATA format — AAAA additional processing | `crates/pharos-plugins/src/zone/mod.rs:985-991` | **Fixed**: KX exchanger AAAA records are included in additional processing. Fixed on `conf/zone` (#95). | No |
| §4 Security Considerations — signed KX records | `crates/pharos-plugins/src/zone/mod.rs:144-190`, `crates/pharos-plugins/src/dnssec/signing.rs:67-109` | **Partial**: KX additional processing is fixed on `conf/zone` (#95); signed-KX enforcement remains deferred because it crosses into unowned DNSSEC signing code. | No |

## RFC 2308: Negative Caching of DNS Queries (DNS NCACHE)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.1 Name Error | `crates/pharos-plugins/src/zone/mod.rs:812-853,889-910` | **Partial**: ENT and wildcard denial proofs are fixed (conf/zone #95); CNAME-to-NXDOMAIN proof selection remains deferred because it needs broader cross-name proof selection. | No |
| §2.1 Name Error | `crates/pharos-proto/src/response.rs:70-76`, `crates/pharos-plugins/src/cache/mod.rs:348-355,573-585` | **Fixed**: NXDOMAIN with CNAME answers is classified by the final query-cycle RCODE. Fixed on `conf/server` (#101); cache coverage is included in #97. | No |
| §2.1 Name Error | `crates/pharos-plugins/tests/allocations/kubernetes_services.rs:189-190`, `crates/pharos-plugins/src/kubernetes/README.md:29` | **Deviation**: A SOA query for a nonexistent name returns NOERROR instead of NXDOMAIN, matching documented CoreDNS behavior allowed by ADR 0002. | Yes |
| §2.2 No Data | `crates/pharos-proto/src/response.rs:70-96`, `crates/pharos-plugins/src/cache/mod.rs:573-580` | **Fixed**: SOA-less NODATA is classified as negative and is not cached. Fixed on `conf/cache` (#97). | No |
| §2.2 No Data | `crates/pharos-plugins/src/kubernetes/mod.rs:744-753`, `crates/pharos-plugins/tests/allocations/kubernetes_services.rs:187-188`, `crates/pharos-plugins/src/kubernetes/README.md:28` | **Deviation**: An existing reverse name with a PTR RRset returns NXDOMAIN for an A query instead of NODATA, matching documented CoreDNS behavior allowed by ADR 0002. | Yes |
| §2.2 No Data | `crates/pharos-plugins/src/kubernetes/mod.rs:744-753,967-1007`, `crates/pharos-plugins/tests/allocations/kubernetes_services.rs:552-554`, `crates/pharos-plugins/src/kubernetes/README.md:27` | **Deviation**: Existing zone, service, and namespace names without TXT data return NXDOMAIN instead of NODATA, matching documented CoreDNS behavior allowed by ADR 0002. | Yes |
| §2.2 No Data | `crates/pharos-plugins/src/kubernetes/mod.rs:744-753,967-1007`, `crates/pharos-plugins/tests/allocations/kubernetes_services.rs:555` | **Violation**: `ns.dns.cluster.local.` has generated A/AAAA data, so a TXT query is NODATA, not NXDOMAIN; the compatibility notes do not document this case. | No |
| §2.2 No Data | `crates/pharos-plugins/src/zone/mod.rs:541-544,676-687`, `crates/pharos-plugins/tests/functional/file_coredns.rs:1007-1015` | **Deviation**: An SOA/NS-only apex returns NOERROR/NODATA for an absent QTYPE, following RFC 2308 §2.2 rather than CoreDNS v1.15.0's NXDOMAIN behavior. Recorded in `docs/compatibility.md` (conf/zone #95). | Yes |
| §3 Negative Answers from Authoritative Servers | `crates/pharos-plugins/src/zone/mod.rs:445-457,827-853` | **Fixed**: Negative SOA TTL is capped at `min(SOA TTL, SOA.MINIMUM)`. Fixed on `conf/zone` (#95). | No |
| §3 Negative Answers from Authoritative Servers | `crates/pharos-plugins/src/zone/mod.rs:855-867` | **Fixed**: Signed wildcard NODATA includes the wildcard and closest-encloser NSEC proofs. Fixed on `conf/zone` (#95). | No |
| §3 Negative Answers from Authoritative Servers | `crates/pharos-plugins/src/zone/mod.rs:459-467` | **Fixed**: Negative SOA RRSIG TTL is capped in line with the SOA TTL. Fixed on `conf/zone` (#95). | No |
| §3 Negative Answers from Authoritative Servers | `crates/pharos-plugins/src/kubernetes/mod.rs:803-809,1085-1114,1284-1299` | **Fixed**: ExternalName target responses preserve the final RCODE and negative SOA authority data. Fixed on `conf/k8s` (#103). | No |
| §3 Negative Answers from Authoritative Servers | `crates/pharos-plugins/src/template/mod.rs:692-716`, `crates/pharos-plugins/tests/functional/template_coredns.rs:264-295` | **Violation**: An authoritative NXDOMAIN template writes the operator's SOA into Answer rather than Authority. ADR 0002 would allow a CoreDNS-compatible difference only if recorded, and neither `docs/compatibility.md` nor `crates/pharos-plugins/src/template/README.md` records it. | No |
| §3.1 Retries and Timeouts | `crates/pharos-plugins/src/forward/setup.rs:111-123`, `crates/pharos-plugins/src/forward/mod.rs:288-303` | **Fixed**: Attempts are capped at 1–3 per upstream/transport; zero means one. Fixed on `conf/forward` (#104). | No |
| §3.2 Caching | `—` | **Fixed**: Failure-cache conditions, keys, TTLs, backoff, and stale policy are recorded in `docs/compatibility.md`. Fixed on `conf/cache` (#97). | Yes |
| §3.2 Caching | `crates/pharos-plugins/src/cache/setup.rs:201-209`, `crates/pharos-plugins/src/cache/mod.rs:521-533` | **Partial**: The default failure TTL is 5 seconds, but `servfail 0`, sub-second TTLs, or `disable denial` can prevent caching or reduce the TTL below 1 second. RFC 9520 requires failure caching for at least 1 second. | No |
| §3.2 Caching | `crates/pharos-plugins/src/cache/mod.rs:521-559` | **Fixed**: Repeated failures use exponential backoff capped at five minutes. Fixed on `conf/cache` (#97). | No |
| §3.2 Caching | `crates/pharos-plugins/src/cache/mod.rs:521-559`, `crates/pharos-plugins/src/cache/setup.rs:201-209` | **Partial**: REFUSED is now cached, but FORMERR and `servfail 0`/sub-second TTL behavior remain unchanged. `servfail 0` and sub-second values can still bypass the one-second minimum (conf/cache #97). | No |
| §4 SOA Minimum Field | `crates/pharos-proto/src/zone.rs:443-474` | **Fixed**: Omitted legacy SIG TTLs default from the SIG record's Original TTL. Fixed on `conf/proto` (#99). | No |
| §5 Caching Negative Answers | `crates/pharos-plugins/src/cache/mod.rs:767-779`, `crates/pharos-plugins/src/cache/store.rs:157-160` | **Fixed**: NXDOMAIN keys use `<QNAME,QCLASS>` and support cross-QTYPE reuse. Fixed on `conf/cache` (#97). | No |
| §5 Caching Negative Answers | `crates/pharos-plugins/src/cache/mod.rs:605-619` | **Fixed**: Negative TTLs are not raised above the SOA-derived lifetime; the accepted `denial_min_ttl` option is an ignored compatibility no-op. Fixed on `conf/cache` (#97). | No |
| §5 Caching Negative Answers | `crates/pharos-proto/src/response.rs:70-96`, `crates/pharos-plugins/src/cache/mod.rs:573-650` | **Fixed**: SOA-less NODATA is classified as negative but is not cached. Fixed on `conf/cache` (#97). | No |
| §5 Caching Negative Answers | `crates/pharos-plugins/src/cache/setup.rs:81-109` | **Fixed**: The configured negative-cache maximum is capped at the positive maximum. Fixed on `conf/cache` (#97). | No |
| §6 Negative answers from the cache | `crates/pharos-plugins/src/cache/store.rs:179-187` | **Fixed**: Negative TTLs age under `keepttl`. Fixed on `conf/cache` (#97). | No |
| §7.1 Server Failure | `crates/pharos-plugins/src/cache/mod.rs:767-779` | **Partial**: Failure entries still omit the upstream IP. Deferred on `conf/cache` (#97) because cache context does not expose the selected upstream. | No |
| §7.2 Dead / Unreachable Server | `crates/pharos-plugins/src/proxy/health.rs:93-145`, `crates/pharos-plugins/src/forward/mod.rs:307-320` | **Partial**: Health probes validate the response Question and down state expires/re-arms after 300 seconds (conf/forward #104); down-state query-tuple scope and failure classification remain open. | No |
| §8 Changes from RFC 1034 | `crates/pharos-plugins/src/cache/setup.rs:211-235`, `crates/pharos-plugins/src/cache/mod.rs:642-648` | **Partial**: Negative caching works by default, but `disable denial` can turn it off while positive caching remains enabled. RFC 2308 §8 requires negative caching when a resolver caches other answers. | No |
| §8 Changes from RFC 1034 | `crates/pharos-plugins/src/cache/mod.rs:767-779`, `crates/pharos-plugins/src/cache/store.rs:157-162` | **Partial**: Cross-QTYPE NXDOMAIN reuse is fixed on `conf/cache` (#97); reuse under the final CNAME target remains deferred because it needs response-chain rewriting. | No |

## RFC 2535: Domain Name System Security Extensions

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| RFC 2535 §5.2 NXT RDATA Format | `crates/pharos-proto/src/zone/rdata/legacy.rs:212-223`, `crates/pharos-proto/src/zone/rdata.rs:1003-1026` | **Violation**: NXT still uses the RFC 4034 windowed bitmap rather than RFC 2535's unwindowed form. Deferred on `conf/proto` (#99); NXT bitmap support needs a separate representation. | No |

## RFC 2606: Reserved Top Level DNS Names

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 TLDs for Testing, & Documentation Examples | — | **Violation**: RFC 6761 §6.2 updates this reservation: caching servers should not query upstream for `.test` by default and should return immediate negative responses. No reserved-name handling exists; `forward` routes by configured zone and can forward these queries. No recorded exception covers this behavior. | No |
| §2 TLDs for Testing, & Documentation Examples | — | **Violation**: RFC 6761 §6.2 says caching servers should offer a disabled-by-default option to enable upstream resolution for `.test`. No such special-name option exists. | No |
| §2 TLDs for Testing, & Documentation Examples | — | **Violation**: RFC 6761 §6.2 says authoritative servers should recognize `.test` names as special and return immediate negative responses by default. No reserved-name handling exists; the `file` plugin refuses or forwards names outside configured zones. No recorded exception covers this behavior. | No |
| §2 TLDs for Testing, & Documentation Examples | `crates/pharos-plugins/src/local/mod.rs:75-77,121-177` | **Partial**: The optional `local` plugin returns loopback addresses and negative responses for other localhost queries, but servers without this plugin can forward or refuse them. | Yes |
| §2 TLDs for Testing, & Documentation Examples | `crates/pharos-plugins/src/local/mod.rs:75-77,121-177` | **Partial**: The optional `local` plugin handles authoritative localhost queries, but zones served without this plugin can return configured data instead. | Yes |
| §2 TLDs for Testing, & Documentation Examples | — | **Violation**: RFC 6761 §6.4 says caching servers should not query upstream for `.invalid` names and should return immediate NXDOMAIN responses. No reserved-name handling exists. | No |
| §2 TLDs for Testing, & Documentation Examples | — | **Violation**: RFC 6761 §6.4 says authoritative servers should handle `.invalid` names as caching servers do. Configured zones can return positive answers, with no default special handling. | No |

## RFC 2782: A DNS RR for specifying the location of services (DNS SRV)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §The format of the SRV RR | `crates/pharos-plugins/src/whoami/mod.rs:41-59` | **Violation**: `whoami` emits `_udp.Name` or `_tcp.Name`, omitting the required `_Service` label from `_Service._Proto.Name`. Its README does not document this format exception. | No |
| §The format of the SRV RR | `crates/pharos-plugins/src/whoami/mod.rs:30, crates/pharos-plugins/src/whoami/mod.rs:87-94` | **Fixed**: `whoami` emits IN-class SRV records with `_whoami._udp` and `_whoami._tcp` owners. Fixed on `conf/plugins-synth` (#102). | No |
| §The format of the SRV RR | `crates/pharos-plugins/src/k8s_external/transfer.rs:175-204, 238-280` | **Partial**: Query SRV responses enforce target addressability; AXFR still cannot resolve hostname targets synchronously and may emit SRV without address data. Deferred on `conf/k8s` (#103). | No |
| §The format of the SRV RR | `crates/pharos-plugins/src/k8s_external/mod.rs:317-347, 371-432` | **Fixed**: Query SRV records are suppressed when a hostname target has no non-CNAME A/AAAA RRset. Fixed on `conf/k8s` (#103). | No |

## RFC 2930: Secret Key Establishment for DNS (TKEY RR)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 The TKEY Resource Record | `crates/pharos-proto/src/codes.rs:173, crates/pharos-proto/src/rdata.rs:30-32,963,1261-1296` | **Partial**: Pharos assigns TKEY type code 249 and its zone-file encoder emits the field sequence, but wire RDATA parsing rejects TKEY as an unsupported name-bearing type, and the generic RDATA writer rejects it. Pharos therefore cannot parse or build TKEY RRs in DNS messages. | No |
| §2.3 The Algorithm Field | `crates/pharos-proto/src/zone/rdata/advanced.rs:200-218`, `crates/pharos-proto/src/rdata.rs:963` | **Partial**: Zone input resolves relative algorithm names and validates text lengths (conf/proto #99); typed TKEY wire RDATA parsing remains unsupported. | No |
| §2.6 The Error Field — extended RCODE | `crates/pharos-proto/src/codes.rs:47-81`, `crates/pharos-proto/src/rdata.rs:963` | **Partial**: The shared 16-bit `Rcode` includes TKEY codes 19–21, consistent with RFC 6895 §2.3's unified error space, but typed TKEY RDATA parsing rejects the Error field. | No |
| §2.7 The Key Size and Data Fields | `crates/pharos-proto/src/zone/rdata/advanced.rs:209-212`, `crates/pharos-proto/src/rdata.rs:963` | **Partial**: Zone text validates the 16-bit key-size field (conf/proto #99); typed TKEY wire RDATA parsing remains unsupported. | No |
| §2.8 The Other Size and Data Fields | `crates/pharos-proto/src/zone/rdata/advanced.rs:213-218`, `crates/pharos-proto/src/rdata.rs:963` | **Partial**: Zone text validates the 16-bit Other Data size (conf/proto #99); typed TKEY wire RDATA parsing remains unsupported. | No |
| §3 General TKEY Considerations — one TKEY per message | `crates/pharos-proto/src/message.rs:217-237` | **Fixed**: Message parsing rejects multiple TKEY records. Fixed on `conf/proto` (#99). | No |
| §3 General TKEY Considerations — transient, not cached or zone data | `crates/pharos-plugins/src/cache/mod.rs:153-169, 561-608`, `crates/pharos-plugins/src/cache/store.rs:301-335`, `crates/pharos-proto/src/zone/rdata/advanced.rs:200-217`, `crates/pharos-plugins/src/zone/mod.rs:145-188` | **Fixed**: Cache excludes TKEY and zone parsing rejects meta-type TKEY records. Fixed on `conf/cache` (#97) and `conf/proto` (#99). | No |
| §3 General TKEY Considerations — unavailable state | `crates/pharos-server/src/admission.rs:45-65`, `crates/pharos-plugins/src/dynupdate/update.rs:5-17,97,152-153,170` | **Partial**: Admission treats TKEY as an ordinary QUERY and passes it to routing with no NOTIMP or REFUSED. Only the dynamic UPDATE path refuses TKEY, and it returns FORMERR rather than NOTIMP or REFUSED. | No |

## RFC 3007: Secure Domain Name System (DNS) Dynamic Update

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §1.4 Data and message signatures | `crates/pharos-plugins/src/dynupdate/store.rs:66-80`, `crates/pharos-plugins/src/dnssec/mod.rs:27-47` | **Partial**: dynamic updates commit changed Zone records without applying zone-key signatures. DNSSEC signs responses only when configured keys exist and the Query has DO set, so an update to a signed Zone is not guaranteed signed when the transaction completes. | No |
| §3.1 Standard policies | `crates/pharos-plugins/src/dynupdate/setup.rs:261-275` | **Partial**: Rules support one exact owner, the zone apex (`@`), or every zone name (`*`). They lack a concise rule for a principal's own name and subdomains. | No |
| §3.1 Standard policies | `crates/pharos-plugins/src/dynupdate/setup.rs:276-286` | **Partial**: `*` represents all types, but configuration has no concise user-types selector. | No |
| §4.3 Non-explicit updates to SIGs | `crates/pharos-plugins/src/dynupdate/store.rs:66-79`, `crates/pharos-plugins/src/dnssec/mod.rs:32-47` | **Partial**: Dynamic updates commit changed RRsets without signatures. The DNSSEC plugin signs selected responses only after a query with DO; it does not ensure the updated RRset is signed when the update completes. | No |
| §4.4 Effects on the zone | `crates/pharos-plugins/src/zone/update.rs:184-198`, `crates/pharos-plugins/src/dnssec/signing.rs:116-151` | **Partial**: A changed zone gets a new SOA serial, but the update transaction does not regenerate or sign SOA and denial records. DNSSEC only synthesizes denial NSEC and signs selected records in later DO responses. | No |

## RFC 3110: RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 RSA Public KEY Resource Records | `crates/pharos-dnssec/src/keys.rs:319-326` | **Violation**: The parser accepts the three-octet exponent-length form even when the exponent is at most 255 bytes; RFC 3110 requires the one-octet form for those lengths. A signing key loaded this way retains and republishes that noncanonical DNSKEY data. | Yes |
| §2 RSA Public KEY Resource Records | `crates/pharos-dnssec/src/keys.rs:333-350` | **Violation**: Leading zero octets in the exponent or modulus are silently stripped for key comparison, not rejected as RFC 3110 requires. The original public key remains in the loaded DNSKEY and can be published by the signer. | Yes |
| §2 RSA Public KEY Resource Records | `crates/pharos-dnssec/src/sign.rs:77-85`, `crates/pharos-dnssec/src/keys.rs:129-149, 199-204` | **Fixed**: RSA exponent and modulus are capped at 4096 bits. Fixed on `conf/dnssec` (#100). | No |

## RFC 3225: Indicating Resolver Support of DNSSEC

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3 Protocol Changes | `crates/pharos-plugins/src/zone/mod.rs:459-467`, `crates/pharos-proto/src/builder.rs:328-334` | **Fixed**: Optional Additional RRSIG groups are omitted without TC when they do not fit. Fixed on `conf/dnssec` (#100) and `conf/server` (#101). | No |
| §3 Protocol Changes | `crates/pharos-plugins/src/zone/transfer.rs:59-65`, `crates/pharos-server/src/tcp.rs:233-235` | **Partial**: Normal Responses copy the query DO bit; TCP transfer streams still omit OPT and DO. Transfer OPT handling remains deferred on `conf/secondary` (#98) and `conf/k8s` (#103). | No |
| §3 Protocol Changes | `crates/pharos-plugins/src/zone/mod.rs:855-867`, `crates/pharos-plugins/src/zone/mod.rs:931-948` | **Fixed**: Wildcard NODATA includes the NSEC proofs for the wildcard type and closest encloser. Fixed on `conf/zone` (#95). | No |
| §3 Protocol Changes | `crates/pharos-plugins/src/zone/mod.rs:950-961` | **Fixed**: A DO-set no-DS referral includes parent-side NSEC proof. Fixed on `conf/zone` (#95). | No |

## RFC 3226: DNSSEC and IPv6 A6 aware server/resolver message size requirements

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3 Protocol changes | `crates/pharos-server/src/udp.rs:139-142`, `crates/pharos-server/src/udp_linux.rs:57-71` | **Partial**: RFC 4035 §3 updates DNSSEC servers to fragment IPv6 UDP datagrams at the minimum IPv6 MTU when needed and the path MTU is unknown. These send paths use generic UDP socket calls and do not ensure that fragmentation behavior; they rely on platform defaults. | No |
| §3 Protocol changes | `crates/pharos-server/src/outcome.rs:275-281`, `crates/pharos-proto/src/edns.rs:152-153` | **Deviation**: Response OPT advertises Pharos's 4,096-octet capacity; UDP send limit remains the request size capped at 4,096. CoreDNS `bufsize` echoes its reduced size. Recorded in `docs/compatibility.md` (RFC 6891 §6.2.4; RFC 3226 §3; conf/server #101). | Yes |

## RFC 3339: Date and Time on the Internet: Timestamps

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3 Two Digit Years | `crates/pharos-server/src/logging.rs:186-212` | **Violation**: MUST generate four digit years in dates. `{year:04}` pads to a minimum width only; years outside 0000–9999 emit five digits or a sign, same defect as §5.6. | No |
| §5.6 Internet Date/Time Format | `crates/pharos-server/src/logging.rs:113-121,186-212` | **Violation**: `year:04` sets a minimum width, not a four-digit limit. A supplied `SystemTime` outside years 0000–9999 produces a value that does not match `date-fullyear = 4DIGIT`. | No |

## RFC 3403: Dynamic Delegation Discovery System (DDDS) Part Three: The Domain Name System (DNS) Database

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3 General Description | `crates/pharos-proto/src/rdata.rs:773-791, crates/pharos-proto/src/zone/rdata.rs:202-210` | **Partial**: NAPTR character strings are preserved as octets, and numeric master-file escapes can produce invalid UTF-8 despite §3 specifying UTF-8 values. Pharos does not execute substitution expressions, so code-point matching and locale independence do not apply. | No |
| §4.1 NAPTR RR Format | `crates/pharos-proto/src/rdata.rs:773-791, crates/pharos-proto/src/zone/rdata.rs:202-210` | **Fixed**: NAPTR FLAGS are limited to ASCII letters and digits or the empty string. Fixed on `conf/proto` (#99). | No |
| §4.1 NAPTR RR Format | `crates/pharos-proto/src/rdata.rs:773-791, crates/pharos-proto/src/zone/rdata.rs:202-210` | **Fixed**: NAPTR rejects a nonempty REGEXP with a non-root REPLACEMENT. Fixed on `conf/proto` (#99). | No |

## RFC 3596: DNS Extensions to Support IP Version 6

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.1 AAAA record type | `crates/pharos-proto/src/zone.rs:898-909`, `crates/pharos-plugins/src/zone/mod.rs:277-287,454-457` | **Fixed**: Zone parsing requires IN-class AAAA records and lookup does not cross classes. Fixed on `conf/proto` (#99) and `conf/zone` (#95). | No |
| §2.1 AAAA record type | `crates/pharos-plugins/src/whoami/mod.rs:25-30,71-82` | **Fixed**: `whoami` emits IN-class AAAA records and passes non-IN Questions through. Fixed on `conf/plugins-synth` (#102). | No |
| §2.2 AAAA data format | `crates/pharos-plugins/src/k8s_external/mod.rs:892-899,931-938`, `crates/pharos-plugins/src/k8s_external/transfer.rs:162-172` | **Fixed**: Empty AAAA RDATA is omitted from query and transfer responses. Fixed on `conf/k8s` (#103). | No |
| §2.5 IP6.ARPA Domain | `crates/pharos-plugins/src/kubernetes/reverse.rs:35-49` | **Fixed**: IPv6 reverse names require exactly 32 nibbles before `ip6.arpa`. Fixed on `conf/k8s` (#103). | No |

## RFC 3597: Handling of Unknown DNS Resource Record (RR) Types

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 Definition | `crates/pharos-proto/src/message.rs:87-89`, `crates/pharos-proto/src/rdata.rs:643-965` | **Partial**: `Rdata::parse_in_message` classifies by type only, so it cannot distinguish class-specific RDATA formats. Its fallback also treats unhandled assigned QTYPE/meta-type values as `Unknown`, despite §2 excluding them. | No |
| §3 Transparency | `crates/pharos-proto/src/zone/rdata.rs:409-501,723` | **Fixed**: Valid known-type RDATA written in generic `\#` form is preserved byte-for-byte; malformed layouts are rejected. Fixed on `conf/proto` (#99). | No |
| §4 Domain Name Compression | `crates/pharos-proto/src/rdata.rs:8-32,963` | **Partial**: the parser rejects several RFC 1035 well-known name-bearing types, including MD, MF, MB, MG, MR, and MINFO, rather than decompressing their embedded names as required. | No |
| §4 Domain Name Compression | `crates/pharos-proto/src/rdata.rs:8-32,963` | **Partial**: the parser also rejects RP, AFSDB, RT, SIG, PX, and NXT, so it does not provide the recommended decompression for these types; SRV and NAPTR are supported. | No |
| §5 Text Representation | `crates/pharos-proto/src/zone.rs:898-909` | **Violation**: `parse_class` delegates directly to integer parsing, which accepts a leading `+`; thus invalid forms such as `CLASS+1` are accepted instead of requiring decimal digits immediately after `CLASS`. | Yes |
| §5 Text Representation | `crates/pharos-proto/src/zone/rdata.rs:88-99` | **Partial**: generic RDATA words are concatenated before hex validation. This checks only the combined digit count and accepts separate words with odd digit counts, contrary to the requirement that each word contain an even number of hex digits. | Yes |
| §5 Text Representation | `crates/pharos-proto/src/zone/rdata.rs:409-501,723`, `crates/pharos-proto/tests/zone_strictness.rs:80-129` | **Fixed**: Valid generic known-type RDATA is preserved and malformed layouts are rejected. Fixed on `conf/proto` (#99). | No |
| §6 Equality Comparison | `crates/pharos-plugins/src/dynupdate/update.rs:87-132,181-205`, `crates/pharos-plugins/src/dynupdate/setup.rs:63-147` | **Fixed**: Opaque ordinary RR types are accepted for UPDATE and prerequisite equality. Fixed on `conf/dynupdate` (#96). | No |
| §7 DNSSEC Canonical Form and Ordering | `crates/pharos-proto/src/rdata.rs:8-32`, `crates/pharos-dnssec/src/canonical.rs:293-295` | **Partial**: canonicalization handles some listed legacy name-bearing types, but the parser rejects MD, MF, MB, MG, MR, MINFO, RP, AFSDB, RT, SIG, PX, NXT, and KX, while the canonicalizer rejects A6. Pharos therefore cannot produce the required canonical RDATA for all pre-RFC 3597 types retained by RFC 4034 §6.2. | No |

## RFC 4007: IPv6 Scoped Address Architecture

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §5 Specification (updates RFC 4007) | `crates/pharos-plugins/src/forward/setup.rs:245-249,309-319` | **Deviation**: The `forward` Corefile directive accepts scoped non-global IPv6 upstreams but strips the zone before storing the socket address, so users cannot select the required zone. `crates/pharos-plugins/src/forward/README.md` documents this CoreDNS-compatible behavior. | Yes |
| §7 Sending Packets | `crates/pharos-plugins/src/forward/setup.rs:245-249,261-272,280-295,309-319` | **Deviation**: `forward` strips zone identifiers from numeric upstreams and resolver entries, so scoped destinations cannot select the intended zone. The plugin README records this CoreDNS-compatible behavior, which ADR 0002 permits. | Yes |
| §11 Textual Representation | `crates/pharos-plugins/src/bind/mod.rs:42-58`, `crates/pharos-plugins/src/forward/setup.rs:245-319`, `crates/pharos-plugins/src/acl/mod.rs:104-120,195-198`, `crates/pharos-plugins/src/expression/mod.rs:777-819` | **Partial**: `bind` rejects a literal `<address>%<zone_id>`, while `forward` removes zones from numeric upstreams. Views emit `%scope_id` from `client_ip()` but `incidr()` cannot parse it; ACL network parsing rejects zone suffixes and matching discards the peer scope ID. | No |
| §11.1 Non-Global Addresses | `crates/pharos-plugins/src/bind/mod.rs:47-58` | **Partial**: interface expansion adds zones to link-local unicast and scope-2 multicast only, not other non-global multicast scopes such as interface-local, realm-local, admin-local, site-local, or organization-local. It correctly leaves loopback addresses unzoned. | No |
| §11.1 Non-Global Addresses | `crates/pharos-plugins/src/expression/mod.rs:777-788` | **Partial**: `write_ip` appends `%scope_id` to every scoped IPv6 socket address, including global and loopback addresses where RFC 4007 says the form should not be used. | No |
| §11.2 The `<zone_id>` Part | `crates/pharos-plugins/src/lib.rs:402-409` | **Partial**: zone text resolves only through `if_nametoindex`; decimal zone indices, including `%0`, are treated as interface names and are not supported. Omitting the zone yields the default scope ID. | No |
| §11.2 The `<zone_id>` Part | `crates/pharos-plugins/src/secondary/update.rs:45-54` | **Violation**: `primary_matches` accepts interface-name zones but not numeric indices, and its comment cites RFC 4007 §11 rather than §11.2. No plugin README records this deviation, and ADR 0002 requires CoreDNS-compatible differences to be recorded in the compatibility document, which omits it. | No |
| §11.7 Combinations of Delimiter Characters | `crates/pharos-plugins/src/expression/mod.rs:777-819`, `crates/pharos-plugins/src/acl/mod.rs:104-120` | **Partial**: `client_ip()` can include a numeric scope ID, but `incidr()` and ACL CIDR parsing use `IpAddr`, which rejects zone-qualified prefixes such as `fe80::%2/64`. Callers cannot disambiguate a non-global prefix by zone as the section recommends, including for Realm-Local multicast added by RFC 7346. | No |
| §12 Security Considerations | `crates/pharos-plugins/src/acl/mod.rs:104-120,195-199,237-240` | **Violation**: ACL rules accept unqualified link-local prefixes, then compare only the client's bare `IpAddr`, discarding its IPv6 scope ID. RFC 4007 warns that link-local addresses without a zone index cannot be used in ACLs; no README or ADR justifies this behavior. | No |

## RFC 4025: A Method for Storing IPsec Keying Material in DNS

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.4 RDATA Format - Algorithm Type | `crates/pharos-proto/src/zone/rdata/advanced.rs:151-185`, `crates/pharos-proto/src/zone/rdata.rs:435-440` | **Fixed**: Algorithm 0 rejects nonempty key data. Fixed on `conf/proto` (#99). | No |
| §2.5 RDATA Format - Gateway | `crates/pharos-proto/src/zone/rdata/advanced.rs:504-509` | **Fixed**: IPv4-mapped IPv6 gateways are accepted. Fixed on `conf/proto` (#99). | No |
| §2.6 RDATA Format - Public Keys | `crates/pharos-proto/src/zone/rdata/advanced.rs:177-184` | **Partial**: Algorithm-specific RSA/DSA key checks remain deferred on `conf/proto` (#99) because they need typed key validation. | No |
| §3.1 Representation of IPSECKEY RRs | `crates/pharos-proto/src/zone/rdata/advanced.rs:148-152, 168, 493-516` | **Fixed**: Undefined gateway types and missing required gateway fields are rejected. Fixed on `conf/proto` (#99). | No |

## RFC 4033: DNS Security Introduction and Requirements

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.2 Authenticating Name and Type Non-Existence | `crates/pharos-plugins/src/dnssec/signing.rs:101-152, 234-289` | **Partial**: The plugin synthesizes and signs NSEC records for negative replies, but it does not check synthetic spans or bitmaps against authoritative zone data. A proof can therefore claim false name or type non-existence; the DNSSEC plugin README records this limitation. | Yes |
| §8.1 TTL Values vs. RRSIG Validity Period | `crates/pharos-plugins/src/cache/mod.rs:570-618`, `crates/pharos-plugins/src/cache/store.rs:163-207` | **Fixed**: Cache lifetime is capped at RRSIG expiry using serial arithmetic. Fixed on `conf/cache` (#97). | No |
| §8.1 TTL Values vs. RRSIG Validity Period | `crates/pharos-plugins/src/cache/mod.rs:618`, `crates/pharos-plugins/src/cache/setup.rs:54` | **Deviation**: The configured positive minimum TTL can extend cache lifetime past a short RR TTL; the cache README records the retained CoreDNS-compatible minimum-TTL floor (RFC 2181 §7.2; RFC 4033 §8.1). | Yes |
| §8.2 New Temporal Dependency Issues for Zones | `crates/pharos-plugins/src/sign/signer.rs:83-85` | **Partial**: The signer re-signs the SOA after replacing its serial with the current Unix timestamp. Equal or backward timestamps do not advance the serial as required; no documented exception found. | No |
| §12 Security Considerations | `crates/pharos-plugins/src/transfer/mod.rs:222-230`, `crates/pharos-plugins/src/tsig/mod.rs:84-95` | **Partial**: Transfers can proceed with IP-based authorization alone; TSIG is optional. RFC 4033 §12 requires TSIG, SIG(0), IPsec, or equivalent protection for zone transfers. | No |

## RFC 4034: Resource Records for the DNS Security Extensions

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.1.1 The Flags Field | `crates/pharos-plugins/src/dnssec/signing.rs:337-359` | **Fixed**: Runtime signing rejects keys without the Zone Key bit. Fixed on `conf/dnssec` (#100). | No |
| §2.1.1 The Flags Field | `crates/pharos-dnssec/src/keys.rs:288-314`, `crates/pharos-plugins/src/dnssec/setup.rs:88-95`, `crates/pharos-plugins/src/sign/signer.rs:93-109`, `crates/pharos-proto/src/rdata.rs:1124-1138` | **Fixed**: Key setup rejects reserved DNSKEY bits; receivers ignore them and serialization clears them. Fixed on `conf/proto` (#99) and `conf/dnssec` (#100). | No |
| §2.1.2 The Protocol Field | `crates/pharos-proto/src/rdata.rs:1124-1138` | **Partial**: Zone input validates protocol 3, but wire re-encoding preserves received protocol values for relay rather than normalizing them. This behavior remains open on `conf/proto` (#99). | No |
| §2.2 DNSKEY RR Presentation Format | `crates/pharos-proto/src/zone/rdata.rs:251-253` | **Fixed**: Zone DNSKEY protocol is parsed numerically and must equal 3. Fixed on `conf/proto` (#99). | No |
| §2.2 DNSKEY RR Presentation Format | `crates/pharos-proto/src/zone/rdata.rs:252-253`, `crates/pharos-dnssec/src/keys.rs:294-296` | **Fixed**: DNSKEY Algorithm mnemonics are accepted. Fixed on `conf/proto` (#99). | No |
| §3 The RRSIG Resource Record | `crates/pharos-plugins/src/sign/signer.rs:179-183,215-220` | **Fixed**: Apex NS RRSIG TTL matches the covered NS RRset TTL. Fixed on `conf/dnssec` (#100). | No |
| §3.1.4 Original TTL Field | `crates/pharos-plugins/src/dnssec/signing.rs:202-227,257-259,377-380` | **Deviation**: Generated signatures use the lowest TTL received in the response, which can be lower than the covered RRset's authoritative-zone TTL after caching. The dnssec plugin README records this response-signing policy and its CoreDNS compatibility. | Yes |
| §3.1.4 Original TTL Field | `crates/pharos-plugins/src/sign/signer.rs:179-183` | **Fixed**: Offline apex NS signatures use the covered NS RRset's TTL as Original TTL. Fixed on `conf/dnssec` (#100). | No |
| §3.1.5 Signature Expiration and Inception Fields | `crates/pharos-plugins/src/log/mod.rs:186-205`, `crates/pharos-plugins/src/sign/output.rs:13-46`, `crates/pharos-proto/src/response.rs:99-106`, `crates/pharos-proto/tests/response.rs:101-105` | **Partial**: Shared response validation uses RFC 1982 serial arithmetic (conf/server #101); logging and offline signer refresh still use separate ordinary/half-range comparisons and remain open. | No |
| §3.1.5 Signature Expiration and Inception Fields | `crates/pharos-proto/src/zone/rdata.rs:1179-1189`, `crates/pharos-proto/tests/zone_strictness.rs:58-78` | **Violation**: The parser wraps the year-2200 presentation time into a different 32-bit date instead of rejecting a date outside the permitted 68-year range. The comment at `zone/rdata.rs:1179` names §3.1.5 but does not enforce the range. | Yes |
| §3.1.7 The Signer's Name Field | `crates/pharos-plugins/src/sign/setup.rs:72-88`, `crates/pharos-plugins/src/sign/signer.rs:97-109,170-220` | **Deviation**: With multiple origins in one `sign` directive, each signature names its zone apex, but shared DNSKEY records use the last origin as owner. Earlier zones therefore lack the DNSKEY owner named by their RRSIG. `crates/pharos-plugins/src/sign/README.md` documents this CoreDNS-compatible behavior. | Yes |
| §3.1.7 The Signer's Name Field | `xtask/src/dnssec.rs:48-54` | **Fixed**: The verifier checks signer scope against the zone containing the covered RRset. Fixed on `conf/dnssec` (#100). | No |
| §3.1.8.1 Signature Calculation | `crates/pharos-plugins/src/sign/interop.rs:101-109` | **Fixed**: The verifier includes RRset class when selecting covered records. Fixed on `conf/dnssec` (#100). | No |
| §3.2 RRSIG RR Presentation Format | `crates/pharos-proto/src/rdata.rs:1436-1458`, `crates/pharos-proto/src/codes.rs:20-25,100` | **Fixed**: Type Covered 0 formats as `TYPE0`. Fixed on `conf/proto` (#99). | No |
| §4 NSEC Resource Record | `crates/pharos-plugins/src/sign/signer.rs:151` | **Violation**: generated NSEC TTL is SOA.MINIMUM. RFC 9077 §3.1 updates this to the lesser of SOA.MINIMUM and SOA TTL. | No |
| §4.1.2 Type Bit Maps Field | `crates/pharos-proto/src/rdata.rs:212-228,874-878,1460-1466` | **Fixed**: Wire parsing ignores TYPE0 bitmap bits and presentation omits them. Fixed on `conf/proto` (#99). | No |
| §4.1.2 Type Bit Maps Field | `crates/pharos-proto/src/zone/rdata.rs:305-316`, `crates/pharos-proto/tests/zone_strictness.rs:44-47`, `crates/pharos-proto/tests/zone_rdata.rs:191` | **Violation**: Zone parsing accepts NSEC RDATA with no type-bitmap blocks, although the field requires one or more nonempty blocks. | Yes |
| §4.1.2 Type Bit Maps Field | `crates/pharos-plugins/src/sign/signer.rs:130-148` | **Fixed**: Delegation bitmaps filter parent-side data. Fixed on `conf/dnssec` (#100). | No |
| §4.1.2 Type Bit Maps Field | `crates/pharos-dnssec/src/denial.rs:171-214` | **Fixed**: Compact-denial bitmaps contain RRSIG, NSEC, and NXNAME. Fixed on `conf/dnssec` (#100). | No |
| §6.2 Canonical RR Form | `crates/pharos-dnssec/src/canonical.rs:60-63, 293-295` | **Partial**: Canonicalization lowercases supported listed RDATA names and follows RFC 6840 §5.1 for NSEC and RRSIG. A6 and remaining legacy name-bearing types such as MD/MF, MINFO/RP, AFSDB/RT, SIG, and NXT are unsupported, so their RDATA names cannot be canonicalized. | Yes |
| §A.2 DNSSEC Digest Types | `crates/pharos-dnssec/src/digest.rs:6-9,54-65` | **Fixed**: The public SHA-1 DS/CDS digest API is removed; the signer emits SHA-256 CDS. Fixed on `conf/dnssec` (#100). | No |

## RFC 4035: Protocol Modifications for the DNS Security Extensions

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.1 Including DNSKEY RRs in a Zone — DNSKEY for each signing key | `crates/pharos-plugins/src/sign/setup.rs:71-83`, `crates/pharos-plugins/src/sign/signer.rs:93-110`, `crates/pharos-plugins/src/sign/README.md:14` | **Partial**: The offline signer publishes each signing key's DNSKEY only at `key_owner`, which setup assigns to the last configured origin. Earlier configured zones therefore lack their signer's DNSKEY; the README documents this CoreDNS-compatible behavior and recommends one directive per origin. | Yes |
| §2.1 Including DNSKEY RRs in a Zone — Zone Key bit | `crates/pharos-plugins/src/dnssec/setup.rs:79-95`, `crates/pharos-plugins/src/dnssec/signing.rs:337-359` | **Fixed**: Runtime setup rejects keys without the Zone Key bit. Fixed on `conf/dnssec` (#100). | No |
| §2.1 Including DNSKEY RRs in a Zone — apex secure entry point | `crates/pharos-plugins/src/sign/setup.rs:71-83`, `crates/pharos-plugins/src/sign/signer.rs:93-110`, `crates/pharos-plugins/src/sign/README.md:14` | **Deviation**: With multiple configured origins, earlier zones have no apex DNSKEY, despite the MUST for a signed zone intended to be usable beyond an island of security. The README documents this CoreDNS-compatible behavior; RFC 6840 §6.2 clarifies that the SEP bit itself does not determine secure-entry-point use. | Yes |
| §2.2 Including RRSIG RRs in a Zone | `crates/pharos-plugins/src/dnssec/signing.rs:337-359`, `crates/pharos-plugins/src/dnssec/mod.rs:112-128` | **Fixed**: Each DNSKEY algorithm signs each RRset required by RFC 6840 §5.11. Fixed on `conf/dnssec` (#100). | No |
| §2.2 Including RRSIG RRs in a Zone | `crates/pharos-plugins/src/sign/signer.rs:59-70,170-208` | **Fixed**: Offline signing rejects an SOA owner that differs from the signer zone; online signing uses the zone signer name. Fixed on `conf/dnssec` (#100). | No |
| §2.3 Including NSEC RRs in a Zone | `crates/pharos-plugins/src/dnssec/signing.rs:117-129`, `crates/pharos-dnssec/src/denial.rs:195-214` | **Deviation**: The plugin creates synthetic NSEC spans without checking zone contents. A span can cover existing descendant names, contrary to RFC 4470 §3; the DNSSEC README documents this CoreDNS-compatible limitation. | Yes |
| §2.3 Including NSEC RRs in a Zone | `crates/pharos-plugins/src/sign/signer.rs:73-85,147-155`, `crates/pharos-plugins/src/dnssec/signing.rs:130-141` | **Fixed**: Offline and synthetic NSEC TTLs use `min(SOA TTL, SOA.MINIMUM)`. Fixed on `conf/dnssec` (#100). | No |
| §2.3 Including NSEC RRs in a Zone | `crates/pharos-plugins/src/sign/signer.rs:130-155` | **Fixed**: Delegation bitmaps filter parent-side data. Fixed on `conf/dnssec` (#100). | No |
| §2.4 Including DS RRs in a Zone | `crates/pharos-plugins/src/sign/signer.rs:130-168`, `crates/pharos-plugins/src/zone/mod.rs:453-456` | **Fixed**: DS TTLs are normalized to the delegating NS TTL. Fixed on `conf/dnssec` (#100). | No |
| §2.4 Including DS RRs in a Zone | `crates/pharos-plugins/src/sign/signer.rs:49-70,130-168`, `crates/pharos-plugins/src/zone/mod.rs:153-187` | **Fixed**: Apex DS RRsets are rejected. Fixed on `conf/dnssec` (#100). | No |
| §2.5 Changes to the CNAME Resource Record | `crates/pharos-plugins/src/sign/signer.rs:49-70,130-168`, `crates/pharos-plugins/src/zone/mod.rs:199-229` | **Fixed**: Offline signing rejects data that cannot coexist at a CNAME owner. Fixed on `conf/dnssec` (#100). | No |
| §3 Serving — DNAME-synthesized CNAME signatures | `crates/pharos-plugins/src/zone/mod.rs:727-748`, `crates/pharos-plugins/src/dnssec/signing.rs:187-259` | **Fixed**: Synthesized CNAMEs from DNAME are left unsigned; real CNAMEs remain signed. Fixed on `conf/dnssec` (#100). | No |
| §3.1.1 Including RRSIG RRs in a Response — Additional-section truncation | `crates/pharos-plugins/src/dnssec/signing.rs:234-260`, `crates/pharos-proto/src/builder.rs:312-334` | **Fixed**: Optional Additional RRsets and their signatures are written transactionally; incomplete groups are omitted without TC. Fixed on `conf/dnssec` (#100) and `conf/server` (#101). | No |
| §3.1.1 Including RRSIG RRs in a Response — Answer priority | `crates/pharos-plugins/src/dnssec/signing.rs:187-260` | **Fixed**: Answer and Authority RRSIGs are prioritized over optional data. Fixed on `conf/dnssec` (#100). | No |
| §3.1.1 Including RRSIG RRs in a Response — Authority priority | `crates/pharos-plugins/src/dnssec/signing.rs:187-260` | **Fixed**: Answer and Authority RRSIGs are prioritized over optional data. Fixed on `conf/dnssec` (#100). | No |
| §3.1.3 Including NSEC RRs in a Response | `crates/pharos-plugins/src/dnssec/signing.rs:101-109`, `crates/pharos-plugins/tests/functional/dnssec_more.rs:680-715` | **Fixed**: Denial responses with extra Authority records receive generated proofs. Fixed on `conf/dnssec` (#100). | No |
| §3.1.3.1 Including NSEC RRs: No Data Response | `crates/pharos-plugins/src/dnssec/signing.rs:115-117,164-177,262-290` | **Fixed**: NSEC proofs and signatures are placed in Authority. Fixed on `conf/dnssec` (#100). | No |
| §3.1.3.2 Including NSEC RRs: Name Error Response | `crates/pharos-plugins/src/dnssec/signing.rs:99-112,151-156,262-289`, `crates/pharos-dnssec/src/denial.rs:171-215`, `crates/pharos-plugins/src/dnssec/README.md:17` | **Fixed**: Compact denial uses NXNAME in a synthetic NSEC bitmap and returns NOERROR. Fixed on `conf/dnssec` (#100); the implementation choice is recorded in the DNSSEC README and `docs/compatibility.md`. | Yes |
| §3.1.3.2 Including NSEC RRs: Name Error Response | `crates/pharos-plugins/src/dnssec/signing.rs:117-129`, `crates/pharos-dnssec/src/denial.rs:156-215`, `crates/pharos-plugins/src/dnssec/README.md:17` | **Deviation**: Synthetic black-lie NSEC spans are not checked against zone contents; the zone inventory is unavailable to the response signer. Recorded in the DNSSEC README and `docs/compatibility.md` (conf/dnssec #100). | Yes |
| §3.1.3.2 Including NSEC RRs: Name Error Response | `crates/pharos-plugins/src/zone/mod.rs:889-929`, `crates/pharos-plugins/src/file/tests.rs:432-489` | **Fixed**: The ENT closest-encloser proof is included. Fixed on `conf/zone` (#95). | No |
| §3.1.3.3 Including NSEC RRs: Wildcard Answer Response | `crates/pharos-plugins/src/zone/mod.rs:750-785,931-948` | **Fixed**: Wildcard CNAME signatures use the expanded QNAME and include the no-closer-match proof. Fixed on `conf/zone` (#95). | No |
| §3.1.3.4 Including NSEC RRs: Wildcard No Data Response | `crates/pharos-plugins/src/zone/mod.rs:855-867,931-948`, `crates/pharos-plugins/src/dnssec/signing.rs:117-145` | **Fixed**: Wildcard NODATA includes the closest-encloser proof. Fixed on `conf/zone` (#95). | No |
| §3.1.3.5 Finding the Right NSEC RRs — predecessor selection | `crates/pharos-plugins/src/zone/mod.rs:341-350,875-928` | **Partial**: ENT and wildcard proof selection are fixed (conf/zone #95); remaining NSEC predecessor edge cases need broader proof selection and remain open. | No |
| §3.1.4 Including DS RRs in a Response — no DS at delegation | `crates/pharos-plugins/src/zone/mod.rs:838-853,950-961` | **Fixed**: A no-DS referral includes the parent-side NSEC proof. Fixed on `conf/zone` (#95). | No |
| §3.1.4.1 Responding to Queries for DS RRs | `crates/pharos-plugins/src/secondary/mod.rs:144-151,201-204`, `crates/pharos-plugins/src/zone/mod.rs:293-311,518-532,541-544,684-688` | **Fixed**: DS queries route to the configured parent; child-only authority returns authoritative NODATA. Fixed on `conf/server` (#101). | Yes |
| §3.1.4.1 Responding to Queries for DS RRs | `crates/pharos-server/src/router.rs:160-207`, `crates/pharos-server/tests/router.rs:109-127` | **Fixed**: DS queries select the parent when configured, otherwise the child authority. Fixed on `conf/server` (#101). | Yes |
| §3.1.6 The AD and CD Bits in an Authoritative Response — CD bit | `crates/pharos-plugins/src/zone/mod.rs:710-715`, `crates/pharos-plugins/src/dnssec/mod.rs:104-105`, `crates/pharos-plugins/src/zone/transfer.rs:59-64`, `crates/pharos-plugins/src/local/mod.rs:161-164`, `crates/pharos-plugins/src/chaos/mod.rs:106-109` | **Partial**: Zone, transfer, and DNSSEC paths clear CD (`conf/zone` #95, `conf/secondary` #98, `conf/dnssec` #100); local and CHAOS response paths remain open. | No |
| §4.6 Handling of the CD and AD Bits | `crates/pharos-plugins/src/cache/mod.rs:663-666`, `crates/pharos-plugins/src/forward/setup.rs:91` | **Partial**: The cache clears AD only when the query has neither AD nor DO; otherwise it preserves upstream AD. Forward supports no TLS and exposes no AD-trust setting, so it does not disregard the upstream AD bit as §4.6 requires without a secure channel or explicit configuration. | No |

## RFC 4255: Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.1 The SSHFP RDATA Format | `crates/pharos-proto/src/rdata.rs:919-925,1204-1214` | **Deviation**: Wire parsing and encoding accept an SSHFP RDATA containing only the two header octets, with an empty fingerprint. The compatibility document records this CoreDNS-compatible behavior; ADR 0002 permits compatibility where deployments depend on it. | Yes |

## RFC 4291: IP Version 6 Addressing Architecture

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.3 Text Representation of Address Prefixes | `crates/pharos-corefile/src/key.rs:39-44` | **Deviation**: Server-block keys reject valid prefixes such as `::1/128` and `0:1::/32` to match CoreDNS v1.15.0's `plugin/normalize.go` guard. Recorded in `docs/compatibility.md` under ADR 0003. | Yes |

## RFC 4343: Domain Name System (DNS) Case Insensitivity Clarification

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.1 Escaping Unusual DNS Label Octets | `crates/pharos-proto/src/name.rs:115,243-245` | **Partial**: Presentation output escapes unusual octets, but both presentation parsers accept raw non-ASCII bytes. Section 2.1 requires escapes for those octets in ASCII presentation contexts. | Yes |
| §3 Name Lookup, Label Types, and CLASS | `crates/pharos-corefile/src/key.rs:67-68` | **Deviation**: Corefile keys use Go `strings.ToLower`, including Unicode mappings, to match CoreDNS v1.15.0 `plugin/normalize.go`; this exceeds RFC 4343's ASCII-only DNS folding. Recorded in `docs/compatibility.md` under ADR 0003. | Yes |
| §3 Name Lookup, Label Types, and CLASS | `crates/pharos-plugins/src/rewrite/mod.rs:769-772,2196-2199` | **Violation**: CNAME matching passes the presented RDATA name (case kept by `NameRef` Display, `name.rs:417-419`) to `matcher.matches` (`mod.rs:771`) unfolded, while rule text is lowercased at parse (`mod.rs:303-305,354-368`), so mixed-case DNS-equivalent targets miss. No ADR or README records this. | No |
| §3 Name Lookup, Label Types, and CLASS | `xtask/src/compare.rs:49-68,216-217` | **Partial**: Question and owner names compare as case-sensitive strings, so DNS-equivalent responses can be reported as different. This affects comparison results, not server output. | No |
| §3.1 Original DNS Label Types — ASCII case comparison | `crates/pharos-plugins/src/k8s_external/mod.rs:489-490` | **Fixed**: k8s_external target correlation uses ASCII case-insensitive DNS-name comparison. Fixed on `conf/k8s` (#103). | No |
| §3.1 Original DNS Label Types — ASCII case comparison | `crates/pharos-plugins/src/loadbalance/weighted.rs:187-190` | **Deviation**: Weight selection compares DNS labels byte-for-byte. The loadbalance README (line 14) records that CoreDNS compares presentation strings exactly; ADR 0002 permits that CoreDNS-compatible behavior. The README does not name case sensitivity explicitly. | Yes |
| §3.1 Original DNS Label Types — ASCII case comparison | `xtask/src/compare.rs:216-217,283` | **Partial**: Comparison treats owner-name and typed RDATA presentation strings as case-sensitive, so DNS-equivalent responses can be reported as different. This affects comparison results, not server output. | No |
| §4.1 DNS Output Case Preservation | `crates/pharos-plugins/src/rewrite/mod.rs:983-985,1195-1200` | **Violation**: Rewrite lowercases query and mapped names before response construction, losing their prior ASCII case. | No |
| §4.2 DNS Input Case Preservation | `crates/pharos-plugins/src/zone/mod.rs:140-151` | **Fixed**: Zone construction preserves input case for owners and name-bearing RDATA. Fixed on `conf/zone` (#95). | No |

## RFC 4398: Storing Certificates in the Domain Name System (DNS)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 The CERT Resource Record | `crates/pharos-plugins/src/dynupdate/mod.rs:235-247` | **Fixed**: Dynamic UPDATE rejects incomplete CERT headers, including short exact-delete RDATA. Fixed on `conf/dynupdate` (#96). | No |
| §2.1 Certificate Type Values | `crates/pharos-proto/src/zone/rdata/advanced.rs:107-119` | **Fixed**: The required `IPKIX` mnemonic is recognized. Fixed on `conf/proto` (#99). | No |
| §2.2 Text Representation of CERT RRs | `crates/pharos-proto/src/zone/rdata/advanced.rs:107-119` | **Fixed**: CERT text accepts the defined `IPKIX` mnemonic. Fixed on `conf/proto` (#99). | No |

## RFC 4470: Minimally Covering NSEC Records and DNSSEC On-line Signing

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3 Minimally Covering NSEC Records | `crates/pharos-dnssec/src/denial.rs:195-214`, `crates/pharos-plugins/src/dnssec/signing.rs:117-156` | **Deviation**: RFC requires the generated owner to sort before QNAME and the next name after it. `black_lie` uses QNAME as owner and only generates a following name; the signer also changes NXDOMAIN to NOERROR. The plugin README records this CoreDNS-compatible behavior. Verified erratum 81 corrects the escaped literals in the example physically located here; it does not change the ordering rule. | Yes |
| §3 Minimally Covering NSEC Records | `crates/pharos-dnssec/src/denial.rs:159-215`, `crates/pharos-plugins/src/dnssec/signing.rs:117-129` | **Deviation**: Generated spans must not cover existing names. The plugin has no authoritative name inventory to check spans; its README notes that referral spans can cover descendants. | Yes |
| §3 Minimally Covering NSEC Records | `crates/pharos-dnssec/src/denial.rs:159-215`, `crates/pharos-plugins/src/dnssec/signing.rs:117-129` | **Deviation**: Before answering, RFC requires checking the span and using a better epsilon or the closest covered existing name when needed. The plugin cannot perform this fallback because it lacks the zone inventory. | Yes |
| §3 Minimally Covering NSEC Records | `crates/pharos-dnssec/src/denial.rs:159-214`, `crates/pharos-plugins/src/dnssec/signing.rs:99-145,262-289` | **Violation**: For NODATA, QNAME exists and `black_lie` uses it as the synthetic NSEC owner. The signer returns that synthetic record instead of the existing name's real NSEC. | No |
| §3 Minimally Covering NSEC Records | `crates/pharos-dnssec/src/denial.rs:171-195` | **Partial**: The required RRSIG bit is retained for NODATA QTYPE=RRSIG (conf/dnssec #100); the synthetic black-lie bitmap still includes extra types, as recorded in `docs/compatibility.md`. | Yes |
| §3 Minimally Covering NSEC Records | `crates/pharos-plugins/src/dnssec/signing.rs:262-282,350-367` | **Fixed**: Required NSEC signatures are generated for each DNSKEY algorithm. Fixed on `conf/dnssec` (#100). | No |
| §4 Better Epsilon Functions | `crates/pharos-dnssec/src/denial.rs:159-215`, `crates/pharos-plugins/src/dnssec/signing.rs:117-129` | **Deviation**: An authoritative server should ensure generated spans cover no existing names. The plugin does not check spans against zone data; its README records this limitation. | Yes |

## RFC 4509: Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records (RRs)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.2 DS Record with SHA-256 Wire Format | `crates/pharos-proto/src/rdata.rs:815-834, 1108-1122`, `crates/pharos-proto/src/zone/rdata.rs:234-243` | **Fixed**: SHA-256 DS digests require exactly 32 octets. Fixed on `conf/proto` (#99). | No |

## RFC 4592: The Role of Wildcards in the Domain Name System

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.2.1 An Example | `crates/pharos-plugins/src/hosts/data.rs:138-149,184-187` | **Deviation**: `hosts` replaces only the first QNAME label when seeking a wildcard, so `*.example.org` does not answer `a.b.example.org` when `b.example.org` is absent, unlike the RFC example. The CoreDNS-port test preserves this behavior; ADR 0002 permits CoreDNS-compatible behavior, but this specific difference is not recorded in the plugin README. | No |
| §2.2.3 Yet Another Definition of Existence | `crates/pharos-plugins/src/zone/mod.rs:200-224,541-544,684-687` | **Fixed**: The apex exists even when the requested type is absent, so lookup returns NODATA rather than NXDOMAIN. Fixed on `conf/zone` (#95). | No |
| §3.2 Step 3 | `crates/pharos-plugins/src/zone/mod.rs:541-581` | **Fixed**: Wildcard synthesis is gated by name existence; an empty non-terminal blocks it. Fixed on `conf/zone` (#95). | No |
| §3.3 Part 'c' | `crates/pharos-plugins/src/hosts/data.rs:133-149` | **Partial**: wildcard lookup checks only `*.<immediate parent>`. For a missing intermediate name, it does not try the wildcard below the closest existing encloser, so valid synthesis can be missed. | No |
| §3.3.1 Closest Encloser and the Source of Synthesis | `crates/pharos-plugins/src/zone/mod.rs:541-581` | **Fixed**: Existing empty non-terminals are the closest encloser and block wildcard synthesis. Fixed on `conf/zone` (#95). | No |
| §3.3.1 Closest Encloser and the Source of Synthesis | `crates/pharos-plugins/src/hosts/data.rs:133-149` | **Partial**: the hosts lookup never searches ancestor suffixes for the closest encloser. It misses synthesis from `*.<closest encloser>` whenever the immediate parent does not exist. | No |
| §4.4 DNAME RRSet at a Wildcard Domain Name | `crates/pharos-plugins/src/zone/mod.rs:166-180,563-581,794-810` | **Fixed**: Zone loading rejects wildcard-owned DNAME records. Fixed on `conf/zone` (#95). | No |
| §4.7 NSEC RRSet at a Wildcard Domain Name | `crates/pharos-plugins/src/sign/signer.rs:130-155` | **Partial**: the signer creates NSEC records only for owners that already have records. An empty non-terminal wildcard owner is omitted from the generated NSEC chain. | No |
| §4.7 NSEC RRSet at a Wildcard Domain Name | `crates/pharos-plugins/src/zone/mod.rs:794-810` | **Fixed**: Wildcard NSEC records are not synthesized at a different QNAME. Fixed on `conf/zone` (#95). | No |

## RFC 4648: The Base16, Base32, and Base64 Data Encodings

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.3 Interpretation of Non-Alphabet Characters in Encoded Data | `crates/pharos-proto/src/tsig_key.rs:32-45` | **Deviation**: `decode_secret` removes CR/LF before decoding, accepting non-alphabet characters; ADR 0002 permits CoreDNS-compatible behavior. | Yes |
| §12 Security Considerations | `crates/pharos-proto/src/zone/rdata.rs:933-968`, `crates/pharos-proto/src/zone/rdata/legacy.rs:263-314`, `crates/pharos-proto/src/zone/rdata/advanced.rs:560-579`, `crates/pharos-dnssec/src/keys.rs:121-127,192-194,301-303`, `crates/pharos-proto/src/tsig_key.rs:42-45` | **Partial**: Base64 fields are decoded before size checks. Input caps remain deferred on `conf/infra` (#105) for `tsig_key.rs` (outside its ownership) and on `conf/proto` (#99) for the other typed decoders. | No |

## RFC 5001: DNS Name Server Identifier (NSID) Option

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.4 Presentation Format | `crates/pharos-plugins/src/nsid/mod.rs:16-24, crates/pharos-proto/src/edns_options.rs:308` | **Partial**: NSID display includes two hexadecimal digits per payload octet, but the Corefile writer copies the default hostname or configured text as bytes instead of accepting the required hex presentation. No §2.4 exception is recorded. | No |

## RFC 5155: DNS Security (DNSSEC) Hashed Authenticated Denial of Existence

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.1.2 Flags | `crates/pharos-proto/src/rdata.rs:882-907,1167-1180` | **Fixed**: Zone NSEC3 flags are validated; reserved flags are handled per the wire receive rules. Fixed on `conf/proto` (#99). | No |
| §3.1.3 Iterations (RFC 9276 §3.1) | `crates/pharos-dnssec/src/denial.rs:294-322` | **Fixed**: `nsec3_chain` rejects nonzero iteration counts. Fixed on `conf/dnssec` (#100). | No |
| §3.1.6 Hash Length | `crates/pharos-proto/src/rdata.rs:898-907, 1175-1180` | **Fixed**: NSEC3 requires a 1–255-octet Next Hashed Owner Name. Fixed on `conf/proto` (#99). | No |
| §3.2.1 Type Bit Maps Encoding | `crates/pharos-proto/src/rdata.rs:1175-1180`, `crates/pharos-proto/src/zone/rdata.rs:1004-1022` | **Fixed**: Wire parsers ignore TYPE0 bitmap bits, presentation omits them, and zone input remains strict. Fixed on `conf/proto` (#99). | No |
| §3.2.1 Type Bit Maps Encoding | `crates/pharos-dnssec/src/denial.rs:44-50`, `crates/pharos-proto/src/rdata.rs:1175-1180`, `crates/pharos-proto/src/zone/rdata.rs:1004-1022` | **Partial**: TYPE0 handling is fixed on `conf/proto` (#99); other pseudo-types and QTYPEs beyond the supported NXNAME exception remain deferred because they need a separate bitmap representation. | No |
| §4 The NSEC3PARAM Resource Record | `crates/pharos-dnssec/src/denial.rs:294-299` | **Fixed**: The NSEC3 chain builder requires zero iterations and empty salt. Fixed on `conf/dnssec` (#100). | No |
| §4.1.3 Iterations | `crates/pharos-dnssec/src/denial.rs:294-299,322-335` | **Fixed**: The NSEC3 chain generator rejects nonzero iterations. Fixed on `conf/dnssec` (#100). | No |
| §4.1.5 Salt | `crates/pharos-dnssec/src/denial.rs:294-299,322-335` | **Fixed**: The NSEC3 chain generator rejects nonempty salts. Fixed on `conf/dnssec` (#100). | No |
| §7.1 Zone Signing | `crates/pharos-dnssec/src/denial.rs:290-347`, `crates/pharos-plugins/src/sign/signer.rs:139-155`, `crates/pharos-plugins/src/zone/mod.rs:115-117,159-160` | **Partial**: `nsec3_chain` builds a circular chain for supplied owners and empty non-terminals, but the zone signer never calls it and rejects NSEC3 zones. The helper does not provide an end-to-end NSEC3 signing path. | No |
| §7.1 Zone Signing | `crates/pharos-dnssec/src/denial.rs:294-299,322-336` | **Fixed**: `nsec3_chain` rejects nonzero iterations. Fixed on `conf/dnssec` (#100). | No |
| §7.1 Zone Signing | `crates/pharos-dnssec/src/denial.rs:294-299,322-336` | **Fixed**: `nsec3_chain` rejects nonempty salts. Fixed on `conf/dnssec` (#100). | No |
| §9.2 Use of the AD Bit | `crates/pharos-plugins/src/forward/mod.rs:378-397` | **Violation**: Forward copies upstream AD unchanged, including when a response contains an Opt-Out closest-encloser proof. The RFC 6840 §5.8 citation in cache code covers query signaling, not this prohibition. | No |
| §10.3 Iterations — RFC 9276 update | `crates/pharos-dnssec/src/denial.rs:294-299,322-337` | **Fixed**: The builder accepts only zero iterations. Fixed on `conf/dnssec` (#100). | No |
| §10.3 Iterations — per-key ceiling | `crates/pharos-dnssec/src/denial.rs:294-299,322-337` | **Fixed**: Zero iterations stay below the per-key ceiling. Fixed on `conf/dnssec` (#100). | No |
| §11 IANA Considerations | `crates/pharos-proto/src/rdata.rs:882-896,1182-1190` | **Fixed**: Received nonzero NSEC3PARAM flags are ignored and emitted as zero; zone input remains strict. Fixed on `conf/proto` (#99). | No |
| §12.1.1 Dictionary Attacks | `crates/pharos-dnssec/src/denial.rs:294-301` | **Partial**: RFC 9276 §3.1 supersedes the earlier salt advice and recommends zero-length salt. `nsec3_chain` takes caller-supplied salt and permits nonempty values, but has no default or policy to guide the signer toward zero length. | No |
| §12.1.4 Using High Iteration Values | `crates/pharos-dnssec/src/denial.rs:219-243,294-299` | **Violation**: `nsec3_chain` accepts any `u16` iteration count and `nsec3_hash` performs that many additional rounds. RFC 9276 §3.1 requires zone publishers to use 0 iterations when using NSEC3. | No |
| §C.2.1 Avoiding Hash Collisions During Generation | `crates/pharos-dnssec/src/denial.rs:339-342` | **Partial**: `nsec3_chain` detects a duplicate hash and returns `HashCollision`, whose message tells the caller to choose another salt. As the chain generator/signer, it does not choose that salt or retry to regenerate the full chain; the nearby citation names §7.1, not §C.2.1. | No |

## RFC 5452: Measures for Making DNS More Resilient against Forged Answers

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3 Description of DNS Spoofing — matching the question section | `crates/pharos-plugins/src/proxy/mod.rs:560-567`, `crates/pharos-plugins/src/forward/resolve.rs:84-104` | **Fixed**: Proxy and configured-resolver paths validate the response Question and discard mismatches. Fixed on `conf/forward` (#104). | No |
| §4.2 Matching the Question Section | `crates/pharos-plugins/src/proxy/mod.rs:560-568`, `crates/pharos-plugins/src/forward/resolve.rs:84-89`, `crates/pharos-plugins/src/proxy/health.rs:230-235` | **Fixed**: Forward resolver and health probes match the response Question to the query. Fixed on `conf/forward` (#104). | No |
| §4.2 Matching the Question Section | `crates/pharos-plugins/src/secondary/update.rs:183-216` | **Fixed**: Secondary SOA checks validate the echoed Question. Fixed on `conf/secondary` (#98). | No |
| §6 Accepting Only In-Domain Records | `crates/pharos-plugins/src/cache/mod.rs:596-598`, `crates/pharos-plugins/src/cache/store.rs:302-304`, `crates/pharos-plugins/src/forward/resolve.rs:89-103` | **Violation**: The cache stores every Answer, Authority, and Additional record of a forwarded Response with no owner-name check, and setup lookups take A/AAAA data from any owner name. No ADR or plugin README justifies this, and ADR 0002 defaults to RFC behaviour. | No |
| §9.1 Query Matching Rules | `crates/pharos-plugins/src/proxy/mod.rs:507-567`, `crates/pharos-plugins/src/forward/resolve.rs:84-104` | **Fixed**: Setup-time A/AAAA lookups validate ID, QR, Question, and RCODE before accepting addresses. Fixed on `conf/forward` (#104). | No |
| §9.1 Query Matching Rules | `crates/pharos-plugins/src/loop/mod.rs:188-193` | **Partial**: The loop probe accepts any parseable response with the matching ID; it does not match the response QNAME, QTYPE, or QCLASS to its query. | No |
| §9.2 Avoiding Certain Ports | `crates/pharos-plugins/src/proxy/mod.rs:339-342`, `crates/pharos-plugins/src/forward/mod.rs:160-172` | **Missing**: UDP binds use port 0, and forward configuration exposes no way to exclude specific source ports. | No |
| §9.2 Unpredictable Source Addresses | `crates/pharos-plugins/src/forward/mod.rs:160-172`, `crates/pharos-plugins/src/proxy/mod.rs:350-364` | **Missing**: A proxy can bind one configured source address or use the route-selected address; it does not choose unpredictably among multiple local addresses. | No |
| §9.2 Unpredictable Source Port | `crates/pharos-plugins/src/proxy/mod.rs:339-342,447-475,572-585` | **Partial**: UDP sockets remain pooled and reuse source ports. Deferred to issue #109 for a bounded randomized-port design and burst/latency measurement; documented in the forward README and `docs/compatibility.md`. | Yes |
| §9.2.1 Justification and Discussion | `crates/pharos-plugins/src/proxy/mod.rs:339-342,447-475,572-585` | **Partial**: UDP source-port reuse is tracked in #109; source-address randomization remains deferred on `conf/forward` (#104) because it needs a separate bounded design. The tradeoff is documented in the forward README and `docs/compatibility.md`. | Yes |

## RFC 5625: DNS Proxy Implementation Guidelines

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3 The Transparency Principle | `crates/pharos-plugins/src/forward/mod.rs:182-185`, `crates/pharos-plugins/src/proxy/mod.rs:407-414` | **Partial**: the proxy normally uses the client's transport, but `prefer_udp` sends TCP-client queries upstream over UDP. The forward README records this CoreDNS-compatible option. | Yes |
| §4.4.1 TCP Transport | `crates/pharos-plugins/src/proxy/mod.rs:407-414` | **Deviation**: With `prefer_udp`, the proxy sends even a TCP-received Query over UDP first, then retries over TCP only if the UDP response has TC. The `forward` README documents this CoreDNS-compatible transport preference. | Yes |
| §4.4.2 Extension Mechanisms for DNS (EDNS0) | `crates/pharos-server/src/admission.rs:57-64`, `crates/pharos-proto/src/edns.rs:26-33` | **Partial**: Unsupported EDNS-version proxying remains deferred because admission is in unowned `pharos-server` paths (conf/forward #104; conf/server #101). | No |
| §4.5 Secret Key Transaction Authentication for DNS (TSIG) | `crates/pharos-plugins/src/tsig/mod.rs:166-178`, `crates/pharos-plugins/src/forward/mod.rs:253-265`, `crates/pharos-server/src/outcome.rs:108-147,327-329` | **Fixed**: AD is cleared only after verified client TSIG is stripped and Pharos re-signs without upstream transaction security. Fixed on `conf/forward` (#104). | No |
| §6.1 Forgery Resilience | `crates/pharos-plugins/src/proxy/mod.rs:476-487` | **Deviation**: Upstream queries get unpredictable random IDs (RFC 5452 §9.2), but TSIG-signed Queries with unshared keys keep the client's ID, because RFC 8945 §5.5 requires forwarding them unchanged. The `forward` README documents that TSIG Messages retain their original ID. | Yes |
| §6.2 Interface Binding | `crates/pharos-corefile/src/setup.rs:61-65`, `crates/pharos-plugins/src/lib.rs:399-402`, `crates/pharos-server/src/lib.rs:877-899`, `crates/pharos/src/app.rs:41-43` | **Deviation**: The default listener binds an unspecified dual-stack address and can expose a `forward` proxy on every interface; configure `bind` to restrict it. Recorded in `docs/compatibility.md` (RFC 5625 §6.2; conf/infra #105). | Yes |
| §6.3 Packet Filtering | `crates/pharos-server/src/admission.rs:24-47` | **Partial**: Malformed packets of at least four octets receive FORMERR; packets shorter than four octets remain dropped. The `conf/server` fix covers malformed messages that pass the four-octet minimum (#101). | No |

## RFC 5702: Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.1 RSA/SHA-256 DNSKEY Resource Records | `crates/pharos-dnssec/src/sign.rs:75-85`, `crates/pharos-dnssec/src/keys.rs:129-149` | **Fixed**: RSA/SHA-256 keys are capped at 4096 bits. Fixed on `conf/dnssec` (#100). | No |
| §2.2 RSA/SHA-512 DNSKEY Resource Records | `crates/pharos-dnssec/src/sign.rs:75-85`, `crates/pharos-dnssec/src/keys.rs:129-149` | **Fixed**: RSA/SHA-512 keys are capped at 4096 bits. Fixed on `conf/dnssec` (#100). | No |

## RFC 5936: DNS Zone Transfer Protocol (AXFR)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.2 AXFR Response | `crates/pharos-plugins/src/erratic/mod.rs:45-51`, `crates/pharos-plugins/src/erratic/xfr.rs:59-99` | **Deviation**: the `erratic` test plugin can end a successful-looking AXFR without its closing SOA to simulate truncation; its README records this scenario. | Yes |
| §2.2 AXFR Response | `crates/pharos-plugins/src/zone/transfer.rs:31-34,66-73,123-131`, `crates/pharos-plugins/src/kubernetes/transfer.rs:136-168,484-520`, `crates/pharos-plugins/src/k8s_external/transfer.rs:128-133,696-707`, `crates/pharos-plugins/src/erratic/xfr.rs:20-24,53-93` | **Partial**: Zone, Kubernetes, and k8s_external transfer paths reject non-IN classes (conf/zone #95; conf/k8s #103); the `erratic` test transfer builder remains open. | No |
| §2.2 AXFR Response | `crates/pharos-plugins/src/secondary/update.rs:92-127`, `crates/pharos-plugins/src/zone/mod.rs:194-198` | **Fixed**: The secondary drops duplicate transferred RRs, and Zone construction suppresses duplicate records. Fixed on `conf/secondary` (#98) and `conf/zone` (#95). | No |
| §2.2 AXFR Response | `crates/pharos-plugins/src/zone/mod.rs:194-198`, `crates/pharos-plugins/src/zone/transfer.rs:83-96`, `crates/pharos-plugins/src/k8s_external/transfer.rs:245-260` | **Fixed**: Zone and k8s_external transfer builders suppress duplicate records and address records per port. Fixed on `conf/zone` (#95) and `conf/k8s` (#103). | No |
| §2.2 AXFR Response | `xtask/src/differential.rs:499-516`, `xtask/src/compare.rs:90-117` | **Fixed**: The differential AXFR client compares across Messages and ignores duplicate RRs. Fixed on `conf/infra` (#105). | No |
| §2.2 AXFR Response | `xtask/src/differential.rs:487-516` | **Fixed**: Differential AXFR comparison preserves Message boundaries and supports multi-Message transfers. Fixed on `conf/infra` (#105). | No |
| §2.2 AXFR Response | `xtask/src/differential.rs:453-468` | **Fixed**: Differential AXFR requires the opening SOA to belong to the requested zone. Fixed on `conf/infra` (#105). | No |
| §2.2.1 Header Values | `crates/pharos-plugins/src/zone/transfer.rs:59-64`, `crates/pharos-plugins/src/kubernetes/transfer.rs:155-161`, `crates/pharos-plugins/src/k8s_external/transfer.rs:120-126`, `crates/pharos-plugins/src/erratic/xfr.rs:21-24`, `crates/pharos-server/src/admission.rs:77-92` | **Partial**: Zone, Kubernetes, and k8s_external transfers clear CD (conf/zone #95; conf/k8s #103); the `erratic` transfer builder remains open. | No |
| §2.2.2 Question Section | `crates/pharos-plugins/src/zone/transfer.rs:66-73` | **Fixed**: Zone transfer responses preserve the request Question. Fixed on `conf/zone` (#95). | No |
| §2.2.5 Additional Section | `crates/pharos-server/src/outcome.rs:55-65`, `crates/pharos-plugins/src/transfer/mod.rs:26-35`, `crates/pharos-plugins/src/zone/transfer.rs:57-73`, `crates/pharos-plugins/src/kubernetes/transfer.rs:155-172`, `crates/pharos-plugins/src/k8s_external/transfer.rs:120-137` | **Partial**: AXFR OPT forwarding remains deferred: it crosses shared transfer/server files outside `conf/secondary` (#98) and `conf/k8s` (#103) ownership. | No |
| §2.3 TCP Connection Aborts | `crates/pharos-plugins/src/secondary/update.rs:171-175,303-315` | **Partial**: Failure classification remains deferred on `conf/secondary` (#98); the report leaves RFC 5936 retry/failure policy work open. | No |
| §2.3 TCP Connection Aborts | `crates/pharos-plugins/src/secondary/update.rs:303-315` | **Partial**: Startup transfers still retry indefinitely with a capped delay. Deferred on `conf/secondary` (#98) because retry-policy/state changes need separate work. | No |
| §2.3 TCP Connection Aborts | `crates/pharos-server/src/tcp.rs:235-247` | **Partial**: Broader TCP session teardown remains deferred on `conf/server` (#101); aborting a shared connection can affect other sessions. | No |
| §3.1 Records to Include | `crates/pharos-plugins/src/zone/mod.rs:145-160`, `crates/pharos-plugins/src/zone/transfer.rs:74-136` | **Partial**: Out-of-zone owner and required-glue validation remain deferred on `conf/zone` (#95); classification needs glue/occlusion handling and broader fixture updates. | No |
| §3.1 Records to Include | `crates/pharos-plugins/src/kubernetes/transfer.rs:368-477` | **Partial**: AXFR now includes `dns-version` and service records (conf/k8s #103); reverse-zone PTR reconstruction remains deferred because it needs visible-address enumeration and deduplication. | No |
| §3.4 Name Compression | `crates/pharos-plugins/src/zone/mod.rs:145-174`, `crates/pharos-proto/src/builder.rs:356-365` | **Fixed**: Zone construction preserves owner and embedded-name case for AXFR. Fixed on `conf/zone` (#95). | No |
| §4.1.1 AXFR Client TCP — connection reuse | `crates/pharos-server/src/transfer.rs:165-183`, `crates/pharos-plugins/src/secondary/update.rs:75-93,178-200` | **Partial**: SOA check and AXFR still use separate connections. Reuse was deferred on `conf/secondary` (#98) as an invasive transfer change. | No |
| §4.1.2 AXFR Server TCP — remote close | `crates/pharos-server/src/tcp.rs:185-190,310` | **Violation**: remote closure ends the read loop but does not cancel active transfer tasks; they can continue until a later write fails or the stream ends. | No |
| §5 Authorization | `crates/pharos-plugins/src/transfer/mod.rs:282-299` | **Partial**: `to` accepts exact IP addresses and `*`, but not IP address ranges as RFC 5936 recommends. | No |
| §5 Authorization | `crates/pharos-plugins/src/transfer/mod.rs:211-228`, `crates/pharos-plugins/tests/functional/transfer.rs:121-151` | **Deviation**: exact-text ACL matching preserves CoreDNS behavior under ADR 0002; equivalent IPv6 spellings can be denied. | Yes |
| §6 Zone Integrity | `crates/pharos-plugins/src/secondary/update.rs:304-315,334-345` | **Partial**: Failed transfers preserve the active Zone, but rejected serial memory remains deferred on `conf/secondary` (#98) as retry-policy state. | No |
| §6 Zone Integrity | `crates/pharos-server/src/transfer.rs:195-219`, `crates/pharos-plugins/src/zone/mod.rs:192-197`, `crates/pharos-plugins/src/secondary/update.rs:135-154` | **Fixed**: AXFR clients compare the closing SOA to the opening SOA before publishing. Fixed on `conf/secondary` (#98). | No |
| §6.3.1 Connection Reuse | `crates/pharos-plugins/src/secondary/update.rs:75-92,178-200`, `crates/pharos-server/src/transfer.rs:165-183` | **Partial**: SOA check and AXFR still use separate connections. Reuse was deferred on `conf/secondary` (#98) as an invasive transfer change. | No |
| §6.3.4 The edns-tcp-keepalive EDNS(0) Option | `crates/pharos-server/src/outcome.rs:55-65`, `crates/pharos-plugins/src/transfer/mod.rs:26-35`, `crates/pharos-plugins/src/zone/transfer.rs:57-73`, `crates/pharos-plugins/src/kubernetes/transfer.rs:155-172`, `crates/pharos-plugins/src/k8s_external/transfer.rs:120-137` | **Partial**: Streamed AXFR OPT remains deferred on `conf/secondary` (#98), `conf/k8s` (#103), and `conf/server` (#101); it crosses shared transfer/server paths. | No |

## RFC 6052: IPv6 Addressing of IPv4/IPv6 Translators

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.2 IPv4-Embedded IPv6 Address Format — prefix lengths | `crates/pharos-plugins/src/siit/mod.rs:50-60`, `crates/pharos-plugins/src/dns64/mod.rs:91-97` | **Deviation**: The Well-Known Prefix is restricted to /96, unlike CoreDNS's acceptance of other lengths. Recorded in `docs/compatibility.md` (RFC 6052 §§2.1–2.2; conf/plugins-synth #102). | Yes |
| §2.2 IPv4-Embedded IPv6 Address Format — reserved octet | `crates/pharos-plugins/src/dns64/mod.rs:81-97,180-189` | **Fixed**: Shared DNS64/SIIT prefix validation rejects nonzero reserved octets after masking host bits. Fixed on `conf/plugins-synth` (#102). | No |
| §3.1 Restrictions on the Use of the Well-Known Prefix — MUST NOT represent non-global IPv4 | `crates/pharos-plugins/src/siit/mod.rs:30,102-126`, `crates/pharos-plugins/src/dns64/mod.rs:31,177-199` | **Partial**: Global-IPv4 filtering remains deferred on `conf/plugins-synth` (#102) because it needs a complete special-use/global address policy in both DNS64 and SIIT. | No |
| §3.1 Restrictions on the Use of the Well-Known Prefix — MUST NOT translate and MUST drop non-global IPv4 | `crates/pharos-plugins/src/siit/mod.rs:102-126` | **Partial**: Non-global IPv4 filtering remains deferred on `conf/plugins-synth` (#102) pending a complete address policy. | No |
| §3.3 Choice of Prefix for Stateless Translation Deployments | `crates/pharos-plugins/src/siit/mod.rs:29-33` | **Partial**: SIIT permits a Network-Specific Prefix, but defaults to the Well-Known Prefix. RFC 6052 recommends a Network-Specific Prefix for stateless deployments; no ADR or plugin README records a rationale for this default. | No |

## RFC 6147: DNS64: DNS Extensions for Network Address Translation from IPv6 Clients to IPv4 Servers

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §5 DNS64 Normative Specification | `crates/pharos-plugins/src/dns64/mod.rs:19-25,30-35,180-189` | **Partial**: DNS64 still supports one synthesis prefix; per-range prefixes remain deferred on `conf/plugins-synth` (#102) as a broader DNS64 processing feature. | No |
| §5 DNS64 Normative Specification | `crates/pharos-plugins/src/dns64/mod.rs:100-112` | **Missing**: PTR synthesis is deferred on `conf/plugins-synth` (#102) until DNS64 response processing supports reverse synthesis. | No |
| §5.1.2 The Answer when There is an Error | `crates/pharos-plugins/src/dns64/mod.rs:127-130`, `crates/pharos-proto/src/response.rs:52-67,69-76` | **Violation**: With DO set, an RCODE=3 response containing an expired RRSIG is classified as `OtherError`, so DNS64 attempts synthesis instead of returning the Name Error under normal DNS handling. | No |
| §5.1.3 Dealing with Timeouts | `crates/pharos-plugins/src/dns64/mod.rs:115-117`, `crates/pharos-plugins/src/forward/mod.rs:400` | **Partial**: Timeout-as-empty behavior remains deferred on `conf/plugins-synth` (#102) with the broader DNS64 response-processing changes. | No |
| §5.1.4 Special Exclusion Set for AAAA Records — answer contains both excluded and usable AAAA | `crates/pharos-plugins/src/dns64/mod.rs:127-130` | **Partial**: Mixed excluded/usable AAAA filtering remains deferred on `conf/plugins-synth` (#102) because it needs safe record filtering and Response rebuilding. | No |
| §5.1.4 Special Exclusion Set for AAAA Records — answer contains only excluded AAAA | `crates/pharos-plugins/src/dns64/mod.rs:127-130` | **Partial**: Excluded-only AAAA handling remains deferred on `conf/plugins-synth` (#102) with the DNS64 response rebuild work. | No |
| §5.1.4 Special Exclusion Set for AAAA Records — configure exclusion ranges | `crates/pharos-plugins/src/dns64/mod.rs:19-35,100-112` | **Partial**: Configurable exclusion ranges remain deferred on `conf/plugins-synth` (#102) as a broader DNS64 feature. | No |
| §5.1.4 Special Exclusion Set for AAAA Records — default `::ffff/96` exclusion | `crates/pharos-plugins/src/dns64/mod.rs:127-130` | **Partial**: The default `::ffff/96` exclusion remains deferred on `conf/plugins-synth` (#102) because mixed answers need safe filtering and rebuilding. | No |
| §5.1.4 Special Exclusion Set for AAAA Records — never return excluded AAAA | `crates/pharos-plugins/src/dns64/mod.rs:127-130` | **Partial**: Excluded AAAA filtering remains deferred on `conf/plugins-synth` (#102) because it requires removing records and rebuilding the Response. | No |
| §5.1.5 Dealing with CNAME and DNAME — follow chain to terminal A or AAAA | `crates/pharos-plugins/src/dns64/mod.rs:138-147,171-208` | **Partial**: Terminal alias chasing remains deferred on `conf/plugins-synth` (#102) until DNS64 response processing is extended. | No |
| §5.1.7 Performing the Synthesis — select prefix by configured IPv4 ranges | `crates/pharos-plugins/src/dns64/mod.rs:28-35,177-189` | **Partial**: Per-range prefix selection remains deferred on `conf/plugins-synth` (#102) as a larger DNS64 feature. | No |
| §5.2 Generation of the IPv6 Representations of IPv4 Addresses | `crates/pharos-plugins/src/dns64/mod.rs:81-97,180-189`, `crates/pharos-plugins/src/siit/mod.rs:47-60,102-126` | **Fixed**: DNS64 and SIIT use the shared validator for masked prefixes and reserved-octet checks. Fixed on `conf/plugins-synth` (#102). | No |
| §5.3.1 PTR Resource Record — address matching | `crates/pharos-plugins/src/dns64/mod.rs:100-114` | **Missing**: PTR synthesis is deferred on `conf/plugins-synth` (#102) until DNS64 response processing supports reverse synthesis. | No |
| §5.3.1 PTR Resource Record — response strategy | — | **Missing**: PTR synthesis is deferred on `conf/plugins-synth` (#102) until DNS64 response processing supports reverse synthesis. | No |
| §5.3.2 Handling the Additional Section | `crates/pharos-plugins/src/dns64/mod.rs:171-207` | **Partial**: the code restricts synthesis to A records in Answer, but re-parses and re-serializes all other records. Unsupported name-bearing or malformed records return an error instead of passing through unchanged; the plugin README records this limitation. | Yes |
| §5.3.3 Other Resource Records | `crates/pharos-plugins/src/dns64/mod.rs:107-112,200-207` | **Partial**: non-AAAA queries, including A queries, pass through, and parsed records are copied semantically. Unsupported name-bearing or malformed records in a synthesized response fail instead of being returned unchanged; the plugin README records this limitation. | Yes |
| §5.4 Assembling a Synthesized Response to a AAAA Query | `crates/pharos-plugins/src/dns64/mod.rs:157-166` | **Fixed**: Synthesized responses preserve AA/RA from the initial AAAA lookup. Fixed on `conf/plugins-synth` (#102). | No |
| §5.4 Assembling a Synthesized Response to a AAAA Query | `crates/pharos-plugins/src/dns64/mod.rs:127-147,166-209` | **Fixed**: A successful empty A lookup returns the original AAAA response. Fixed on `conf/plugins-synth` (#102). | No |

## RFC 6303: Locally Served DNS Zones

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §1 Introduction | `crates/pharos-plugins/src/local/mod.rs:78-90` | **Partial**: The local plugin recognizes only a subset of reverse zones. The full reverse-zone catalogue is deferred on `conf/plugins-synth` (#102) as a broader feature. | No |
| §3 Changes to Iterative Resolver Behaviour | `crates/pharos-plugins/src/local/mod.rs:111-165` | **Partial**: Intercepted local answers now set AA (conf/plugins-synth #102); RFC 6303 zone-list coverage remains incomplete as listed under §1 and §4. | No |
| §3 Changes to Iterative Resolver Behaviour | `crates/pharos-plugins/src/local/mod.rs:20-47` | **Partial**: Per-zone enable/disable controls remain deferred on `conf/plugins-synth` (#102) with the full reverse-zone catalogue. | No |
| §3 Changes to Iterative Resolver Behaviour | `crates/pharos-plugins/src/local/mod.rs:175` | **Deviation**: Local apex NS targets use resolvable `localhost.` rather than the zone apex; the local README records this choice (conf/plugins-synth #102). | Yes |
| §3 Changes to Iterative Resolver Behaviour | `crates/pharos-plugins/src/local/mod.rs:16-18` | **Fixed**: Local SOA RNAME is `nobody.invalid.`. Fixed on `conf/plugins-synth` (#102). | No |
| §3 Changes to Iterative Resolver Behaviour | `crates/pharos-plugins/src/local/mod.rs:27-43` | **Partial**: Operator-configurable NS/SOA values remain deferred on `conf/plugins-synth` (#102) with per-zone controls. | No |
| §4.1 RFC 1918 Zones | — | **Missing**: RFC 1918 reverse zones are part of the broader local reverse-zone catalogue deferred on `conf/plugins-synth` (#102). | No |
| §4.2 RFC 5735 and RFC 5737 Zones | `crates/pharos-plugins/src/local/mod.rs:78-90` | **Partial**: It serves `0.IN-ADDR.ARPA` and `127.IN-ADDR.ARPA`, but omits `254.169.IN-ADDR.ARPA`, TEST-NET-1/2/3, and the listed `255.255.255.255.IN-ADDR.ARPA`; the `255` match instead selects `255.IN-ADDR.ARPA`. | Yes |
| §4.3 Local IPv6 Unicast Addresses | — | **Missing**: IPv6 unspecified and loopback reverse zones remain deferred with the full reverse-zone catalogue on `conf/plugins-synth` (#102). | No |
| §4.4 IPv6 Locally Assigned Local Addresses | — | **Missing**: `D.F.IP6.ARPA` remains deferred with the full reverse-zone catalogue on `conf/plugins-synth` (#102). | No |
| §4.5 IPv6 Link-Local Addresses | — | **Missing**: IPv6 link-local reverse zones remain deferred with the full reverse-zone catalogue on `conf/plugins-synth` (#102). | No |
| §4.6 IPv6 Example Prefix | — | **Missing**: The IPv6 example prefix remains deferred with the full reverse-zone catalogue on `conf/plugins-synth` (#102). | No |

## RFC 6604: xNAME RCODE and Status Bits Clarification

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.1 The Authoritative Answer Bit | `crates/pharos-plugins/src/header/mod.rs:61-72,84-90`, `crates/pharos-plugins/tests/functional/header.rs:22,66` | **Deviation**: `header response set aa` or `clear aa` overrides AA without checking authority for the first answer owner, retaining CoreDNS v1.15.0 behavior. The choice is recorded in `docs/compatibility.md` (RFC 1035 §4.1.1). | Yes |
| §3 RCODE Clarification | `crates/pharos-plugins/src/zone/mod.rs:676-683`, `crates/pharos-plugins/src/template/mod.rs:671-700`, `crates/pharos-plugins/src/rewrite/mod.rs:1582-1588,1619-1625`, `crates/pharos-plugins/src/kubernetes/mod.rs:817-829,850-863,1098-1115`, `crates/pharos-plugins/src/k8s_external/mod.rs:198-205,795-808,497-528` | **Partial**: Zone DNAME and Kubernetes/k8s_external target chasing use final-cycle RCODEs (conf/zone #95; conf/k8s #103). Rewrite/template RCODE chasing remains deferred on `conf/plugins-synth` (#102) as broader cross-cutting behavior. The compatibility note records the chased A/AAAA behavior. | Yes |

## RFC 6605: Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4 DNSKEY and RRSIG Resource Records for ECDSA | `crates/pharos-dnssec/src/keys.rs:150-160`, `crates/pharos-dnssec/src/sign.rs:56-68,107-121`, `crates/pharos-plugins/src/sign/signer.rs:198-221` | **Partial**: Pharos signs with both ECDSA algorithms and emits fixed-width `r\|\|s`, but has no production ECDSA signature-verification path. Verification appears only in tests and the `xtask` dev checker (`xtask/src/dnssec.rs`, P-256 only); RFC requires implementations that create DNS records to implement both signing and verification for both algorithms. | No |

## RFC 6672: DNAME Redirection in the DNS

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.1 Format | `crates/pharos-plugins/src/zone/mod.rs:163-164,545-550` | **Fixed**: Zone construction requires a nonempty DNAME target. Fixed on `conf/zone` (#95). | No |
| §2.2 The DNAME Substitution | `crates/pharos-plugins/src/zone/mod.rs:554-555` | **Fixed**: Overlong substitution returns YXDOMAIN. Fixed on `conf/zone` (#95). | No |
| §2.2 The DNAME Substitution | `crates/pharos-plugins/src/zone/mod.rs:554-555,727-748` | **Fixed**: YXDOMAIN responses retain the DNAME and its RRSIG when signed, without Self Lookup. Fixed on `conf/zone` (#95). | No |
| §2.3 DNAME Owner Name Matching the QNAME | `crates/pharos-plugins/src/zone/mod.rs:664-666,802-810`, `crates/pharos-plugins/src/any/mod.rs:15-47` | **Partial**: Ordinary QTYPEs at the DNAME owner are answered from that owner. The Zone lookup treats ANY as a literal RR type and returns no owner RRset unless the separately configured `any` plugin supplies the RFC 8482 HINFO response. | No |
| §2.3 DNAME Owner Name Matching the QNAME | `crates/pharos-plugins/src/zone/mod.rs:166-188` | **Fixed**: Non-apex DNAME/NS coexistence is rejected. Fixed on `conf/zone` (#95). | No |
| §2.3 DNAME Owner Name Matching the QNAME | `crates/pharos-plugins/src/zone/mod.rs:189-191` | **Partial**: Requiring apex NS when the apex owns a DNAME remains deferred on `conf/zone` (#95), because apex NS enforcement needs unowned Auto fixture updates. | No |
| §2.4 Names next to and below a DNAME Record | `crates/pharos-plugins/src/zone/mod.rs:135-188` | **Fixed**: Zone loading enforces a singleton DNAME RRset. Dynamic-update replacement is fixed on `conf/dynupdate` (#96); static validation on `conf/zone` (#95). | No |
| §2.4 Names next to and below a DNAME Record | `crates/pharos-plugins/src/zone/mod.rs:135-188` | **Fixed**: Zone construction rejects CNAME/DNAME coexistence. Fixed on `conf/zone` (#95). | No |
| §2.4 Names next to and below a DNAME Record | `crates/pharos-plugins/src/zone/mod.rs:75-120,135-188` | **Fixed**: Zone loading rejects DNAME singleton/coexistence violations and DNAME descendants. Fixed on `conf/zone` (#95). | No |
| §2.4 Names next to and below a DNAME Record | `crates/pharos-plugins/src/zone/mod.rs:75-120` | **Partial**: Ancestor-zone DNAME checks remain deferred on `conf/zone` (#95) because they need cross-zone state. | No |
| §3.2 Server Algorithm | `crates/pharos-plugins/src/zone/mod.rs:554-556` | **Fixed**: Overlong substitution returns YXDOMAIN with the DNAME in Answer. Fixed on `conf/zone` (#95). | No |
| §3.2 Server Algorithm | `crates/pharos-plugins/src/zone/mod.rs:678-683` | **Fixed**: Final-cycle YXDOMAIN is preserved; overlong substitution does not trigger Self Lookup. Fixed on `conf/zone` (#95). | No |
| §3.2 Server Algorithm | `crates/pharos-plugins/src/cache/mod.rs:178-213`, `crates/pharos-plugins/src/cache/store.rs:157-161` | **Missing**: Cache lookup requires an exact QNAME, QTYPE, and QCLASS match. It does not search for a cached DNAME at an ancestor when QNAME is absent. | No |
| §3.4 Acceptance and Intermediate Storage | `crates/pharos-plugins/src/cache/store.rs:139-161`, `crates/pharos-plugins/src/cache/store.rs:189-203` | **Missing**: Cache hits still do not synthesize a CNAME for an ancestor DNAME. Deferred on `conf/cache` (#97) because it needs a DNAME substitution path. | No |
| §3.4 Acceptance and Intermediate Storage | `crates/pharos-plugins/src/cache/mod.rs:625-652`, `crates/pharos-plugins/src/cache/store.rs:94-101` | **Partial**: Cache still does not track DNAME validation status. Deferred on `conf/cache` (#97) because DNAME validation needs new cache metadata. | No |
| §5.2 Dynamic Update and DNAME | `crates/pharos-plugins/src/zone/update.rs:136-151`, `crates/pharos-plugins/src/zone/mod.rs:323-324` | **Fixed**: Dynamic UPDATE replaces an existing DNAME at the owner. Fixed on `conf/dynupdate` (#96). | No |
| §5.3.1 Signed DNAME, Unsigned Synthesized CNAME | `crates/pharos-plugins/src/dnssec/signing.rs:234-259`, `crates/pharos-plugins/tests/functional/dnssec_extra.rs:254-261` | **Fixed**: Synthesized CNAMEs are unsigned; real CNAMEs remain signed. Fixed on `conf/dnssec` (#100). | No |

## RFC 6698: The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4 Moving DLV to Historic Status | `crates/pharos-proto/src/codes.rs:186`, `crates/pharos-proto/src/zone/rdata/legacy.rs:187-196` | **Deviation**: DLV remains recognized and accepted in zone files for CoreDNS v1.15.0 / miekg/dns v1.1.73 interoperability; `docs/compatibility.md` records this (conf/proto #99). The final reports do not state DLV Dynamic UPDATE behavior. | Yes |

## RFC 6742: DNS Resource Records for the Identifier-Locator Network Protocol (ILNP)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.1.2 NID RR Presentation Format | `crates/pharos-proto/src/zone/rdata/legacy.rs:126-133` | **Fixed**: NID requires four correctly delimited four-digit hexadecimal groups. Fixed on `conf/proto` (#99). | No |
| §2.2.1 L32 RDATA Wire Format | `crates/pharos-proto/src/zone/rdata.rs:88-100`, `crates/pharos-proto/src/zone/rdata.rs:444-476` | **Partial**: Generic L32 wire-layout validation remains deferred on `conf/proto` (#99) as typed ILNP RDATA support. | No |
| §2.2.2 L32 RR Presentation Format | `crates/pharos-proto/src/zone/rdata/legacy.rs:142-146` | **Fixed**: L32 accepts IPv4 literals only. Fixed on `conf/proto` (#99). | No |
| §2.3.1 The L64 RDATA Wire Format | `crates/pharos-proto/src/zone/rdata/legacy.rs:121-136`, `crates/pharos-proto/src/rdata.rs:963-965` | **Partial**: Typed L64 wire-layout validation remains deferred on `conf/proto` (#99) because it needs typed RDATA support. | No |
| §2.3.1.1 The Preference Field | `crates/pharos-proto/src/zone/rdata/legacy.rs:121-136`, `crates/pharos-proto/src/rdata.rs:963-965`, `crates/pharos-proto/src/rdata.rs:1260-1296` | **Partial**: Typed L64 field layout remains deferred on `conf/proto` (#99) as part of ILNP wire-format support. | No |
| §2.3.1.2 The Locator64 Field | `crates/pharos-proto/src/zone/rdata/legacy.rs:121-136`, `crates/pharos-proto/src/rdata.rs:963-965`, `crates/pharos-proto/src/rdata.rs:1260-1296` | **Partial**: Typed L64 field layout remains deferred on `conf/proto` (#99) as part of ILNP wire-format support. | No |
| §2.3.2 L64 RR Presentation Format | `crates/pharos-proto/src/zone/rdata/legacy.rs:125-136` | **Fixed**: L64 presentation requires four correctly delimited four-digit hexadecimal groups. Fixed on `conf/proto` (#99). | No |
| §2.4.1.2 The FQDN Field | `crates/pharos-proto/src/zone.rs:543-550` | **Fixed**: Zone parsing rejects LP records whose target equals the owner. Fixed on `conf/proto` (#99). | No |
| §2.4.1.2 The FQDN Field | `crates/pharos-proto/src/builder.rs:208-227`, `crates/pharos-proto/src/zone/rdata.rs:31-39`, `crates/pharos-plugins/src/dynupdate/mod.rs:250-280` | **Partial**: Zone-file parsing and dynamic-update normalization produce uncompressed names, but the public raw-RDATA builder can transmit caller-supplied compressed LP names. | No |

## RFC 6761: Special-Use Domain Names

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §6.1 Domain Name Reservation Considerations for Private Addresses — authoritative DNS servers: immediate negative responses | `crates/pharos-plugins/src/file/mod.rs:369-385`, `crates/pharos-plugins/src/zone/mod.rs:514-519,684-688` | **Partial**: A configured authoritative zone returns NXDOMAIN for absent names, but names outside configured zones fall through or return REFUSED instead of receiving the required immediate negative response. | No |
| §6.1 Domain Name Reservation Considerations for Private Addresses — authoritative DNS servers: special recognition | `crates/pharos-plugins/src/file/mod.rs:369-385` | **Violation**: The file plugin selects only configured zones and has no special-name recognition for private-address reverse-mapping domains. | No |
| §6.1 Domain Name Reservation Considerations for Private Addresses — caching DNS servers: avoid upstream queries by default | `crates/pharos-plugins/src/cache/mod.rs:295-306`, `crates/pharos-plugins/src/forward/mod.rs:222-235` | **Violation**: Cache misses continue down the chain, and a matching `forward .` stanza forwards these names upstream. | No |
| §6.1 Domain Name Reservation Considerations for Private Addresses — caching DNS servers: immediate responses | `crates/pharos-plugins/src/cache/mod.rs:295-306` | **Violation**: Cache misses do not generate immediate positive or negative responses for these names; they delegate to the next plugin. | No |
| §6.1 Domain Name Reservation Considerations for Private Addresses — caching DNS servers: special recognition | `crates/pharos-plugins/src/cache/mod.rs:153-169` | **Violation**: Cache eligibility checks query shape and configured zones, but never recognizes private-address reverse-mapping names as special. | No |
| §6.2 Domain Name Reservation Considerations for "test." — authoritative DNS servers: immediate negative responses | `crates/pharos-plugins/src/file/mod.rs:369-385`, `crates/pharos-plugins/src/zone/mod.rs:514-519,684-688` | **Partial**: A configured authoritative zone returns NXDOMAIN for absent names, but names outside configured zones fall through or return REFUSED instead of receiving the required immediate negative response. | No |
| §6.2 Domain Name Reservation Considerations for "test." — authoritative DNS servers: special recognition | `crates/pharos-plugins/src/file/mod.rs:369-385` | **Violation**: The file plugin selects only configured zones and has no special-name recognition for `test.` or its subdomains. | No |
| §6.2 Domain Name Reservation Considerations for "test." — caching DNS servers: avoid upstream queries by default | `crates/pharos-plugins/src/cache/mod.rs:295-306`, `crates/pharos-plugins/src/forward/mod.rs:222-235` | **Violation**: Cache misses continue down the chain, and a matching `forward .` stanza forwards these names upstream. | No |
| §6.2 Domain Name Reservation Considerations for "test." — caching DNS servers: immediate negative responses | `crates/pharos-plugins/src/cache/mod.rs:295-306` | **Violation**: Cache misses do not generate immediate negative responses for these names; they delegate to the next plugin. | No |
| §6.2 Domain Name Reservation Considerations for "test." — caching DNS servers: special recognition | `crates/pharos-plugins/src/cache/mod.rs:153-169` | **Violation**: Cache eligibility checks query shape and configured zones, but never recognizes `test.` or its subdomains as special. | No |
| §6.3 Domain Name Reservation Considerations for "localhost." — 4. Caching DNS Servers | `crates/pharos-plugins/src/local/mod.rs:55-60, 75-77, 120-133`, `crates/pharos-plugins/tests/allocations/local_allocations.rs:25-52` | **Partial**: The optional `local` plugin answers A/AAAA with loopback and other types negatively for recognized localhost names. At the `localhost.` apex, NS and SOA queries instead receive positive answers, contrary to the required negative response. | Yes |
| §6.3 Domain Name Reservation Considerations for "localhost." — 5. Authoritative DNS Servers | `crates/pharos-plugins/src/local/mod.rs:55-60, 75-77, 120-133` | **Partial**: The optional `local` plugin provides the prescribed behavior for most queries, but serves positive NS and SOA answers at the `localhost.` apex instead of negative responses for all non-address types. | Yes |
| §6.3 Domain Name Reservation Considerations for "localhost." — 6. DNS Server Operators | — | **Missing**: Operator documentation does not state that the effective RDATA for localhost names is defined by protocol and cannot be modified by local configuration; the `local` RDATA is fixed constants (`local/mod.rs:17-18`), but no operator-facing text records it. | No |
| §6.4 Domain Name Reservation Considerations for "invalid." — 4. Caching DNS Servers | `crates/pharos-plugins/src/forward/mod.rs:229-234, crates/pharos-plugins/src/cache/mod.rs:153-170` | **Violation**: No special handling blocks `.invalid` queries; a matching forward stanza sends them upstream, and the cache has no `.invalid` exclusion. | No |
| §6.4 Domain Name Reservation Considerations for "invalid." — 5. Authoritative DNS Servers | `crates/pharos-plugins/src/file/mod.rs:369-385` | **Violation**: The authoritative file plugin serves configured `.invalid` zones as ordinary zones and has no rule to return immediate negative responses. | No |
| §6.4 Domain Name Reservation Considerations for "invalid." — 6. DNS Server Operators | — | **Missing**: Operator documentation does not state that `.invalid` names are protocol-defined nonexistent and cannot be overridden by local configuration. | No |
| §6.5 Domain Name Reservation Considerations for Example Domains — 6. DNS Server Operators | — | **Missing**: Operator documentation does not state that example names are reserved for documentation. | No |

## RFC 6781: DNSSEC Operational Practices, Version 2

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.1 Operational Motivation for Zone Signing Keys and Key Signing Keys | `crates/pharos-plugins/src/dnssec/signing.rs:337-359` | **Partial**: With both key types configured, signer chooses KSK solely by RR type, so KSK can sign non-apex DNSKEY RRsets; RFC 6781 §3.1 limits KSK signing to the apex DNSKEY RRset. Existing comment cites RFC 4034 §2.1.1, not this operational rule. | No |
| §3.4.1 Signature Algorithm | `crates/pharos-dnssec/src/keys.rs:67-75` | **Deviation**: RFC 6781 recommends RSA/SHA-1 as an alternative, but Pharos rejects algorithms 5 and 7. The DNSSEC plugin README documents the rejection because RFC 9905 §2 prohibits these algorithms for signing. | Yes |
| §4.1 Key Rollovers | `crates/pharos-plugins/src/sign/signer.rs:52-57,87-118,198-224` | **Partial**: The signer replaces DNSKEY/RRSIG input and regenerates records only from the configured keys. It has no rollover stages or cache-window tracking, so changing keys can remove material needed to validate cached data. | No |
| §4.1.1 Zone Signing Key Rollovers | `crates/pharos-plugins/src/dnssec/signing.rs:337-359` | **Partial**: The online signer separates KSK and ZSK signatures, but does not stage ZSK rollover or retain old keys for the cache interval; configured keys determine the current DNSKEY and signatures. | No |
| §4.1.1.1 Pre-Publish Zone Signing Key Rollover | `crates/pharos-plugins/src/dnssec/setup.rs:43-70`, `crates/pharos-plugins/src/dnssec/mod.rs:113-129`, `crates/pharos-plugins/src/dnssec/signing.rs:350-365` | **Partial**: Every configured key has a private signer, appears in the DNSKEY answer, and signs eligible RRsets immediately. The implementation cannot publish a future ZSK without using it to sign data. | No |
| §4.1.2 Key Signing Key Rollovers | `crates/pharos-plugins/src/dnssec/mod.rs:99-129`, `crates/pharos-plugins/src/dnssec/signing.rs:350-365` | **Partial**: Multiple KSKs can be published and can sign the DNSKEY RRset together. The signer does not coordinate parent DS changes or preserve the old KSK through the TTL_DNSKEY and TTL_DS waits required by Verified erratum 4844. | No |
| §4.1.2.1 Special Considerations for RFC 5011 KSK Rollover | `crates/pharos-plugins/src/dnssec/signing.rs:337-365` | **Partial**: A revoked KSK remains eligible to sign the DNSKEY RRset, but the implementation does not enforce the additional Maximum Zone TTL publication period before removal. | No |
| §4.1.3 Single-Type Signing Scheme Key Rollover | `crates/pharos-plugins/src/dnssec/signing.rs:337-365` | **Partial**: A single configured key can sign both DNSKEY and other RRsets, and multiple keys can overlap. The implementation does not stage the DS change or wait for old DNSKEY/DS data to expire before removing a key. | No |
| §4.1.4 Algorithm Rollovers | `crates/pharos-plugins/src/dnssec/mod.rs:113-129`, `crates/pharos-plugins/src/dnssec/signing.rs:350-409` | **Partial**: Configuring a new algorithm publishes its DNSKEY and signatures together. The signer cannot first publish new-algorithm signatures, wait for old signed data to expire, then publish the DNSKEY and coordinate the parent DS transition. | No |
| §4.1.4.1 Single-Type Signing Scheme Algorithm Rollover | `crates/pharos-plugins/src/dnssec/mod.rs:113-129`, `crates/pharos-plugins/src/dnssec/signing.rs:350-409` | **Partial**: The signer can use multiple algorithms, but publishes each configured DNSKEY and its signatures together. It cannot perform the required signatures-first cache transition for a single-type key. | No |
| §4.1.4.2 Algorithm Rollover, RFC 5011 Style | `crates/pharos-plugins/src/dnssec/signing.rs:337-365` | **Partial**: A revoked key can sign the DNSKEY RRset, but no rollover state ensures the new trust anchor is established before revocation or retains the revoked key for the RFC 5011 period. | No |
| §4.1.4.3 Single Signing Type Algorithm Rollover, RFC 5011 Style | `crates/pharos-plugins/src/dnssec/signing.rs:337-365` | **Partial**: Configured ZSKs can sign zone RRsets while KSKs sign DNSKEY, allowing a shadow-key arrangement. The implementation does not enforce a same-algorithm shadow key or stage its introduction and removal around revocation. | No |
| §4.4.1 Time Considerations — Maximum Zone TTL | `crates/pharos-plugins/src/sign/signer.rs:172-183` | **Partial**: The signer sets a 32-day validity period plus up to five days of jitter and preserves source TTLs. It does not ensure the Maximum Zone TTL is shorter than the signature validity period. | No |
| §4.4.1 Time Considerations — Minimum Zone TTL | `crates/pharos-plugins/src/sign/signer.rs:73-85`, `crates/pharos-plugins/src/sign/signer.rs:149-155`, `crates/pharos-plugins/src/sign/signer.rs:179-183` | **Partial**: The signer accepts zone TTLs and uses them for signed RRsets without checking that the Minimum Zone TTL supports fetching and validating the complete trust chain. | No |
| §4.4.1 Time Considerations — SOA expiration timing | `crates/pharos-plugins/src/secondary/update.rs:244-265` | **Partial**: SOA refresh, retry, and expire values are used as supplied. The implementation does not relate SOA expiration to the refresh period or signature validity period. | No |
| §4.4.1 Time Considerations — Secondary refresh before signature expiration | `crates/pharos-plugins/src/secondary/update.rs:244-265`, `crates/pharos-plugins/src/secondary/update.rs:316-357`, `crates/pharos-plugins/src/secondary/mod.rs:198-204` | **Partial**: The secondary refreshes on the SOA timer and stops serving only after SOA expiration following failed refreshes. It does not compare refresh or expiry timing with RRSIG expiration, so it can serve expired signatures while the SOA expiry timer remains active. | No |
| §4.4.1 Time Considerations — Signature publication period | `crates/pharos-plugins/src/sign/output.rs:13-46`, `crates/pharos-plugins/src/sign/mod.rs:91-100` | **Partial**: The signer checks every five hours and re-signs when a signature has less than seven days remaining. It does not compare this lead time with Maximum Zone TTL, so publication can end less than one TTL before expiration. | No |
| §4.4.1 Time Considerations — Upcoming signature expiration monitoring | `—` | **Missing**: The secondary has no monitor or alert for upcoming RRSIG expiration; its refresh loop checks SOA serials only. | No |

## RFC 6840: Clarifications and Implementation Notes for DNS Security (DNSSEC)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §5.6 Setting the DO Bit on Replies | `crates/pharos-server/src/outcome.rs:268-285` | **Fixed**: Response DO follows the Query DO bit. Fixed on `conf/server` (#101). | No |
| §5.11 Mandatory Algorithm Rules | `crates/pharos-plugins/src/dnssec/signing.rs:337-359,365-412` | **Fixed**: Each DNSKEY algorithm signs every RRset it is required to sign. Fixed on `conf/dnssec` (#100). | No |

## RFC 6891: Extension Mechanisms for DNS (EDNS(0))

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §6.1.1 Basic Elements | `crates/pharos-proto/src/message.rs:203-247`, `crates/pharos-server/src/admission.rs:45-47,68-75`, `crates/pharos-server/src/outcome.rs:219-223` | **Fixed**: Parseable EDNS errors include an OPT in FORMERR/NOTIMP responses; malformed OPT framing receives the specified fallback. Fixed on `conf/server` (#101). | No |
| §6.1.1 Basic Elements | `crates/pharos-proto/src/zone.rs:447-550`, `crates/pharos-proto/src/zone/rdata.rs:88-100,409-455` | **Fixed**: OPT is rejected as zone data. Fixed on `conf/proto` (#99). | No |
| §6.1.1 Basic Elements | `crates/pharos-proto/src/message.rs:224-235`, `crates/pharos-proto/src/tsig.rs:586-638`, `crates/pharos-plugins/src/forward/mod.rs:253-265` | **Fixed**: SIG(0) and TSIG must be the final Additional RR; OPT may precede them. Fixed on `conf/server` (#101). | No |
| §6.1.1 Basic Elements | `crates/pharos-proto/src/builder.rs:210-269,275-292,386-404` | **Fixed**: MessageBuilder rejects duplicate OPT records. Fixed on `conf/server` (#101). | No |
| §6.1.4 Flags | `crates/pharos-proto/src/edns.rs:152-156`, `crates/pharos-server/src/outcome.rs:268-285` | **Fixed**: Reserved EDNS flags are cleared in generated Responses. Fixed on `conf/server` (#101). | No |
| §6.1.4 Flags | `crates/pharos-plugins/src/nsid/mod.rs:114-117`, `crates/pharos-server/src/outcome.rs:282-285` | **Fixed**: Response DO bit follows the Query. Fixed on `conf/server` (#101). | No |
| §7 Transport Considerations | `crates/pharos-server/src/admission.rs:45-47,68-75`, `crates/pharos-proto/src/message.rs:224-232` | **Fixed**: Parseable EDNS errors include an OPT in FORMERR responses. Fixed on `conf/server` (#101). | No |
| §7 Transport Considerations | `crates/pharos-server/src/admission.rs:34-36,68-75` | **Fixed**: Unsupported-opcode NOTIMP responses include permitted Question and OPT data. Fixed on `conf/server` (#101). | No |

## RFC 6895: Domain Name System (DNS) IANA Considerations

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 DNS Query/Response Headers | `crates/pharos-server/src/admission.rs:68-74,77-86` | **Fixed**: Error Responses copy only permitted header flags; reserved Z is ignored on receipt and cleared on output. Fixed on `conf/server` (#101). | No |
| §2.3 RCODE Assignment | `crates/pharos-proto/src/codes.rs:62,73-75` | **Partial**: Context-free `Display` still labels RCODE 16 as BADSIG; this remains deferred in unowned `pharos-proto/src/codes.rs` (`conf/server` #101). | No |
| §2.3 RCODE Assignment | `crates/pharos-server/src/metrics.rs:1846-1861` | **Fixed**: Metrics label RCODE 16 as BADVERS; BADSIG remains a TSIG error, not a DNS RCODE label. Fixed on `conf/server` (#101). | No |
| §3 DNS Resource Records | `crates/pharos-plugins/src/cache/mod.rs:618-627` | **Deviation**: The cache raises a record TTL of zero to its configured minimum before checking eligibility; the default minimum is 5 seconds, so it caches and serves data beyond the transaction. The cache README documents this CoreDNS-compatible behavior. | Yes |
| §3 DNS Resource Records | `crates/pharos-proto/src/zone.rs:870-895` | **Fixed**: TTL parser rejects values above 2,147,483,647. Fixed on `conf/proto` (#99). | No |
| §3.1 RRTYPE IANA Considerations | `crates/pharos-dnssec/src/denial.rs:42-50` | **Fixed**: Type 128 is generated only as RFC 9824 NXNAME signaling in compact denial, not as zone data. Fixed on `conf/dnssec` (#100). | No |
| §3.1 RRTYPE IANA Considerations | `crates/pharos-proto/src/zone.rs:453-462,912-921` | **Fixed**: Query-only and meta types are rejected from zone data. Fixed on `conf/proto` (#99). | No |
| §3.2 RR CLASS IANA Considerations | `crates/pharos-plugins/src/zone/mod.rs:70-71,277-286,613-666` | **Fixed**: Mixed-class zones are rejected and lookup falls through on a mismatched QCLASS. Fixed on `conf/zone` (#95). | No |
| §3.2 RR CLASS IANA Considerations | `crates/pharos-plugins/src/whoami/mod.rs:25-30,71-95` | **Fixed**: `whoami` uses IN class for generated records. Fixed on `conf/plugins-synth` (#102). | No |
| §3.2 RR CLASS IANA Considerations | `crates/pharos-proto/src/zone.rs:898-909` | **Fixed**: Invalid zone RR classes, including NONE, are rejected. Fixed on `conf/proto` (#99). | No |
| §3.3.2 Label Contents and Use | `crates/pharos-plugins/src/zone/mod.rs:70-71,277-286,613-666` | **Fixed**: Mixed-class zones are rejected and query lookup falls through on a class mismatch. Fixed on `conf/zone` (#95). | No |

## RFC 7043: Resource Records for EUI-48 and EUI-64 Addresses in the DNS

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.1 EUI48 RDATA Wire Format | `crates/pharos-proto/src/rdata.rs:964-965,1296`, `crates/pharos-proto/src/zone/rdata/legacy.rs:109-118`, `crates/pharos-proto/src/zone/rdata.rs:462-467` | **Fixed**: EUI-48 wire RDATA requires exactly six octets. Fixed on `conf/proto` (#99). | No |
| §4.1 EUI64 RDATA Wire Format | `crates/pharos-proto/src/rdata.rs:963-965`, `crates/pharos-proto/src/zone/rdata.rs:462-467` | **Fixed**: EUI-64 wire RDATA requires exactly eight octets. Fixed on `conf/proto` (#99). | No |

## RFC 7208: Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.1 DNS Resource Records | `crates/pharos-proto/src/zone/rdata.rs:154-165`, `crates/pharos-proto/tests/zone_rdata.rs:208` | **Deviation**: SPF (TYPE99) remains accepted in zone files. CoreDNS v1.15.0 with miekg/dns v1.1.73 loads the sample zone and answers TYPE99 queries; recorded in `docs/compatibility.md` (conf/proto #99). | Yes |
| §14.1 The SPF DNS Record Type | `crates/pharos-proto/src/zone/rdata.rs:154-165`, `crates/pharos-proto/src/zone.rs:484`, `crates/pharos-plugins/src/dynupdate/setup.rs:131` | **Deviation**: SPF zone records remain accepted for CoreDNS v1.15.0 / miekg/dns v1.1.73 compatibility; dynamic UPDATE rejects SPF (conf/dynupdate #96). Recorded in `docs/compatibility.md` (conf/proto #99). | Yes |

## RFC 7344: Automating DNSSEC Delegation Trust Maintenance

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4.1 CDS and CDNSKEY Processing Rules | `crates/pharos-plugins/src/sign/setup.rs:71-90`, `crates/pharos-plugins/src/sign/signer.rs:97-107` | **Deviation**: With multiple origins, generated CDS/CDNSKEY records use the last origin rather than each child-zone apex, contrary to the apex-location rule. The sign README documents this CoreDNS-compatible ownership and advises one directive per origin. | Yes |
| §5 CDS/CDNSKEY Publication | `crates/pharos-plugins/src/sign/setup.rs:56-61`, `crates/pharos-plugins/src/sign/signer.rs:97-110` | **Partial**: The signer checks that configured keys are KSKs and publishes CDS/CDNSKEY derived from them, but does not establish that a generated key is present in the Parent's current DS RRset or that replacing DS preserves the delegation. A mismatched key configuration can publish records that break the chain of trust. | No |

## RFC 7468: Textual Encodings of PKIX, PKCS, and CMS Structures

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 General Considerations | `crates/pharos-dnssec/src/keys.rs:192-194` | **Partial**: The parser ignores whitespace and accepts different newline conventions, but `STANDARD.decode` rejects other non-base64 characters instead of ignoring them as SHOULD. PEM parsing is deferred on `conf/infra` (#105) because it belongs to the DNSSEC package. | No |
| §2 General Considerations | `crates/pharos-dnssec/src/keys.rs:184-186` | **Partial**: Leading text before PEM encapsulation boundaries is rejected; full PEM parsing was deferred on `conf/infra` (#105) because this path belongs to the DNSSEC package. | No |

## RFC 7477: Child-to-Parent Synchronization in DNS

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.1.1.2 Flags Field | `crates/pharos-proto/src/zone/rdata/advanced.rs:139`, `crates/pharos-proto/src/zone/rdata.rs:440` | **Fixed**: CSYNC accepts only IMMEDIATE and SOAMINIMUM flag bits. Fixed on `conf/proto` (#99). | No |
| §2.1.1.2.1 Type Bit Map Field | `crates/pharos-proto/src/zone/rdata/advanced.rs:140-143`, `crates/pharos-proto/src/zone/rdata.rs:511,1004-1025` | **Fixed**: CSYNC requires a nonempty ordered type bitmap. Fixed on `conf/proto` (#99). | No |

## RFC 7553: The Uniform Resource Identifier (URI) DNS Resource Record

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4.4 Target | `crates/pharos-proto/src/zone/rdata.rs:228-233`, `crates/pharos-proto/src/rdata.rs:751-757,1055-1063`, `crates/pharos-plugins/src/sign/output.rs:94-101` | **Violation**: Zone parsing unescapes any Target field, including `""`, and wire parsing takes `bytes[4..]` without a length check, so both accept an empty Target contrary to the MUST NOT. No ADR or plugin README justifies it. Existing citations name §4 and §4.5, not §4.4. | No |
| §4.5 URI RDATA Wire Format | `crates/pharos-proto/src/rdata.rs:750-757,1055-1063`, `crates/pharos-plugins/src/sign/output.rs:94-101` | **Violation**: The MUST that the Target length be greater than zero is unenforced: wire parsing and both writers accept a zero-length Target. Priority and Weight are network byte order (conformant). The citation at rdata.rs:750 names §4.5 but does not state the length rule. | Yes |

## RFC 7757: Explicit Address Mappings for Stateless IP/ICMP Translation

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.1 Explicit Address Mapping Table | `crates/pharos-plugins/src/siit/mod.rs:19-24,62-78,102-126` | **Partial**: The plugin stores exact IPv4/IPv6 address pairs, but cannot represent prefix mappings in the EAMT. | No |
| §3.2 Explicit Address Mapping Specification | `crates/pharos-plugins/src/siit/mod.rs:62-77` | **Partial**: The parser accepts only individual IPv4 and IPv6 addresses, not prefixes. Legal prefix EAMs and their prefix lengths cannot be configured. | No |
| §3.3 IP Address Translation Procedure | `crates/pharos-plugins/src/siit/mod.rs:102-126` | **Partial**: Translation supports exact EAM addresses and RFC 6052 prefix decoding, not the full prefix-based EAM procedure. | No |
| §3.3.2 Address Translation Steps: IPv6 to IPv4 | `crates/pharos-plugins/src/siit/mod.rs:108-110` | **Partial**: RFC requires longest-prefix matching; code checks exact IPv6 address equality. The citation names this section but documents precedence, not the missing prefix support. | Yes |

## RFC 7766: DNS Transport over TCP - Implementation Requirements

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4 Discussion — TC retry | `crates/pharos-plugins/src/proxy/mod.rs:407-424`, `crates/pharos-plugins/src/forward/README.md:9` | **Deviation**: The forwarder retries a truncated UDP response over TCP only when `prefer_udp` is set; otherwise it returns the truncated response. The README records this CoreDNS-compatible behavior. | Yes |
| §5 Transport Protocol Selection | `crates/pharos-plugins/src/forward/resolve.rs:56-84` | **Fixed**: Configured resolver lookups retry truncated UDP responses over TCP. Fixed on `conf/forward` (#104). | No |
| §5 Transport Protocol Selection | `crates/pharos-server/src/lib.rs:826-829, 902-904` | **Partial**: Corefile `multisocket` rejects zero UDP workers; the public Rust API still accepts zero and binds no UDP sockets (conf/server #101 review). | No |
| §6.2.1 Connection Reuse | `crates/pharos-plugins/src/secondary/update.rs:182-200`, `crates/pharos-server/src/transfer.rs:165` | **Partial**: SOA check and AXFR still use separate TCP connections. Reuse was deferred on `conf/secondary` (#98) as an invasive transfer change. | No |
| §6.2.1.1 Query Pipelining | `crates/pharos-plugins/src/proxy/mod.rs:446-462, 491-521, 572-585` | **Partial**: One query is outstanding per leased socket, so regular-query TCP pipelining remains deferred on `conf/forward` (#104) pending a connection-manager change. | No |
| §6.2.2 Concurrent Connections | `crates/pharos-plugins/src/proxy/mod.rs:433-475, 572-585` | **Partial**: The proxy does not limit active regular-query upstream TCP connections; connection-manager limits remain deferred on `conf/forward` (#104). | No |
| §6.2.3 Idle Timeouts | `crates/pharos-plugins/src/proxy/mod.rs:243-272, 396-406`, `crates/pharos-plugins/src/forward/README.md:10` | **Deviation**: The client only sweeps expired idle sockets when another exchange starts. With no later traffic, cached TCP sessions remain open indefinitely; the README documents this behavior. | Yes |
| §6.2.3 Idle Timeouts | `crates/pharos-plugins/src/proxy/mod.rs:243-272, 572-585`, `crates/pharos-plugins/src/forward/README.md:10` | **Deviation**: The client keeps idle TCP sessions without an idle-timeout signaling mechanism, and the configured expiry is not enforced without another exchange; the README documents this behavior. | Yes |
| §6.2.4 Teardown | `crates/pharos-server/src/tcp.rs:186-189, 280-286, 310` | **Violation**: When frame reading ends, the server drains in-flight query tasks. Those tasks still try to write responses, even when the peer closed the session before all responses were sent. | No |
| §8 TCP Message Length Field | `crates/pharos-server/src/transfer.rs:165-173`, `crates/pharos-plugins/src/secondary/update.rs:181-199` | **Partial**: The production transfer clients write the length and Message separately; the shared server helper `write_tcp_frame` uses a vectored write. | No |

## RFC 7828: The edns-tcp-keepalive EDNS0 Option

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.1 Option Format | `crates/pharos-proto/src/zone/rdata.rs:622-623`, `crates/pharos-proto/tests/zone_strictness.rs:131-136` | **Fixed**: Generic OPT RDATA preserves the distinct two-octet TIMEOUT 0 form. Fixed on `conf/proto` (#99). | No |
| §3.2.1 Sending Queries | `crates/pharos-plugins/src/forward/mod.rs:297-301`, `crates/pharos-plugins/src/proxy/mod.rs:407-414, 488-491` | **Partial**: Unsigned Queries strip option 11 on UDP and zero its data on TCP; TSIG-signed Queries remain unchanged to preserve their MAC. The signed path is deferred on `conf/forward` (#104). | No |
| §3.2.1 Sending Queries | `crates/pharos-plugins/src/proxy/mod.rs:488-491` | **Fixed**: TCP Queries send a zero-length TIMEOUT option. Fixed on `conf/forward` (#104). | No |
| §3.2.2 Receiving Responses | `crates/pharos-plugins/src/proxy/mod.rs:501-514, 551-585` | **Partial**: The proxy still does not use the server's TCP response timeout; timeout-aware connection management is deferred on `conf/forward` (#104). | No |
| §3.2.2 Receiving Responses | `crates/pharos-plugins/src/proxy/mod.rs:551-585` | **Fixed**: TIMEOUT=0 closes the TCP socket and prevents reuse. Fixed on `conf/forward` (#104). | No |
| §3.4 TCP Session Management | `crates/pharos-server/src/tcp.rs:20-21, 41` | **Partial**: The listener caps accepted TCP connections at 1,024, but does not establish the limit through configuration or process-limit interrogation. | No |
| §3.5 Non-clean Paths | `crates/pharos-plugins/src/proxy/mod.rs:488-491, 501-523` | **Missing**: The proxy forwards option 11 but has no fallback for an intermediary that blocks or disrupts EDNS options. | No |
| §4 Intermediary Considerations | `crates/pharos-proto/src/edns_options.rs:257-262`, `crates/pharos-server/src/outcome.rs:219-223`, `crates/pharos-server/src/tcp.rs:146-170` | **Partial**: Pharos can parse, copy, or generically emit option 11, but does not integrate it with TCP session timeout management. | No |

## RFC 7871: Client Subnet in DNS Queries

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §5 Overview — ECS only for IN class | `crates/pharos-plugins/src/rewrite/mod.rs:1469-1495` | **Violation**: The subnet rewrite inserts ECS without checking the question class, so it can add ECS to non-IN queries. | No |
| §6 Option Format | `crates/pharos-plugins/src/forward/mod.rs:253-266` | **Fixed**: Outgoing ECS SCOPE is zeroed. Fixed on `conf/forward` (#104). | No |
| §7.1.1 Recursive Resolvers | `crates/pharos-plugins/src/rewrite/mod.rs:1233-1251, 1486-1490` | **Partial**: ECS prefix caps and privacy limits remain deferred on `conf/plugins-synth` (#102) as cross-cutting rewrite behavior. | No |
| §7.1.1 Recursive Resolvers | `crates/pharos-plugins/src/rewrite/mod.rs:261-276, 1486-1490` | **Partial**: Configured ECS prefixes can be full-width; privacy caps remain deferred on `conf/plugins-synth` (#102). | No |
| §7.1.1 Recursive Resolvers | `crates/pharos-plugins/src/rewrite/mod.rs:1486-1490` | **Missing**: REFUSED handling when ECS is not forwarded remains deferred on `conf/plugins-synth` (#102) as part of broader ECS privacy policy. | No |
| §7.1.2 Stub Resolvers | `crates/pharos-plugins/src/rewrite/mod.rs:1233-1251, 1486-1490, 2122-2131` | **Partial**: Rewrite does not cap configured prefixes to an incoming ECS SOURCE; ECS privacy/prefix limits were deferred on `conf/plugins-synth` (#102). | No |
| §7.1.2 Stub Resolvers | `crates/pharos-plugins/src/rewrite/mod.rs:1233-1251, 1486-1490, 2122-2131` | **Partial**: A SOURCE PREFIX-LENGTH of zero is not preserved by the subnet rewrite; deferred on `conf/plugins-synth` (#102) as cross-cutting ECS privacy behavior. | No |
| §7.1.3 Forwarding Resolvers | `crates/pharos-plugins/src/rewrite/mod.rs:1486-1490` | **Partial**: Transparent forwarding is fixed on `conf/forward` (#104); `rewrite edns0 subnet` prefix/privacy limits remain deferred on `conf/plugins-synth` (#102). | No |
| §7.1.3 Forwarding Resolvers | `crates/pharos-plugins/src/forward/mod.rs:334-382` | **Fixed**: Unsigned ECS Queries retry REFUSED without the address and preserve the original REFUSED if retry fails. Fixed on `conf/forward` (#104). | No |
| §7.2.1 Authoritative Nameserver | `crates/pharos-proto/src/edns_options.rs:270-293` | **Partial**: The parser rejects unsupported families, but accepts FAMILY 0 with SOURCE PREFIX-LENGTH 0 and treats its address as IPv4. This undefined family is malformed, yet admission will not return FORMERR. | No |
| §7.2.2 Intermediate Nameserver | `crates/pharos-server/src/outcome.rs:275-287` | **Fixed**: ECS is not echoed to clients whose Query lacked ECS. Fixed on `conf/server` (#101). | No |
| §7.2.2 Intermediate Nameserver | `crates/pharos-server/src/outcome.rs:288-295`, `crates/pharos-proto/src/edns.rs:197-199` | **Fixed**: When upstream omits ECS, the Listener copies the Query's ECS option into the Response OPT. Fixed on `conf/server` (#101). | No |
| §7.3 Handling ECS Responses and Caching | `crates/pharos-plugins/src/cache/mod.rs:625-652`, `crates/pharos-plugins/src/cache/mod.rs:767-779` | **Partial**: The cache stores eligible, non-truncated responses, but its key omits ECS family, source prefix, address, and scope. It therefore does not cache by the ECS option data. | No |
| §7.3 Handling ECS Responses and Caching | `crates/pharos-plugins/src/proxy/mod.rs:415-425` | **Partial**: UDP responses with TC trigger a TCP retry only when `prefer_udp` is enabled; the default UDP forwarding path does not retry. | No |
| §7.3 Handling ECS Responses and Caching | `crates/pharos-plugins/src/proxy/mod.rs:560-568` | **Fixed**: Returned ECS FAMILY, SOURCE, and ADDRESS are validated; longer SCOPE is accepted. Fixed on `conf/forward` (#104). | No |
| §7.3 Handling ECS Responses and Caching | `crates/pharos-plugins/src/forward/mod.rs:380-397` | **Fixed**: REFUSED retries without ECS, subject to the configured per-upstream attempt budget. Fixed on `conf/forward` (#104). | No |
| §7.3.1 Caching the Response | `crates/pharos-plugins/src/cache/mod.rs:767-779`, `crates/pharos-plugins/src/cache/store.rs:301-344` | **Partial**: ECS-bearing queries and responses bypass cache storage, preventing reuse across networks. This safe subset was added on `conf/cache` (#97); scope-aware ECS caching remains deferred there. | No |
| §7.3.1 Caching the Response | `crates/pharos-plugins/src/cache/mod.rs:767-779` | **Missing**: Prefix-aware ECS scope storage remains deferred on `conf/cache` (#97); the current safe subset bypasses ECS-bearing responses. | No |
| §7.3.1 Caching the Response | `crates/pharos-plugins/src/cache/mod.rs:767-779` | **Missing**: ECS-specific cache prefix limits remain deferred on `conf/cache` (#97); ECS responses are bypassed rather than cached. | No |
| §7.3.1 Caching the Response | `crates/pharos-plugins/src/cache/mod.rs:767-779` | **Missing**: Exact-source ECS entries remain deferred on `conf/cache` (#97); ECS responses are bypassed. | No |
| §7.3.1 Caching the Response | `crates/pharos-plugins/src/cache/mod.rs:767-779` | **Missing**: ECS-aware `/0` distinctions remain deferred on `conf/cache` (#97); ECS responses are bypassed. | No |
| §7.3.1 Caching the Response | `crates/pharos-plugins/src/cache/mod.rs:767-779` | **Partial**: Pharos does not implement network-specific ECS caching; it safely bypasses ECS-bearing queries and responses (conf/cache #97). | No |
| §7.3.1 Caching the Response | `crates/pharos-plugins/src/cache/setup.rs:49-55`, `crates/pharos-plugins/src/cache/mod.rs:767-779` | **Partial**: ECS network/answer limits remain deferred on `conf/cache` (#97); ECS-bearing responses are not cached. | No |
| §7.3.2 Answering from Cache | `crates/pharos-plugins/src/cache/mod.rs:178-212`, `crates/pharos-plugins/src/cache/mod.rs:767-779` | **Partial**: Longest-prefix ECS selection remains deferred on `conf/cache` (#97); ECS queries bypass the cache. | No |
| §7.3.2 Answering from Cache | — | **Missing**: Client-address selection among network-scoped entries remains deferred on `conf/cache` (#97); ECS caching is bypassed. | No |
| §7.3.2 Answering from Cache | — | **Missing**: Covering-entry lookup remains deferred on `conf/cache` (#97); ECS caching is bypassed. | No |
| §7.3.2 Answering from Cache | — | **Missing**: Exact source-prefix fallback lookup remains deferred on `conf/cache` (#97); ECS caching is bypassed. | No |
| §7.3.2 Answering from Cache | — | **Missing**: Network-scoped cached responses remain deferred on `conf/cache` (#97); ECS caching is bypassed. | No |
| §7.3.2 Answering from Cache | `crates/pharos-plugins/src/cache/mod.rs:178-212` | **Fixed**: ECS queries no longer use generic cache entries. Fixed on `conf/cache` (#97). | No |
| §7.5 Transitivity | `crates/pharos-plugins/src/forward/mod.rs:253-266`, `crates/pharos-plugins/src/proxy/mod.rs:488-492`, `crates/pharos-plugins/src/cache/mod.rs:651-668`, `crates/pharos-plugins/src/cache/mod.rs:767-780`, `crates/pharos-plugins/src/cache/store.rs:285-344` | **Partial**: `cache` bypasses ECS-bearing queries and responses (conf/cache #97), but prefix-aware ECS caching remains unimplemented. Forwarding sanitization is covered by `conf/forward` (#104). | No |
| §11.1 Privacy — concealing client address | `crates/pharos-plugins/src/rewrite/mod.rs:261-276,1486-1490` | **Partial**: The subnet rewrite permits full-width prefixes and does not enforce privacy limits; ECS privacy/prefix handling was deferred as cross-cutting work on `conf/plugins-synth` (#102). | No |
| §11.1 Privacy — preserving an incoming privacy limit | `crates/pharos-plugins/src/rewrite/mod.rs:1417-1429,1486-1490` | **Violation**: A configured subnet rewrite can disclose more address bits than an incoming SOURCE PREFIX-LENGTH permits. ECS privacy/prefix handling was deferred as cross-cutting work on `conf/plugins-synth` (#102). | No |
| §11.2 Birthday Attacks — discard mismatched response | `crates/pharos-plugins/src/proxy/mod.rs:551-567` | **Fixed**: Responses with mismatched ECS fields are discarded. Fixed on `conf/forward` (#104). | No |
| §11.2 Birthday Attacks — verify ECS response fields | `crates/pharos-plugins/src/proxy/mod.rs:551-567` | **Fixed**: ECS FAMILY, ADDRESS, and SOURCE PREFIX-LENGTH are checked against the query. Fixed on `conf/forward` (#104). | No |
| §11.3 Cache Pollution — do not send beyond cacheable prefix | `crates/pharos-plugins/src/rewrite/mod.rs:261-276,1486-1490; crates/pharos-plugins/src/cache/mod.rs:767-780` | **Partial**: ECS rewrite prefix/privacy limits remain deferred on `conf/plugins-synth` (#102); cache-side prefix-aware controls remain deferred on `conf/cache` (#97). | No |
| §11.3 Cache Pollution — scope cached ECS answers | `crates/pharos-plugins/src/cache/mod.rs:767-780; crates/pharos-plugins/src/cache/store.rs:285-328` | **Partial**: ECS cross-network reuse is prevented by bypass (conf/cache #97); prefix-aware ECS caching remains deferred. | No |

## RFC 7929: DNS-Based Authentication of Named Entities (DANE) Bindings for OpenPGP

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 The OPENPGPKEY Resource Record | `crates/pharos-proto/src/zone/rdata/legacy.rs:174-175`, `crates/pharos-proto/src/zone/rdata.rs:88-100,428-429`, `crates/pharos-proto/src/rdata.rs:963-965` | **Partial**: The zone parser accepts one opaque RDATA blob, but does not check that it contains exactly one OpenPGP key. Generic or wire-format input can include empty, malformed, or concatenated key data. | No |
| §2.1 The OPENPGPKEY RDATA Component | `crates/pharos-proto/src/zone/rdata/legacy.rs:174-175`, `crates/pharos-proto/src/zone/rdata.rs:88-100,428-429`, `crates/pharos-proto/src/rdata.rs:963-965` | **Partial**: OPENPGPKEY RDATA is retained as opaque bytes; Pharos does not validate that it is one RFC 4880 Transferable Public Key. | No |

## RFC 8005: Host Identity Protocol (HIP) Domain Name System (DNS) Extension

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §5.1 HIT Length Format | `crates/pharos-proto/src/zone/rdata/advanced.rs:93` | **Fixed**: HIP HIT length is derived from decoded octets without narrowing overflow. Fixed on `conf/proto` (#99). | No |
| §6 HIP RR Presentation Format | `crates/pharos-proto/src/zone/rdata/advanced.rs:93` | **Fixed**: HIP presentation parsing derives HIT length from decoded octets. Fixed on `conf/proto` (#99). | No |

## RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §8.2.1 Signature Generation Operation | `crates/pharos-dnssec/src/keys.rs:145-147,201-203`, `crates/pharos-dnssec/src/sign.rs:77-80`, `crates/pharos-plugins/src/dnssec/README.md:14` | **Deviation**: aws-lc-rs rejects valid RSA keys below 2048 bits even when the encoded message fits. The DNSSEC README records this floor; RFC 8017 §8.2.1 sets no such floor. | Yes |

## RFC 8020: NXDOMAIN: There Really Is Nothing Underneath

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §1 Introduction and Background: NXDOMAIN subtree meaning | `crates/pharos-plugins/src/kubernetes/mod.rs:804-808`, `crates/pharos-plugins/src/kubernetes/README.md:27` | **Deviation**: Kubernetes plugin returns NXDOMAIN for names with no records of their own even when descendants exist. Its README records this as CoreDNS parity. | Yes |
| §2 Rules: NXDOMAIN cut | `crates/pharos-plugins/src/cache/store.rs:157-161`, `crates/pharos-plugins/src/cache/mod.rs:767-779` | **Partial**: The cache stores NXDOMAIN denials (`cache/mod.rs:582-585`) and answers the exact denied question from them, but names and RRsets below the denied name are not treated as unreachable and are still forwarded. §6 lets non-tree caches skip the cut, but no ADR or cache README records that choice. | No |
| §3.1 Updates to RFC 1034 | `crates/pharos-plugins/src/zone/mod.rs:541-544,563-581,684-687` | **Fixed**: The apex exists even without the queried type, and existing empty non-terminals block wildcard synthesis. Fixed on `conf/zone` (#95). | No |
| §3.2 Updates to RFC 2308: descendant reuse | `crates/pharos-plugins/src/cache/mod.rs:767-779`, `crates/pharos-plugins/src/cache/store.rs:157-161` | **Missing**: NXDOMAIN descendant cuts remain deferred on `conf/cache` (#97); the cache uses exact-name lookup and does not search descendants. | No |
| §5 Possible Issues: ENT answered with NXDOMAIN | `crates/pharos-plugins/src/kubernetes/mod.rs:804-808`, `crates/pharos-plugins/src/kubernetes/README.md:27` | **Deviation**: §5 calls an authoritative NXDOMAIN for an empty non-terminal "definitely wrong". Kubernetes returns NXDOMAIN for names with no records of their own (for example `svc.<zone>`) even when descendants exist. The README records this as CoreDNS parity. | Yes |

## RFC 8078: Managing DS Records from the Parent via CDS/CDNSKEY

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4 DNSSEC Delete Algorithm | `crates/pharos-plugins/src/sign/signer.rs:52-57,97-110` | **Fixed**: The signer preserves and signs a sole CDS/CDNSKEY delete signal. Fixed on `conf/dnssec` (#100). | Yes |

## RFC 8080: Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §8 Security Considerations | `crates/pharos-plugins/src/dnssec/setup.rs:79-86`, `crates/pharos-plugins/src/dnssec/signing.rs:350-392` | **Fixed**: Runtime keys are bound to their owner zones; unkeyed zones pass DNSSEC Queries through. Fixed on `conf/dnssec` (#100). | No |

## RFC 8482: Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4 Behavior of DNS Responders | `crates/pharos-plugins/src/any/mod.rs:11-47`, `crates/pharos-plugins/src/any/README.md:7` | **Deviation**: The plugin synthesizes HINFO before checking whether the QNAME exists, instead of following standard lookup behavior for nonexistent names. The README documents synthesis before backend lookup. | Yes |
| §4 Behavior of DNS Responders | `crates/pharos-plugins/src/any/mod.rs:35-45`, `crates/pharos-plugins/tests/functional/any.rs:39-46` | **Fixed**: Non-IN ANY Questions pass through rather than receiving an IN HINFO answer. Fixed on `conf/plugins-synth` (#102). | No |
| §4.2 Synthesized HINFO RRset — CNAME owner | `crates/pharos-plugins/src/any/mod.rs:15-47`, `crates/pharos-plugins/src/any/README.md:7` | **Deviation**: `any` synthesizes HINFO before checking whether the owner has a CNAME. The README records this CoreDNS-compatible behavior. | Yes |
| §4.2 Synthesized HINFO RRset — CPU field | `crates/pharos-plugins/src/any/mod.rs:37-47` | **Fixed**: CPU field is `RFC8482`. Fixed on `conf/plugins-synth` (#102). | No |
| §4.2 Synthesized HINFO RRset — OS field | `crates/pharos-plugins/src/any/mod.rs:37-47` | **Deviation**: RFC recommends an empty OS string; Pharos sends `See RFC 8482`. The plugin documents CoreDNS-compatible HINFO synthesis. | Yes |
| §4.2 Synthesized HINFO RRset — TTL policy | `crates/pharos-plugins/src/any/mod.rs:37-47` | **Fixed**: Operators can configure the synthesized HINFO TTL; default remains 8482 seconds. Fixed on `conf/plugins-synth` (#102). | No |
| §4.2 Synthesized HINFO RRset — configurable TTL | `crates/pharos-plugins/src/any/mod.rs:37-47` | **Fixed**: The synthesized HINFO TTL is configurable. Fixed on `conf/plugins-synth` (#102). | No |
| §4.2 Synthesized HINFO RRset — signed Zone with DO=1 | `crates/pharos-plugins/src/any/mod.rs:37-47`, `crates/pharos-plugins/src/any/README.md:7` | **Deviation**: The plugin returns no RRSIG for its synthesized answer when DO=1, including for signed Zones. The README records this CoreDNS-compatible limitation. | Yes |
| §6 HINFO Considerations | `crates/pharos-plugins/src/any/mod.rs:37-47`, `crates/pharos-plugins/src/any/setup.rs:7-11` | **Partial**: The opt-in `any` plugin always synthesizes HINFO and has no setting to choose a single RRset or another type. Its README records unconditional HINFO synthesis, but not §6's recommendation for zones that rely on HINFO; operators can avoid this mode only by omitting the plugin. | No |

## RFC 8490: DNS Stateful Operations

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4.2 Applicable Transports | `xtask/src/query.rs:93-97,221-230` | **Fixed**: `+opcode=stateful` rejects UDP. Fixed on `conf/infra` (#105). | No |
| §5.4 Message Format | `xtask/src/query.rs:316-379` | **Violation**: The DSO query builder still emits a Question and may add OPT or TSIG; full DSO client support remains unsupported (conf/server #101), and no builder fix was reported on `conf/infra` (#105). | No |
| §5.4 Message Format | `crates/pharos-server/src/admission.rs:34-37` | **Fixed**: DSO requests with nonzero section counts receive FORMERR. Fixed on `conf/server` (#101). | No |
| §5.4.1 DNS Header Fields in DSO Messages | `xtask/src/query.rs:319-320` | **Violation**: The DSO query builder still uses ID zero; client-side DSO IDs remain unimplemented (conf/server #101; conf/infra #105 only rejects UDP transport). | No |
| §5.4.1 DNS Header Fields in DSO Messages | `crates/pharos-server/src/admission.rs:34-36,68-74` | **Fixed**: ID-zero DSO requests are suppressed, not answered; error responses use nonzero IDs. Fixed on `conf/server` (#101). | No |
| §5.4.1 DNS Header Fields in DSO Messages | `crates/pharos-server/src/admission.rs:70` | **Fixed**: DSO response flags clear reserved AD/CD bits. Fixed on `conf/server` (#101). | No |
| §5.4.3 DSO Unidirectional Messages | `crates/pharos-server/src/admission.rs:34-36,68-74` | **Fixed**: ID-zero DSO unidirectional requests receive no response. Fixed on `conf/server` (#101). | No |
| §5.5 Message Handling | `crates/pharos-server/src/admission.rs:33-36,68-74` | **Fixed**: ID-zero DSO unidirectional requests receive no response. Fixed on `conf/server` (#101). | No |
| §5.5.3 Error Responses | `crates/pharos-server/src/admission.rs:34-36,68-75`, `crates/pharos-server/src/server.rs:426-447`, `crates/pharos-server/src/tcp.rs:207-213,280-293` | **Fixed**: Unexpected DSO unidirectional requests abort the TCP connection. Fixed on `conf/server` (#101). | No |

## RFC 8659: DNS Certification Authority Authorization (CAA) Resource Record

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4.1 Syntax | `crates/pharos-proto/src/zone/rdata.rs:215-225`, `crates/pharos-proto/tests/zone_strictness.rs:185-189`, `crates/pharos-proto/tests/zone_rdata.rs:187-189` | **Fixed**: CAA tags require alphanumeric octets. Fixed on `conf/proto` (#99). | No |
| §4.1 Syntax | `crates/pharos-proto/src/rdata.rs:1047-1053`, `crates/pharos-proto/src/zone/rdata.rs:214-220` | **Fixed**: CAA reserved flag bits are cleared on write; zone input remains strict. Fixed on `conf/proto` (#99). | No |
| §4.1.1 Canonical Presentation Format | `crates/pharos-proto/src/rdata.rs:1346-1350`, `crates/pharos-plugins/src/sign/output.rs:82-92` | **Partial**: Both presentation writers preserve uppercase tags, while the canonical presentation format requires lowercase tags. | No |
| §4.1.1 Canonical Presentation Format | `crates/pharos-proto/src/zone/rdata.rs:221-224`, `crates/pharos-proto/tests/zone_strictness.rs:194-196` | **Fixed**: CAA zone-file values may exceed 255 octets. Fixed on `conf/proto` (#99). | No |

## RFC 8749: Moving DNSSEC Lookaside Validation (DLV) to Historic Status

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4 Moving DLV to Historic Status | `crates/pharos-proto/src/codes.rs:186`, `crates/pharos-proto/src/zone/rdata/legacy.rs:187-197`, `crates/pharos-proto/src/zone/rdata.rs:424` | **Deviation**: DLV remains recognized and accepted in zone files for CoreDNS v1.15.0 / miekg/dns v1.1.73 interoperability; `docs/compatibility.md` records this (conf/proto #99). The final reports do not state DLV Dynamic UPDATE behavior. | Yes |

## RFC 8767: Serving Stale Data to Improve DNS Resiliency

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4 Standards Action — stale response TTL | `crates/pharos-plugins/src/cache/setup.rs:144-148`; `crates/pharos-plugins/src/cache/store.rs:179-185` | **Fixed**: Stale responses use a positive TTL with a 30-second default. Fixed on `conf/cache` (#97). | No |
| §4 Standards Action — zero-TTL cache | `crates/pharos-plugins/src/cache/mod.rs:591-618,648-652` | **Deviation**: Positive minimum TTL still raises and caches zero-TTL records for CoreDNS compatibility; documented in `docs/compatibility.md` and the cache README (RFC 1035 §3.2.1; RFC 8767 §4). | Yes |
| §7 Implementation Caveats | `crates/pharos-plugins/src/cache/mod.rs:218-245, crates/pharos-plugins/src/cache/mod.rs:285-290` | **Deviation**: Default immediate mode serves stale before refresh failure is known. ADR 0002 permits CoreDNS-compatible behavior. | Yes |
| §7 Implementation Caveats | `crates/pharos-plugins/src/cache/mod.rs:593-618, crates/pharos-plugins/src/cache/mod.rs:625-652, crates/pharos-plugins/src/cache/setup.rs:53-56` | **Deviation**: An incoming zero TTL is raised to the configured minimum before eligibility and storage; this retained CoreDNS-compatible behavior is recorded in `docs/compatibility.md` and the cache README. | Yes |

## RFC 8777: DNS Reverse IP Automatic Multicast Tunneling (AMT) Discovery

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4.2 RData Format | `crates/pharos-proto/src/rdata.rs:31,963`, `crates/pharos-proto/src/rdata.rs:1260-1295` | **Partial**: Zone text can encode AMTRELAY, but wire parsing rejects it (AMTRELAY is in `unsupported_name_type`, rdata.rs:31, so rdata.rs:963 returns an error) and the `Unknown` writer rejects it too (rdata.rs:1260-1295). Valid records therefore cannot pass through typed parse/rebuild. | No |
| §4.2 RData Format | `crates/pharos-proto/src/zone/rdata/advanced.rs:163-165` | **Violation**: The zone encoder accepts type values 128–255 and ORs them into the D/type octet, although type is only 7 bits. Values with the high bit set can alter D. Existing RFC 8777 §4 citation covers address encoding, not this bound. | No |
| §4.2.3 RData Format - Type | `crates/pharos-proto/src/zone/rdata/advanced.rs:163-176` | **Violation**: With D=0, types 0–3 use their defined relay encodings (type 3 uncompressed). With D=1, the `out[1] < 128` check at advanced.rs:174 drops the relay bytes for every type, so types 1–3 lose the address or name their type defines. No ADR, plugin README, or `docs/compatibility.md` entry justifies this; zone_advanced.rs:257 asserts the truncated `[10, 0x83]` for type 3. | No |
| §4.2.4 RData Format - Relay | `crates/pharos-proto/src/zone/rdata/advanced.rs:167-176` | **Violation**: With D=0, the empty, IPv4, IPv6, and uncompressed-name relay fields are encoded, including the root label that Erratum 6218 requires. With D=1, advanced.rs:174 omits the relay field for types 1–3, though the field is required for each type. No ADR, plugin README, or `docs/compatibility.md` entry justifies this. | No |
| §4.3.1 Representation of AMTRELAY RRs | `crates/pharos-proto/src/zone/rdata/advanced.rs:146-171` | **Violation**: The parser requires the presentation fields and enforces `.` for type 0, but accepts an 8-bit type value above 127. It then treats the high bit as D, silently changing the supplied type; the relay type is only 7 bits. | No |
| §5 IANA Considerations | `crates/pharos-proto/src/zone/rdata/advanced.rs:163-165` | **Violation**: Verified Erratum 6688 makes Relay Type a 7-bit field, but parsing accepts 128–255 and ORs those bits into D; input 128 is silently encoded as D=1, Relay Type=0. The nearby citation names §4, not §5. | No |

## RFC 8914: Extended DNS Errors

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 Extended DNS Error EDNS0 Option Format | `crates/pharos-proto/src/edns_options.rs:196-209` | **Partial**: RFC defines EXTRA-TEXT as UTF-8, but the public encoder accepts arbitrary bytes and emits them unchanged. Template text is a Rust `String`, but other callers can encode invalid UTF-8; the template encoder comment also cites §4 instead of §2. | No |
| §3 Extended DNS Error Processing | `crates/pharos-plugins/src/template/setup.rs:118-124`, `crates/pharos-plugins/src/template/mod.rs:740-747` | **Partial**: `ederror` accepts text up to the wire limit (65,533 bytes) without limiting or warning on lengthy EXTRA-TEXT, which can consume the response budget and trigger truncation. | No |
| §4.1 Extended DNS Error Code 0 - Other | `crates/pharos-plugins/src/template/setup.rs:118-124`, `crates/pharos-plugins/src/template/mod.rs:740-748` | **Partial**: `ederror` accepts code 0 without a reason and serializes empty EXTRA-TEXT, though RFC 8914 says implementations SHOULD add explanatory text. A reason can be configured, but the nearby citation names §4 rather than §4.1. | No |
| §4.16 Extended DNS Error Code 15 - Blocked | `crates/pharos-plugins/src/acl/mod.rs:251-288`, `crates/pharos-plugins/tests/functional/acl.rs:127-165` | **Violation**: ACL EDE 15 mapping remains deferred on `conf/plugins-synth` (#102) because TSIG/EDE policy is cross-cutting. | No |
| §4.18 Extended DNS Error Code 17 - Filtered | `crates/pharos-plugins/src/acl/mod.rs:251-288`, `crates/pharos-plugins/tests/functional/acl.rs:95-109,392-413` | **Violation**: EDE 17 mapping for server-side filtering remains deferred on `conf/plugins-synth` (#102) as cross-cutting EDE semantics. | No |
| §4.21 Extended DNS Error Code 20 - Not Authoritative | `crates/pharos-plugins/src/auto/mod.rs:191-197`, `crates/pharos-server/src/outcome.rs:77-85`, `crates/pharos-plugins/src/template/setup.rs:118-124`, `crates/pharos-plugins/src/template/mod.rs:740-760` | **Partial**: Automatic EDE 20 mapping remains deferred on `conf/plugins-synth` (#102); Template can still configure it manually. | No |
| §4.21 Extended DNS Error Code 20 - Not Authoritative | `crates/pharos-plugins/src/forward/mod.rs:236-245`, `crates/pharos-server/src/outcome.rs:77-85`, `crates/pharos-plugins/src/template/setup.rs:118-124`, `crates/pharos-plugins/src/template/mod.rs:740-760` | **Partial**: Automatic EDE 20 mapping for forward REFUSED remains deferred on `conf/plugins-synth` (#102); RD-sensitive behavior is also open. | No |

## RFC 8945: Secret Key Transaction Authentication for DNS (TSIG)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §5.2 Server Processing of Request | `crates/pharos-plugins/src/tsig/mod.rs:58-64, 81-95`; `crates/pharos-proto/src/tsig.rs:588-595` | **Partial**: The parser rejects TSIG in Answer or Authority, and the plugin rejects duplicate or non-final Additional records for every Query it serves, before zone matching. A TSIG in Answer or Authority of a Query outside a configured zone is ignored instead of being dropped with FORMERR. | No |
| §5.2 Server Processing of Request | `crates/pharos-plugins/src/tsig/mod.rs:65-95, 123-178`; `crates/pharos-proto/src/message.rs:494-503` | **Partial**: A correctly placed TSIG is retained, removed, and excluded from ARCOUNT when the request has a question matching a configured zone. Requests outside that path do not get TSIG processing. | No |
| §5.2 Server Processing of Request | `crates/pharos-plugins/src/tsig/mod.rs:123-126` | **Partial**: An uninterpretable TSIG maps to FORMERR once the plugin recognizes it, but TSIG outside Additional or requests outside a configured zone bypass this check. Erratum 7983 correctly changes the destination to the client. | No |
| §5.2 Server Processing of Request | `crates/pharos-plugins/src/tsig/mod.rs:65-95, 166-178`; `crates/pharos-server/src/outcome.rs:145-148`; `crates/pharos-server/src/admission.rs:34-36`; `crates/pharos-server/src/server.rs:499-501`; `crates/pharos-plugins/src/tsig/README.md:8,11` | **Partial**: A valid TSIG request gets a signed response only after the plugin matches a configured zone and question and UPDATE admission passes. A valid TSIG outside that path, including a rejected UPDATE, can receive an unsigned response. | Yes |
| §5.2.1 Key Check and Error Handling | `crates/pharos-plugins/src/tsig/mod.rs:151-155`; `crates/pharos-plugins/src/tsig/README.md:11` | **Deviation**: A known key with an unsupported algorithm returns NOTAUTH/BADSIG instead of required NOTAUTH/BADKEY. Plugin README records this CoreDNS-compatibility choice. | Yes |
| §5.2.1 Key Check and Error Handling | `crates/pharos-plugins/src/tsig/mod.rs:138-164` | **Missing**: Unknown-key and unsupported-algorithm errors return responses but are not logged, despite the SHOULD. | No |
| §5.2.2 MAC Check and Error Handling | `crates/pharos-plugins/src/tsig/mod.rs:160-165`; `crates/pharos-server/src/outcome.rs:341-370` | **Missing**: MAC failure is checked and returns unsigned NOTAUTH/BADSIG, but code does not log the error, despite the SHOULD. | No |
| §5.2.3 Time Check and Error Handling | `crates/pharos-plugins/src/tsig/mod.rs:157-165` | **Deviation**: the server does not cache the latest received Time Signed value. The TSIG README explicitly says replay detection is not implemented. | Yes |
| §5.2.3 Time Check and Error Handling | `crates/pharos-plugins/src/tsig/mod.rs:157-165` | **Deviation**: the server does not reject a request whose Time Signed value predates an earlier request. The TSIG README explicitly says replay detection is not implemented. | Yes |
| §5.2.3 Time Check and Error Handling | `crates/pharos-plugins/src/tsig/mod.rs:162-164` | **Missing**: BADTIME responses return without logging the error, despite the SHOULD. | No |
| §5.3 Generation of TSIG on Answers | `crates/pharos-server/src/admission.rs:57-64`, `crates/pharos-server/src/server.rs:497-535`, `crates/pharos-plugins/src/tsig/README.md:11` | **Deviation**: admission-level errors, including BADVERS and rejected UPDATE, bypass TSIG processing and remain unsigned for signed requests. The TSIG README records this CoreDNS-compatible behavior. | Yes |
| §5.3.1 TSIG on TCP Connections | `crates/pharos-proto/src/tsig.rs:418-437` | **Partial**: the normal stream signer signs Responses, but the public `TsigStream::add_unsigned` lets a caller emit unsigned intermediary Responses. Its doc comment states RFC 8945 requires senders to sign every Response and limits the method to legacy interoperability, so the requirement is only partly met by the API. | No |
| §5.4 Client Processing of Answer | `xtask/src/query.rs:255-290` | **Fixed**: The TSIG response checker requires NOTAUTH for unsigned BADKEY/BADSIG errors. Fixed on `conf/infra` (#105). | No |
| §5.5 Special Considerations for Forwarding Servers | `crates/pharos-plugins/src/tsig/mod.rs:138-140` | **Violation**: When the TSIG plugin covers the Query's zone, an unknown key returns BADKEY instead of forwarding the TSIG Message unchanged. | No |
| §5.5 Special Considerations for Forwarding Servers | `crates/pharos-plugins/src/tsig/mod.rs:177-178`, `crates/pharos-plugins/src/forward/mod.rs:395-397`, `crates/pharos-server/src/outcome.rs:145-148` | **Fixed**: AD is cleared only after a verified client TSIG is stripped and before Pharos re-signs without upstream transaction security. Fixed on `conf/forward` (#104). | No |
| §6 Algorithms and Identifiers | `crates/pharos-plugins/src/tsig/setup.rs:99-107`, `crates/pharos-plugins/src/tsig/mod.rs:144-160` | **Partial**: SHA-1 remains supported as required for compatibility, but setup enables it for every key and offers no policy to replace existing SHA-1 use with SHA-2 as recommended. | No |
| §7 TSIG Truncation Policy | `crates/pharos-proto/src/tsig.rs:127-150` | **Partial**: The default signer emits a full-length Response MAC, but `sign_truncated` permits one shorter than the validated Query MAC. RFC 8945 says a reply SHOULD be at least as long as its Query MAC. | No |
| §8 Shared Secrets | `crates/pharos-proto/src/tsig_key.rs:33-45`, `crates/pharos-proto/src/tsig.rs:68-79`, `crates/pharos-plugins/src/tsig/setup.rs:99-108` | **Violation**: Any decodable secret length is accepted and passed to HMAC. This permits secrets shorter than the keyed hash output, contrary to §8's SHOULD. | No |
| §10 Security Considerations | `crates/pharos-plugins/src/tsig/setup.rs:99-107`, `crates/pharos-plugins/src/tsig/mod.rs:144-155` | **Deviation**: one configured key name and secret create keys for all five supported algorithms, contrary to the recommendation to associate only one algorithm with a key name. ADR 0002 permits CoreDNS-compatible behavior, and `crates/pharos/compatibility.md:243` records this behavior; neither gives a section-specific citation. | No |

## RFC 8976: Message Digest for DNS Zones

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.2.3 Hash Algorithm Field | `crates/pharos-proto/src/rdata.rs:927-935,1215-1227`, `crates/pharos-proto/src/zone/rdata.rs:274-285` | **Fixed**: SHA-384 ZONEMD digests require exactly 48 octets. Fixed on `conf/proto` (#99). | No |
| §2.2.3 Hash Algorithm Field | `crates/pharos-proto/src/rdata.rs:927-935,1215-1227`, `crates/pharos-proto/src/zone/rdata.rs:274-285` | **Fixed**: SHA-512 ZONEMD digests require exactly 64 octets. Fixed on `conf/proto` (#99). | No |
| §2.2.4 Digest Field | `crates/pharos-proto/src/rdata.rs:927-935,1215-1227`, `crates/pharos-proto/src/zone/rdata.rs:274-285`, `crates/pharos-proto/tests/zone_strictness.rs:32-42` | **Fixed**: ZONEMD digests retain the 12-octet minimum in zone parsing, wire parsing, and encoding. Fixed on `conf/proto` (#99). | No |
| §2.5 Including ZONEMD RRs in a Zone | `crates/pharos-plugins/src/zone/mod.rs:194-223` | **Violation**: Zone construction retains each ZONEMD record without checking for duplicate `(Scheme, Hash Algorithm)` tuples at an owner. A zone with distinct digests but a repeated tuple can load and be served. | No |

## RFC 9077: NSEC and NSEC3: TTLs and Aggressive Use

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.1 Updates to RFC 4034 | `crates/pharos-plugins/src/sign/signer.rs:149-155`, `crates/pharos-plugins/src/zone/mod.rs:454-467` | **Fixed**: Stored NSEC TTL uses `min(SOA TTL, SOA.MINIMUM)`. Fixed on `conf/dnssec` (#100). | No |
| §3.2 Updates to RFC 4035 | `crates/pharos-plugins/src/sign/signer.rs:149-155`, `crates/pharos-plugins/src/zone/mod.rs:454-467`, `crates/pharos-plugins/src/dnssec/signing.rs:130-141,277-289` | **Fixed**: Stored and synthetic NSEC TTLs use the lesser of SOA TTL and MINIMUM. Fixed on `conf/dnssec` (#100). | No |

## RFC 9110: HTTP Semantics

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.4 Error Handling | `crates/pharos-server/src/http.rs:124-126, 194-196`, `crates/pharos-plugins/src/lib.rs:597-607, 653-658, 699-706` | **Violation**: `/health` ignores the method and returns 200 for every method; `/ready` and `/metrics` return 404 for non-GET methods even when the path exists. These handlers discard method semantics; the ready and prometheus READMEs record their 404 behavior, but the health README does not record its method behavior. | No |
| §7.4 Rejecting Misdirected Requests | `crates/pharos-server/src/http.rs:183-185`, `crates/pharos-plugins/src/lib.rs:597-607,653-658,692-705` | **Violation**: The shared listener routes only on `request.uri().path()` and ignores the target URI scheme. An absolute-form `https` target for an operational endpoint is routed over cleartext, contrary to the requirement to reject it unless the connection is secured for that origin. | No |
| §8.8.3.1 Generation | `crates/pharos-server/src/http.rs:186-193`, `crates/pharos-plugins/src/lib.rs:597-607,653-658,699-706` | **Violation**: `/ready` and `/metrics` bodies change with check state and metric values, so change detection is reasonable, but the shared response builder adds no ETag. Health's constant `OK` body is exempt. No ADR or plugin README documents this omission. | No |
| §9.1 Overview — case-sensitive method token | `crates/pharos-plugins/src/lib.rs:597-607`, `crates/pharos-server/src/http.rs:183-198`, `crates/pharos-kubernetes/examples/support/api.rs:25-27`, `crates/pharos-kubernetes/examples/differential.rs:311-369`, `crates/pharos-kubernetes/examples/memory.rs:103-141` | **Violation**: Health and the Kubernetes mock APIs ignore the method, so lowercase `get` receives the same response as `GET`. This conflates case-sensitive method tokens. | No |
| §9.1 Overview — unrecognized or unimplemented methods | `crates/pharos-plugins/src/lib.rs:597-607,653-659,699-706`, `crates/pharos-server/src/http.rs:124-126,184-197`, `crates/pharos-kubernetes/examples/support/api.rs:25-27`, `crates/pharos-kubernetes/examples/differential.rs:311-369`, `crates/pharos-kubernetes/examples/memory.rs:103-141` | **Violation**: Health returns its normal response, readiness and metrics return 404, and Kubernetes mock APIs return normal GET responses regardless of method. RFC 9110 recommends 501 for unrecognized or unimplemented methods and 405 for recognized methods not allowed by the resource. | No |
| §9.3.2 HEAD | `crates/pharos-server/src/http.rs:124-126, crates/pharos-plugins/src/lib.rs:653-659, 699-706` | **Partial**: Hyper suppresses content for HEAD, but the GET-only ready and metrics routes return 404 instead of the GET route’s status and corresponding headers. | No |
| §9.3.3 POST | `crates/pharos-plugins/src/lib.rs:597-606` | **Violation**: The health route ignores the method and request representation, then returns 200 `OK` for `POST /health`; it does not process the representation according to POST semantics. | No |
| §9.3.4 PUT | `crates/pharos-plugins/src/lib.rs:597-606` | **Violation**: The health route ignores the method and request representation, then returns 200 `OK` for `PUT /health`; it does not create or replace target-resource state. | No |
| §9.3.5 DELETE | `crates/pharos-plugins/src/lib.rs:597-606` | **Violation**: The health route ignores the method and returns 200 `OK` for `DELETE /health` without removing the target resource’s association with its functionality. | No |
| §9.3.8 TRACE | `crates/pharos-plugins/src/lib.rs:597-607, crates/pharos-server/src/http.rs:183-192` | **Violation**: The health route ignores the method and returns constant `OK` for `TRACE /health`; it does not reflect the received request as response content. No source document justifies this. | No |
| §10.1.2 From | `crates/pharos-server/src/http.rs:93-97` | **Violation**: The periodic health self-probe acts as a robotic user agent but sends no `From` contact address. RFC 9110 says robotic user agents SHOULD send a valid address; no exception is documented. | No |
| §10.1.5 User-Agent | `crates/pharos-server/src/http.rs:93-97` | **Violation**: The health self-probe sends no `User-Agent` field, despite RFC 9110's SHOULD to send one on each request unless specifically configured not to. No opt-out is documented. | No |
| §13.1.1 If-Match | `crates/pharos-server/src/http.rs:183-198`, `crates/pharos-plugins/src/lib.rs:597-607,653-659,699-706` | **Violation**: Origin servers MUST evaluate If-Match before performing a method, using strong comparison. These handlers ignore request fields; with no ETag, a non-wildcard tag list cannot match, yet the endpoint still serves the representation. | No |
| §13.1.1 If-Match | `crates/pharos-server/src/http.rs:183-198`, `crates/pharos-plugins/src/lib.rs:597-607,653-659,699-706` | **Violation**: An origin server MUST NOT perform the method when If-Match is false. A GET with a nonmatching If-Match tag list still receives the normal 200 response instead of a failed precondition. | No |
| §13.1.2 If-None-Match | `crates/pharos-server/src/http.rs:183-198`, `crates/pharos-plugins/src/lib.rs:597-607,653-659,699-706` | **Violation**: Recipients MUST evaluate If-None-Match using weak comparison before the method. The handlers ignore it; `If-None-Match: *` matches each existing endpoint representation but still receives 200. | No |
| §13.1.2 If-None-Match | `crates/pharos-server/src/http.rs:183-198`, `crates/pharos-plugins/src/lib.rs:597-607,653-659,699-706` | **Violation**: When If-None-Match is false, an origin server MUST NOT perform the method and MUST return 304 for GET/HEAD or 412 otherwise. A matching wildcard gets the normal 200 response. | No |
| §13.2.1 When to Evaluate | `crates/pharos-server/src/http.rs:183-198`, `crates/pharos-plugins/src/lib.rs:597-607,653-659,699-706` | **Violation**: An origin server MUST evaluate applicable preconditions after normal checks and before processing content or performing the method when the unconditional response would be 2xx or 412. Existing operational endpoints return 200, but the shared handler ignores all conditional fields. | No |
| §13.2.2 Precedence of Preconditions | `crates/pharos-server/src/http.rs:183-198` | **Violation**: An origin server MUST evaluate multiple conditional fields in the specified order. The shared handler ignores all conditional fields, including requests carrying multiple preconditions. | No |
| §14.2 Range | `crates/pharos-server/src/http.rs:183-198`, `crates/pharos-plugins/src/lib.rs:699-706` | **Partial**: The listener ignores `Range` and sends complete responses. RFC 9110 makes range requests optional, but says origin servers ought to support byte ranges when possible; `/metrics` can return large representations, and no justification for omitting range support is recorded. | No |
| §14.5 Partial PUT | `crates/pharos-server/src/http.rs:124-126,183-198`, `crates/pharos-plugins/src/lib.rs:597-607,653-659,699-706` | **Violation**: Health returns 200 for every method on `/health`, including `PUT` with `Content-Range`; ready and metrics routes return 404. None returns the SHOULD-recommended 400 for `Content-Range` on `PUT` when partial PUT is unsupported, and no justification is recorded. | No |
| §15.5 Client Error 4xx | `crates/pharos-server/src/http.rs:186-196`, `crates/pharos-plugins/src/lib.rs:653-659`, `crates/pharos-plugins/src/lib.rs:699-706` | **Partial**: Readiness and metrics path or method misses return empty 404 responses. RFC 9110 says a server SHOULD send an explanatory representation except for HEAD; the health handler supplies a generic not-found explanation. | No |
| §15.5.5 404 Not Found | `crates/pharos-server/src/http.rs:124-126`, `crates/pharos-server/src/http.rs:196`, `crates/pharos-plugins/src/lib.rs:653-659`, `crates/pharos-plugins/src/lib.rs:699-706` | **Deviation**: `/ready` and `/metrics` serve GET only, and other methods on those paths receive 404. The prometheus README records "Only GET requests are served at `/metrics`; other HTTP methods return 404", and the ready README records "serves GET only", so the method policy is documented. The 405 that RFC 9110 §9.1 prefers is assessed under §9.1. | Yes |
| §15.6 Server Error 5xx | `crates/pharos-server/src/http.rs:186-194` | **Partial**: Invalid callback status or content type becomes 500 with an empty body. RFC 9110 §15.6 says a server SHOULD send an explanatory representation except for HEAD. | No |
| §15.6 Server Error 5xx | `crates/pharos-server/src/http.rs:186-196`, `crates/pharos-plugins/src/ready/mod.rs:76-99` | **Partial**: `/ready` 503 responses name shutdown or unready checks but do not say whether the condition is temporary or permanent. The 500 fallback sends no explanatory representation. | No |
| §17.5 Attacks via Protocol Element Length | `crates/pharos-server/src/http.rs:29-30,159-206` | **Partial**: The listener caps concurrent connections at 1,024 and each connection at five seconds, but configures no request-target or field-size limits; remaining parsing bounds rely on Hyper defaults. | No |

## RFC 9276: Guidance for NSEC3 Parameter Settings

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.1 Best Practice for Zone Publishers | `crates/pharos-dnssec/src/denial.rs:294-299,322-336` | **Violation**: `nsec3_chain` accepts any `u16` iteration count and writes it into generated NSEC3 records, allowing nonzero counts despite the MUST to use zero. The helper has no production caller; the signer currently emits NSEC instead. | No |
| §3.1 Best Practice for Zone Publishers | `crates/pharos-dnssec/src/denial.rs:294-299,335` | **Violation**: `nsec3_chain` takes a caller-supplied salt and stores it verbatim (`salt.to_vec()`), so it can emit nonempty salts despite the SHOULD NOT use a salt. No README or ADR justifies this. | No |

## RFC 9293: Transmission Control Protocol (TCP)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.7.4 Nagle Algorithm | `crates/pharos-server/src/tcp.rs:112`, `crates/pharos-plugins/src/proxy/mod.rs:70` | **Violation**: SHLD-7 says a TCP implementation SHOULD implement Nagle. Both the DNS-over-TCP server and the proxy upstream always call `set_nodelay(true)` and never enable Nagle. The per-connection disable (MUST-17) is met by the same call. No ADR or plugin README justifies the deviation; the `tcp.rs:111` comment gives a rationale but is not a recorded decision. | Yes |

## RFC 9432: DNS Catalog Zones

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4 Catalog Zone Structure | `crates/pharos-plugins/src/secondary/catalog.rs:68-71,99-101`, `crates/pharos-plugins/src/secondary/update.rs:135-157`, `crates/pharos-plugins/src/zone/mod.rs:144-198` | **Fixed**: Catalog zones reject multiple SOAs and validate apex authority records. Fixed on `conf/secondary` (#98). | No |
| §4.2 Properties | `crates/pharos-plugins/src/secondary/catalog.rs:92-120` | **Fixed**: Multiple `coo` records are rejected, including on orphan catalog nodes. Fixed on `conf/secondary` (#98). | No |
| §4.3.1 Change of Ownership (coo property) | `crates/pharos-plugins/src/secondary/catalog.rs:92-120` | **Fixed**: `coo` RRsets with multiple records make the catalog invalid. Fixed on `conf/secondary` (#98). | No |
| §5.1 General Requirements | `crates/pharos-plugins/src/secondary/catalog.rs:133-164`, `crates/pharos-plugins/src/secondary/update.rs:145-149` | **Fixed**: Broken catalogs cannot authorize member migration. Fixed on `conf/secondary` (#98). | No |
| §5.1 General Requirements | `crates/pharos-plugins/src/secondary/catalog.rs:159-164`, `crates/pharos-plugins/src/secondary/update.rs:327` | **Fixed**: Expired catalogs cannot authorize member migration. Fixed on `conf/secondary` (#98). | No |
| §5.1 General Requirements | `crates/pharos-plugins/src/secondary/mod.rs:71-80,93-101`, `crates/pharos-plugins/src/secondary/update.rs:303-315` | **Partial**: Startup proceeds while the initial transfer retries, but catalog membership and the last valid member-zone snapshots are in memory only. After restart with a broken catalog, Pharos cannot serve member zones from the last valid catalog version. | No |
| §5.2 Member Zone Name Clash | `crates/pharos-plugins/src/secondary/catalog.rs:147-155` | **Fixed**: Member-name clashes are logged. Fixed on `conf/secondary` (#98). | No |
| §7 Security Considerations | `crates/pharos-plugins/src/secondary/update.rs:87-92`, `crates/pharos-plugins/src/secondary/setup.rs:38-44` | **Missing**: Authenticated/confidential catalog AXFR remains deferred on `conf/secondary` (#98) because it needs storage and transfer-auth configuration. | No |
| §7 Security Considerations | `crates/pharos-plugins/src/secondary/update.rs:87-92`, `crates/pharos-plugins/src/secondary/setup.rs:38-44` | **Missing**: Authenticated member-zone transfers remain deferred on `conf/secondary` (#98) because they need transfer-auth configuration. | No |
| §7 Security Considerations | `crates/pharos-plugins/src/acl/mod.rs:189-314`, `crates/pharos-plugins/src/secondary/update.rs:87-92` | **Partial**: Query ACL is optional and not catalog-specific; catalog data remains served as a normal zone. Catalog AXFR also uses plaintext TCP, with no confidential transfer option in this path. | No |
| §7 Security Considerations | `crates/pharos-plugins/src/secondary/setup.rs:47-71`, `crates/pharos-plugins/src/secondary/catalog.rs:137-145` | **Fixed**: Catalog scope must name admissible suffixes; an empty scope admits no members. Fixed on `conf/secondary` (#98). | No |

## RFC 9460: Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records)

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2.1 Zone-File Presentation Format | `crates/pharos-proto/src/zone.rs:496,525-526,535-542,640-661` | **Violation**: SvcParam parsing bypasses the malformed-digit-escape check. It accepts `\9` and `\99`, although Appendix A permits only a non-digit escape or a three-digit decimal octet from 000 to 255. | Yes |
| §2.2 RDATA Wire Format | `crates/pharos-proto/src/rdata.rs:797-799,1104-1106` | **Deviation**: The decoder accepts compressed TargetName values, although §2.2 specifies an uncompressed name. The writer emits it uncompressed; `crates/pharos/compatibility.md` records accepting compressed names under ADR 0002. | Yes |
| §2.4.1 SvcPriority | `crates/pharos-plugins/src/zone/mod.rs:454-457,802-810` | **Fixed**: Mixed AliasMode/ServiceMode RRsets are rejected. Fixed on `conf/zone` (#95). | No |
| §2.4.3 ServiceMode | `crates/pharos-proto/src/rdata.rs:45-61,86-118`, `crates/pharos-proto/src/zone/rdata.rs:1084-1177`, `crates/pharos-proto/tests/zone_strictness.rs:246-249` | **Fixed**: Wire and zone-file parsing enforce the `no-default-alpn`/`alpn` relationship. Fixed on `conf/proto` (#99). | No |
| §4.1 Authoritative Servers — Additional target records | `crates/pharos-plugins/src/zone/mod.rs:984-1021` | **Partial**: A/AAAA Additional processing is present; target SVCB records and their DNSSEC proofs remain deferred on `conf/zone` (#95) because they need target/proof additional processing. | No |
| §4.1 Authoritative Servers — DNSSEC records | `crates/pharos-plugins/src/zone/mod.rs:445-469`, `crates/pharos-plugins/src/zone/mod.rs:1011-1020` | **Partial**: Target SVCB records and DNSSEC proofs for absent target sets remain deferred on `conf/zone` (#95), outside the branch's owned processing scope. | No |
| §4.1 Authoritative Servers — TargetName "." | `crates/pharos-plugins/src/zone/mod.rs:993-1008`, `crates/pharos-plugins/src/zone/mod.rs:397-399` | **Fixed**: TargetName `.` maps to the owner for ServiceMode address additional processing. Fixed on `conf/zone` (#95). | No |
| §4.4 EDNS Client Subnet (ECS) | `crates/pharos-plugins/src/zone/mod.rs:985-1020`, `crates/pharos-server/src/server.rs:176-183`, `crates/pharos-plugins/src/expression/README.md:17-19` | **Partial**: ECS/source-prefix-zero filtering for SVCB/HTTPS additional data remains deferred on `conf/zone` (#95); it needs view/client policy beyond owned files. | No |
| §7.1.1 Representation | `crates/pharos-proto/src/rdata.rs:45-61,86-118`, `crates/pharos-proto/src/zone/rdata.rs:1115-1122`, `crates/pharos-proto/tests/zone_strictness.rs:243-249` | **Fixed**: `no-default-alpn` requires `alpn`, and mandatory parameters must be present. Fixed on `conf/proto` (#99). | No |
| §7.1.1 Representation — empty alpn | `crates/pharos-proto/src/zone/rdata.rs:1115-1122`, `crates/pharos-proto/tests/zone_strictness.rs:243-244` | **Violation**: The `alpn` presentation value must list one or more alpn-ids, but zone parsing accepts `alpn=` and serializes an empty value. This remains an open conformance gap and is not documented as retained CoreDNS behavior. | No |
| §7.2 "port" | `crates/pharos-proto/src/zone/rdata.rs:1128-1135`, `crates/pharos-proto/src/zone/rdata.rs:814-821` | **Fixed**: SvcParam `port` requires unescaped ASCII decimal. Fixed on `conf/proto` (#99). | No |
| §7.3 "ipv4hint" and "ipv6hint" | `crates/pharos-proto/src/rdata.rs:123-130`; `crates/pharos-proto/src/zone/rdata.rs:1147-1152` | **Fixed**: IPv4-mapped IPv6 hints are accepted. Fixed on `conf/proto` (#99). | No |
| §8 ServiceMode RR Compatibility and Mandatory Keys | `crates/pharos-proto/src/rdata.rs:45-60,86-101`, `crates/pharos-proto/src/zone/rdata.rs:1101-1113`, `crates/pharos-proto/tests/zone_strictness.rs:228-241` | **Fixed**: Mandatory keys must be present, nonempty, and self-consistent. Fixed on `conf/proto` (#99). | No |

## RFC 9471: DNS Glue Requirements in Referral Responses

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.2 Glue for Sibling Domain Name Servers | `crates/pharos-plugins/src/zone/mod.rs:963-980` | **Fixed**: Available sibling A/AAAA glue is included. Fixed on `conf/zone` (#95). | No |
| §3.3 Update to RFC 1034 | `crates/pharos-plugins/src/zone/mod.rs:845-853,963-980` | **Fixed**: Referral responses include available sibling nameserver addresses. Fixed on `conf/zone` (#95). | No |

## RFC 9520: Negative Caching of DNS Resolution Failures

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3.1 Retries and Timeouts | `crates/pharos-plugins/src/forward/setup.rs:111-123`, `crates/pharos-plugins/src/forward/mod.rs:288-303` | **Fixed**: Per-upstream attempt limits clamp to 1–3; zero means one. Fixed on `conf/forward` (#104). | No |
| §3.2 Caching | `crates/pharos-proto/src/response.rs:88-95`, `crates/pharos-plugins/src/cache/mod.rs:625-634` | **Deviation**: REFUSED is cached as a resolution failure per RFC 9520 §§2.2 and 3.2; this differs from the previous CoreDNS-compatible behavior and is recorded in `docs/compatibility.md` (conf/cache #97). | Yes |
| §3.2 Caching | `crates/pharos-plugins/src/cache/setup.rs:201-209`, `crates/pharos-plugins/src/cache/mod.rs:532-533` | **Partial**: The `servfail` option accepts zero and subsecond durations; processing converts the duration to whole seconds and skips insertion at zero. Operators can therefore disable failure caching or set it below the one-second minimum. The citation at `setup.rs:206` names §3.2 but covers only the five-minute cap. | Yes |
| §3.2 Caching | `crates/pharos-plugins/src/cache/setup.rs:139-150`, `crates/pharos-plugins/src/cache/mod.rs:582-585`, `crates/pharos-plugins/src/cache/store.rs:163-171` | **Fixed**: Expired resolution failures are not served stale. Fixed on `conf/cache` (#97). | No |
| §3.2 Caching | `crates/pharos-plugins/src/cache/setup.rs:24,66`, `crates/pharos-plugins/src/cache/mod.rs:532-533,619-620` | **Fixed**: Repeated failures use exponential backoff capped at five minutes. Fixed on `conf/cache` (#97). | No |
| §3.2 Caching | — | **Fixed**: Failure-cache conditions, keys, TTLs, and backoff are summarized in `docs/compatibility.md`. Fixed on `conf/cache` (#97). | Yes |

## RFC 9606: DNS Resolver Information

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §3 Retrieving Resolver Information — RRset cardinality | `crates/pharos-plugins/src/zone/mod.rs:258-267,445-458` | **Violation**: RESINFO cardinality validation remains deferred on `conf/proto` (#99) because registry-aware RESINFO semantics are outside typed RDATA support. | No |
| §4 Format of the Resolver Information — key names | `crates/pharos-proto/src/zone/rdata/legacy.rs:164-172` | **Partial**: Registry-aware key validation remains deferred on `conf/proto` (#99); invalid fields can still be served. | No |
| §4 Format of the Resolver Information — key/value syntax | `crates/pharos-proto/src/zone/rdata/legacy.rs:164-172` | **Partial**: DNS-SD key/value syntax validation remains deferred on `conf/proto` (#99) as registry-aware semantics. | No |
| §5 Resolver Information Keys/Values — exterr value syntax | `crates/pharos-proto/src/zone/rdata/legacy.rs:164-172` | **Partial**: EDE `exterr` value syntax remains deferred on `conf/proto` (#99) as registry-aware semantics. | No |

## RFC 9824: Compact Denial of Existence in DNSSEC

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 Distinguishing Nonexistent Names | `crates/pharos-dnssec/src/denial.rs:171-214` | **Fixed**: Compact-denial bitmaps signal nonexistent names with NXNAME. Fixed on `conf/dnssec` (#100). | No |
| §3.1 Responses for Nonexistent Names | `crates/pharos-plugins/src/dnssec/signing.rs:99-108,151-156,262-289` | **Partial**: Denials with exactly one SOA use compact NXNAME proof; a DO negative response without SOA fails closed with SERVFAIL because no SOA minimum is available for a proof (conf/dnssec #100). | No |
| §3.1 Responses for Nonexistent Names | `crates/pharos-dnssec/src/denial.rs:171-214` | **Fixed**: Compact-denial bitmap contains only RRSIG, NSEC, and NXNAME. Fixed on `conf/dnssec` (#100). | No |
| §3.1 Responses for Nonexistent Names | `crates/pharos-plugins/src/dnssec/setup.rs:27-28,97-105`, `crates/pharos-plugins/src/dnssec/signing.rs:203-204,262-289` | **Fixed**: Keyless Zones pass DNSSEC denials through unsigned instead of emitting unsigned compact proofs. Fixed on `conf/dnssec` (#100). | No |
| §3.2 Responses for Nonexistent Types | `crates/pharos-dnssec/src/denial.rs:171-194` | **Partial**: Owner-specific NODATA bitmaps remain deferred on `conf/dnssec` (#100) because the response signer lacks authoritative zone/type inventory. | No |
| §3.5 Responses to Explicit Queries for NXNAME | — | **Partial**: The DNSSEC plugin returns FORMERR for explicit QTYPE 128 queries; server-wide handling when the plugin is absent remains deferred to unowned `pharos-server` paths (`conf/dnssec` #100). | No |

## RFC 9904: DNSSEC Cryptographic Algorithm Recommendation Update Process

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §1.2 Updating Algorithm Requirement Levels | `crates/pharos-dnssec/src/sign.rs:80-101`, `crates/pharos-dnssec/src/keys.rs:129-131,200-203`, `crates/pharos-plugins/src/sign/signer.rs:87-117` | **Fixed**: Signing rejects algorithm 10 under RFC 9904's NOT RECOMMENDED policy. Fixed on `conf/dnssec` (#100). | No |
| §3 DNS Security Algorithm Numbers Registry Column Values | `crates/pharos-dnssec/src/sign.rs:45-52`, `crates/pharos-dnssec/src/keys.rs:129-148`, `crates/pharos-dnssec/src/keys.rs:200-204` | **Fixed**: Algorithm 10 signing is rejected. Fixed on `conf/dnssec` (#100). | No |
| §4 Digest Algorithms Registry Column Values | `crates/pharos-dnssec/src/digest.rs:38-65`, `crates/pharos-plugins/src/sign/signer.rs:97` | **Fixed**: The SHA-1 DS/CDS digest API is removed; the signer emits SHA-256 CDS. Fixed on `conf/dnssec` (#100). | No |

## RFC 9905: Deprecating the Use of SHA-1 in DNSSEC Signature Algorithms

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §5 IANA Considerations — Digest Algorithms | `crates/pharos-dnssec/src/digest.rs:6-9`, `crates/pharos-dnssec/src/digest.rs:38-49`, `crates/pharos-dnssec/src/digest.rs:54-65` | **Fixed**: The public SHA-1 DS/CDS digest API is removed. Fixed on `conf/dnssec` (#100). | No |

## KEP-752: EndpointSlice API

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §Proposal > Endpoint Port | `crates/pharos-kubernetes/src/object.rs:180-188`, `crates/pharos-plugins/src/kubernetes/transfer.rs:225-237` | **Fixed**: Nil endpoint ports are omitted from AXFR. Fixed on `conf/k8s` (#103). | No |

## KEP-1645: Multi-Cluster Services API

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| KEP-1645 §Design Details > ClusterSet Service Behavior Expectations > DNS | `crates/pharos-plugins/src/kubernetes/transfer.rs:284-308,421-432` | **Fixed**: Multicluster AXFR names include each two-label `source-cluster` ID. Fixed on `conf/k8s` (#103). | No |
| KEP-1645 §specification.md > 2.1 - Definitions | `crates/pharos-plugins/src/kubernetes/setup.rs:185-190,237-243` | **Fixed**: Multicluster zones are restricted to `clusterset.local`. Fixed on `conf/k8s` (#103). | No |
| KEP-1645 §specification.md > 2.2 - Record for Schema Version | `crates/pharos-plugins/src/kubernetes/mod.rs:1008-1017` | **Deviation**: The `dns-version` TXT record returns `1.1.0`, while the MCS DNS schema declares `1.0.0`. The plugin README documents this as CoreDNS parity. | Yes |
| KEP-1645 §specification.md > 2.3.1 - `A`/`AAAA` Record | `crates/pharos-plugins/src/kubernetes/mod.rs:533-542,1128-1158` | **Deviation**: The handler emits family-matched ClusterSetIP addresses, including both families when present, but emits none when a ServiceImport has no ports because address enumeration is nested under the port loop; the plugin README records this CoreDNS-compatible NXDOMAIN. | Yes |
| KEP-1645 §specification.md > 2.3.2 - `SRV` Records | `crates/pharos-kubernetes/src/object.rs:124-135`; `crates/pharos-plugins/src/kubernetes/mod.rs:340-346,1128-1203` | **Partial**: An omitted ServiceImport protocol still becomes an empty label instead of TCP. The #103 report covers `k8s_external` named-port handling but does not state whether ServiceImport protocol handling changed; no follow-up issue is identified. | No |
| KEP-1645 §specification.md > 2.4.1 - `A`/`AAAA` Records | `crates/pharos-plugins/src/kubernetes/name.rs:47-62`; `crates/pharos-plugins/src/kubernetes/mod.rs:507-525`; `crates/pharos-kubernetes/src/object.rs:243-260` | **Deviation**: Pharos accepts one- or two-label source-cluster IDs and encodes each as a DNS label; CoreDNS v1.15.0 parses one cluster label (`plugin/kubernetes/parse.go`). Recorded in `docs/compatibility.md` (conf/k8s #103). | Yes |
| KEP-1645 §specification.md > 2.4.2 - `SRV` Records | `crates/pharos-plugins/src/kubernetes/mod.rs:1165-1180,301-315`; `crates/pharos-kubernetes/src/object.rs:255-260` | **Deviation**: Two-label source-cluster IDs are encoded as separate labels for SRV targets; CoreDNS v1.15.0 parses one cluster label (`plugin/kubernetes/parse.go`). Recorded in `docs/compatibility.md` (conf/k8s #103). | Yes |

## Kubernetes DNS spec

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §2 Resource Records | `crates/pharos-plugins/src/kubernetes/mod.rs:340-346, 547-554, 813-838, 1083-1097`; `crates/pharos-kubernetes/src/object.rs:193-221` | **Fixed**: Required ClusterIP records, tolerated unready endpoints, ExternalName chasing, and named-port SRV behavior are covered. Fixed on `conf/k8s` (#103). | No |
| §2.1 Definitions | `crates/pharos-kubernetes/src/object.rs:193-221` | **Fixed**: `service.alpha.kubernetes.io/tolerate-unready-endpoints=true` enables unready endpoint records. Fixed on `conf/k8s` (#103). | No |
| §2.3 Record for a Service with ClusterIP | `crates/pharos-plugins/src/kubernetes/mod.rs:547-554` | **Deviation**: `ignore empty_service` is accepted but is a no-op for ClusterIP/ClusterSetIP records. Recorded in `docs/compatibility.md` (conf/k8s #103). | Yes |
| §2.3.1 `A`/`AAAA` Record — IPv4 | `crates/pharos-plugins/src/kubernetes/mod.rs:547-554, 605-613, 1136-1158` | **Deviation**: `ignore empty_service` is accepted but does not suppress ClusterIP A records. Recorded in `docs/compatibility.md` (conf/k8s #103). | Yes |
| §2.3.1 `A`/`AAAA` Record — IPv6 | `crates/pharos-plugins/src/kubernetes/mod.rs:547-554, 605-613, 1136-1158` | **Deviation**: `ignore empty_service` is accepted but does not suppress ClusterIP AAAA records. Recorded in `docs/compatibility.md` (conf/k8s #103). | Yes |
| §2.3.2 `SRV` Records — unnamed ports | `crates/pharos-plugins/src/kubernetes/mod.rs:340-346, 1128-1203`; `crates/pharos-plugins/src/kubernetes/transfer.rs:241-255, 328-335` | **Deviation**: Unnamed Service ports produce no SRV records in queries or AXFR; this differs from CoreDNS. Recorded in `docs/compatibility.md` (conf/k8s #103). | Yes |
| §2.4 Records for a Headless Service | `crates/pharos-kubernetes/src/object.rs:193-221`, `crates/pharos-plugins/src/kubernetes/mod.rs:567-615` | **Fixed**: Headless Service records include unready endpoints when the tolerance annotation is set. Fixed on `conf/k8s` (#103). | No |
| §2.4.1 `A`/`AAAA` Records | `crates/pharos-kubernetes/src/object.rs:193-221`, `crates/pharos-plugins/src/kubernetes/mod.rs:567-615`, `crates/pharos-plugins/src/kubernetes/mod.rs:1128-1158` | **Fixed**: Unready endpoints are included when the Service tolerance annotation is set. Fixed on `conf/k8s` (#103). | No |
| §2.4.1 `A`/`AAAA` Records | `crates/pharos-kubernetes/src/object.rs:193-221`, `crates/pharos-plugins/src/kubernetes/mod.rs:804-810`, `crates/pharos-plugins/src/kubernetes/mod.rs:1128-1158` | **Fixed**: Annotated unready endpoints prevent false NXDOMAIN for A queries. Fixed on `conf/k8s` (#103). | No |
| §2.4.1 `A`/`AAAA` Records | `crates/pharos-kubernetes/src/object.rs:193-221`, `crates/pharos-plugins/src/kubernetes/mod.rs:378-407`, `crates/pharos-plugins/src/kubernetes/mod.rs:591-603` | **Fixed**: Hostname endpoint A records include tolerated unready endpoints. Fixed on `conf/k8s` (#103). | No |
| §2.4.1 `A`/`AAAA` Records | `crates/pharos-plugins/src/kubernetes/mod.rs:567-603`, `crates/pharos-plugins/src/kubernetes/mod.rs:1128-1158` | **Fixed**: Multiple IPv4 addresses for a hostname include tolerated unready endpoints. Fixed on `conf/k8s` (#103). | No |
| §2.4.1 `A`/`AAAA` Records | `crates/pharos-kubernetes/src/object.rs:193-221`, `crates/pharos-plugins/src/kubernetes/mod.rs:567-615`, `crates/pharos-plugins/src/kubernetes/mod.rs:1128-1158` | **Fixed**: Unready endpoints are included in AAAA answers when the annotation is set. Fixed on `conf/k8s` (#103). | No |
| §2.4.1 `A`/`AAAA` Records | `crates/pharos-kubernetes/src/object.rs:193-221`, `crates/pharos-plugins/src/kubernetes/mod.rs:804-810`, `crates/pharos-plugins/src/kubernetes/mod.rs:1128-1158` | **Fixed**: Annotated unready endpoints prevent false NXDOMAIN for AAAA queries. Fixed on `conf/k8s` (#103). | No |
| §2.4.1 `A`/`AAAA` Records | `crates/pharos-kubernetes/src/object.rs:193-221`, `crates/pharos-plugins/src/kubernetes/mod.rs:378-407`, `crates/pharos-plugins/src/kubernetes/mod.rs:591-603` | **Fixed**: Hostname endpoint AAAA records include tolerated unready endpoints. Fixed on `conf/k8s` (#103). | No |
| §2.4.1 `A`/`AAAA` Records | `crates/pharos-plugins/src/kubernetes/mod.rs:567-603`, `crates/pharos-plugins/src/kubernetes/mod.rs:1128-1158` | **Fixed**: Multiple IPv6 addresses for a hostname include tolerated unready endpoints. Fixed on `conf/k8s` (#103). | No |
| §2.4.2 `SRV` Records | `crates/pharos-kubernetes/src/object.rs:193-221`, `crates/pharos-plugins/src/kubernetes/mod.rs:567-603`, `crates/pharos-plugins/src/kubernetes/mod.rs:1159-1204` | **Fixed**: Named-port SRV records include tolerated unready endpoint/port combinations. Fixed on `conf/k8s` (#103). | No |
| §2.4.2 `SRV` Records | `crates/pharos-plugins/src/k8s_external/lookup.rs:125-147`, `crates/pharos-plugins/src/k8s_external/mod.rs:312-315` | **Deviation**: Unnamed EndpointSlice ports produce no SRV records, unlike CoreDNS. Recorded in `docs/compatibility.md` (conf/k8s #103). | Yes |
| §2.4.3 `PTR` Records | `crates/pharos-kubernetes/src/object.rs:193-221`, `crates/pharos-plugins/src/kubernetes/mod.rs:418-465` | **Fixed**: PTR responses include tolerated unready endpoints and visit endpoint records after ClusterIP matches. Fixed on `conf/k8s` (#103). | No |
| §2.4.3 `PTR` Records | `crates/pharos-kubernetes/src/object.rs:193-221`, `crates/pharos-plugins/src/kubernetes/mod.rs:418-465` | **Fixed**: PTR responses include tolerated unready IPv6 endpoints and visit endpoint records after ClusterIP matches. Fixed on `conf/k8s` (#103). | No |
| §2.5 Records for External Name Services | `crates/pharos-plugins/src/kubernetes/mod.rs:813-838`, `crates/pharos-plugins/src/kubernetes/mod.rs:1083-1097` | **Fixed**: ExternalName CNAMEs are returned for every QTYPE, including when target Self Lookup fails. Fixed on `conf/k8s` (#103). | Yes |
| §3 Schema Extensions | `crates/pharos-kubernetes/src/object.rs:193-221`, `crates/pharos-plugins/src/kubernetes/mod.rs:567-615` | **Fixed**: Tolerated unready endpoints are included and empty-service options do not suppress required ClusterIP data. Fixed on `conf/k8s` (#103). | No |

## Unmapped code

| Section | Code location | Explanation | Documented |
|---|---|---|---|
| — | `crates/pharos-corefile/src/parser.rs:358-364` | **Deviation**: Import patterns allow at most one `*` or `?` and reject bracket expressions, matching CoreDNS caddy v1.1.4 `caddyfile/parse.go` `doImport`. Recorded in `docs/compatibility.md` under ADR 0003 (conf/infra #105). | Yes |
| — | `crates/pharos-corefile/src/parser.rs:133-161` | **Deviation**: Environment expansion rejects cycles and stops at 10,000 replacements or 16 MiB, unlike CoreDNS's unbounded self-reference loop; `docs/compatibility.md` General records this difference, as ADR 0002 requires. | Yes |
| — | `crates/pharos-dnssec/src/keys.rs:90-176` | **Missing**: the inventory has no normative section for the BIND `.private` v1.2/v1.3 file grammar parsed here; cited algorithm RFCs provide examples, not a grammar specification. | No |
| — | `crates/pharos-plugins/src/auto/setup.rs:65-74` | **Deviation**: `directory` patterns use Rust regex syntax, including Unicode-aware `\d` and `\w`, rather than CoreDNS's Go RE2 syntax. The plugin README records this difference; no in-scope protocol document governs this configuration syntax. | Yes |
| — | `crates/pharos-plugins/src/autopath/mod.rs:26-57,106-125,164-267`; `crates/pharos-plugins/src/autopath/setup.rs:1-14` | **Deviation**: Configured search-path parsing and server-side suffix probing have no governing section in the in-scope standards. The README describes the CoreDNS-compatible extension and several intentional differences. | Yes |
| — | `crates/pharos-plugins/src/gotemplate/quote.rs:36-55` | **Unmapped**: Valid Go rune constants such as `'\xFF'` decode to a single byte, then fail UTF-8 conversion before the caller can consume the rune. The README documents this restriction for string literals, not rune constants. | No |
| — | `crates/pharos-plugins/src/kubernetes/name.rs:60-75` | **Unmapped**: The parser recognizes custom `pin`/`prefer` `_zone` query suffixes. KEP-2433 describes EndpointSlice topology hints, but no in-scope document defines this DNS query syntax or its selection semantics. | No |
| — | `crates/pharos-plugins/src/kubernetes/setup.rs:395-515` | **Fixed**: `key!=value` selectors and repeated-key conjunctions are accepted and applied. Fixed on `conf/k8s` (#103). | No |
| — | `crates/pharos-plugins/src/siit/mod.rs:136-140, 153-181, 192-234` | **Unmapped**: this plugin performs reverse synthesis: an IN A query with no A answer triggers an AAAA self-lookup, then maps matching AAAA answers to A. RFC 6147 defines the opposite DNS64 direction (AAAA from A); the `RFC 6147 §5.1` comment at line 136 therefore cites a section that does not govern this gate. The README identifies the behavior as a CoreDNS `siit` port. | No |
| — | `crates/pharos-plugins/src/timeouts/mod.rs:38-50`, `crates/pharos-server/src/tcp.rs:282-286` | **Unmapped**: `write` configures an application-level response-write deadline. No in-scope DNS section specifies this timeout. | Yes |
| — | `crates/pharos-plugins/src/view/mod.rs:9-33`, `crates/pharos-plugins/src/view/README.md:7-9` | **Unmapped**: Per-thread evaluation storage is capped at 65,535 bytes, so expressions needing more storage do not match. The README documents this limit and the CoreDNS difference; no in-scope protocol document governs it. | Yes |
| — | `crates/pharos-plugins/src/view/mod.rs:27-32` | **Unmapped**: A view matches only when every expression returns boolean `true`; evaluation errors and scratch-borrow conflicts also become non-matches. This is view-selection policy, not DNS protocol behavior, and the README does not document these failure semantics. | No |
| — | `crates/pharos-plugins/src/view/setup.rs:6-25` | **Unmapped**: Setup requires one view name and accepts only `expr` blocks. This is configuration grammar, not DNS protocol behavior; the README does not describe these constraints. | No |
| — | `crates/pharos-plugins/tests/functional/kubernetes_setup.rs:16-343` | **Unmapped**: Corefile option parsing, defaults, ranges, selector syntax, and startup timing are plugin configuration behavior; no in-scope protocol section governs them. | No |
| — | `crates/pharos-plugins/tests/functional/kubernetes_visibility.rs:110-205` | **Unmapped**: Zone-apex NS discovery and `ns.dns.<zone>` address answers bypass namespace visibility filters, while forward lookups remain filtered. No in-scope section specifies these discovery and visibility rules. | No |
| — | `crates/pharos-plugins/tests/functional/shed_setup.rs:33-47` | **Unmapped**: The test checks per-server-block UDP load shedding. DNS standards do not specify this admission policy. | No |
| — | `crates/pharos-plugins/tests/functional/template_behavior.rs:159-289`, `crates/pharos-plugins/src/template/mod.rs:30-31` | **Unmapped**: Tests pin the template expression/render scratch limit at 65,535 bytes. DNS RFCs do not specify this internal workspace limit; the plugin README documents the limit and SERVFAIL on exhaustion. | Yes |
| — | `crates/pharos-plugins/tests/functional/view.rs:8-30,37-78` | **Unmapped**: Tests assert CoreDNS-compatible view setup, expression-based routing, and fallback; no in-scope DNS section specifies this behavior. | Yes |
| — | `crates/pharos-plugins/tests/functional/view_filter.rs:27-64,67-143` | **Unmapped**: Tests assert view expression matching, scratch exhaustion, delegation, and CIDR filtering; no in-scope DNS section specifies these behaviors. | Yes |
| — | `crates/pharos-plugins/tests/functional/view_plugin_metrics.rs:44-124` | **Unmapped**: Tests assert view-specific ACL/cache metric labels and DS view inheritance; no in-scope DNS section specifies metric labeling. | No |
| — | `crates/pharos-plugins/tests/functional/view_routing.rs:13-51,57-188` | **Unmapped**: Tests assert client-IP CIDR view selection, fallback, and view-name metadata; no in-scope DNS document defines these plugin behaviors. The view README identifies the CoreDNS-compatible source. | Yes |
| — | `crates/pharos-plugins/tests/functional/view_routing.rs:190-232` | **Unmapped**: Tests assert view-specific Prometheus labels and counters; DNS specifications do not define these metrics. | No |
| — | `crates/pharos-plugins/tests/functional/whoami.rs:23-114`, `crates/pharos-plugins/src/whoami/mod.rs:7-20,24-97` | **Unmapped**: The plugin's diagnostic behavior—returning client IP and source port/protocol in Additional records for arbitrary queries—is not specified by DNS standards. The source comment and plugin README identify the behavior and CoreDNS origin. | Yes |
| — | `crates/pharos-server/src/router.rs:46-55,152-213`, `crates/pharos-server/src/server.rs:148-185` | **Unmapped**: View filters and metadata predicates select a ServerBlock by local policy; DNS specifications do not define this view-selection policy. | No |
| — | `crates/pharos-server/src/shed.rs:17-163` | **Unmapped**: The bounded newest-first queue evicts older deferred UDP responses under overload. DNS specifications permit UDP response loss but do not prescribe this queue or its eviction order. | No |
