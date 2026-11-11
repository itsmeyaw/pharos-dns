# CoreDNS file-plugin zone corpus

These fixtures originate in CoreDNS v1.15.0, revision
`a6fde3fe339c6ec848447e11cc9796be8c97b4e0`, copyright 2016–2020
The CoreDNS authors and contributors, Apache-2.0. See the repository's
`LICENSE` and `THIRD_PARTY_NOTICES`.

Each `.zone` is named after its original constant, except for the inline and
templated cases listed below. Sources are relative to `plugin/file/`:

| Source | Fixtures |
| --- | --- |
| `alias_delegation_test.go` | `dbAliasDelegation` |
| `apex_test.go` | `exampleApexOnly` |
| `delegation_test.go` | `dbMiekNLDelegation` |
| `dname_test.go` | `dbMiekNLDNAME`, `dbExampleDNAMESigned` |
| `dnssec_test.go` | `dbMiekNLSigned` |
| `dnssex_test.go` | `dbDnssexNLSigned` |
| `ent_test.go` | `dbMiekENTNL` |
| `escape_test.go` | `dbEscapeOwner` |
| `file_test.go` | `dbNoSOA`, `dbSyntaxError`, `dbMalformedSOA`, `dbSOASerialTooLarge`, inline `laterSOAOrigin` |
| `glue_test.go` | `dbAtoomNetSigned` |
| `include_test.go` | inline `includeZone` |
| `lookup_test.go` | `dbMiekNL`, `dbAdditionalExample`, `dbExampleOrgOutOfZone` |
| `nsec3_test.go` | `nsec3paramTest`, `nsec3Test` |
| `reload_test.go` | `reloadZoneTest`, `reloadZone2Test` |
| `setup_test.go` | `dbRelative`, `dbRelativeNet`, `setupSOARelative`, `setupSOAAt`, `setupSOAAbsolute` |
| `svcb_test.go` | `dbMixedCase`, `dbSVCBExample` |
| `wildcard_test.go` | `exampleOrg`, `apexWildcard`, `doubleWildcard`, `dbWildcardAdditional`, `closerENTWildcard`, `emptyNonTerminalWildcard` |

`dbRelativeNet` repeats `dbRelative` using its other test origin. The three
`setupSOA*` files instantiate the upstream `fmt.Sprintf` template with `test`,
`@`, and `test.`. `includeZone` replaces the generated temporary filename with
`child.zone`; this checks default disabled-include rejection, not included-file
parsing. `exampleOrgSigned` from `example_org.go` is already covered by
`../zone-reference/coredns.zone`.

Origins in `manifest.rs` follow the upstream test usages; undotted
`miek.nl` in `nsec3_test.go` is normalized to `miek.nl.`. The checked-in
`.expected` files are generated with the existing Go oracle and miekg/dns
revision `b2d6c9f4480a71247e0df4ce709122852a2849cf` (BSD-3-Clause; see
`../zone-reference/MIEKG-LICENSE`). `accept` is followed by tab-separated,
uncompressed owner wire hex, TTL, class, type, and RDATA wire hex; `reject`
means the parser failed. These are parser outcomes, not CoreDNS zone-validation
outcomes: for example, `dbNoSOA` and NSEC3 fixtures parse successfully.
Both the offline fixture tests and live miekg differential test use the same
manifest; the live test reads each checked-in zone and compares it to the oracle.

To regenerate with local checkouts and cached Go dependencies, run:

```sh
python3 crates/pharos-proto/tests/corpus/zone-coredns/generate.py /path/to/coredns /path/to/miekg-dns
```

The generator disables Go network/module updates and stops on parser/packing
protocol errors; the Rust tests require neither Go nor the reference checkouts.
