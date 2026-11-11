# Live zone parser oracle

The Rust integration test builds this module at test runtime, not during Cargo
builds. Its pinned miekg/dns revision is the same one used by the static corpus.
Set `PHAROS_MIEKG_DNS_DIR` to override it with a local checkout, or place a
checkout at `$HOME/projects/pharos-refs/miekg-dns`. If neither exists, Go uses
the pinned module from its cache or configured proxy. The test honors `GOPROXY`
and `GOSUMDB`, so `GOPROXY=off` works when dependencies are cached and fails
clearly otherwise. It sets `GOWORK=off` and `GOTOOLCHAIN=local` and requires Go
1.26 or later. Only a missing Go executable skips the test; an invalid explicit
checkout, dependency resolution failure, packing failure, or mismatch does not.

The oracle reads zone text from standard input, with an optional origin argument
(default `.`). It emits `accept` and uncompressed record fields, `reject`, or
`pack_error` plus the underlying error. `pack_error` means Go accepted the zone
but could not serialize one of its records; it is not a parser rejection. The
Rust differential test reports it separately and asserts that Rust rejects it,
because no wire record is available for comparison. Separate regressions cover
oversized TXT, invalid base64 and duplicate SVCB keys. Three missing-prior-owner
mutations are still compared and explicitly asserted: Go accepts and emits a
zero-byte owner, while
Rust rejects it because an absolute DNS owner must include a root label. The test
uses `--batch`: each request
is a big-endian u32 origin length and origin bytes followed by a big-endian u32
zone length and raw zone bytes. Each response is a u32 length and response bytes.
This preserves non-UTF-8 input and avoids launching a process for each case.

The packing format and reference sources are documented in
`../../corpus/zone-reference/README.md`; the oracle follows that corpus's
`generate.go` implementation using miekg/dns `NewZoneParser` and `PackRR`.
