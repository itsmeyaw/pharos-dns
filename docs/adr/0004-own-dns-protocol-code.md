# Pharos writes its own safe DNS protocol code

Pharos implements its own DNS protocol code (wire codec, names and compression, RR types, EDNS, zone-file parsing, TSIG, DNSSEC signing, Zone Transfer/NOTIFY/UPDATE helpers) with `#![forbid(unsafe_code)]`, using NLnet Labs' `domain` as the reference design. `domain` fits our needs best (zero-copy parsing, typed EDNS, signed zone files, BIND key files) but concentrates about 400 `unsafe` items in its network-facing parsing code, has had a soundness advisory (RUSTSEC-2026-0310) and has no fuzzing; `hickory` allocates on every decode and rejects DNSSEC records in zone files. Borrowed views over the Message buffer give the same zero-copy design in safe Rust.

## Considered Options

- `domain` as a dependency: rejected for its `unsafe` density on untrusted input.
- `hickory`: rejected for per-Query allocation and incomplete zone-file and EDNS support.
- Own codec on the hot path, `domain` for signing and zone files: rejected, zone files and transfers are untrusted input too.
- Forking `domain` to remove `unsafe`: rejected, a fork of a 0.x crate mid-rewrite is unmaintainable.

## Consequences

Correctness is on us. The codec is done only when it passes differential fuzzing against `domain` and `hickory` (test-only dependencies), RFC test vectors, ported `miekg/dns` and CoreDNS fixtures, and round-trip property tests, with fuzz targets running in CI. Code and tests derived from `domain`, `miekg/dns` and CoreDNS keep their notices in `THIRD_PARTY_NOTICES`. Every Pharos crate forbids `unsafe`; established dependencies (tokio, rustls, aws-lc-rs, quinn, hyper, nix, socket2, kube) may contain it.
