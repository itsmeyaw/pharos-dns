# One folder per Plugin inside one crate

CoreDNS gives each Plugin its own Go package and README. Pharos keeps every Plugin in the `pharos-plugins` crate but gives each one its own folder, `crates/pharos-plugins/src/<plugin>/`, holding `mod.rs` (behaviour), `setup.rs` (Corefile parsing) and `README.md`. The README holds only what is Pharos-specific: deviations from CoreDNS, README examples skipped by the differential harness and why, and the CoreDNS or miekg/dns sources its code and tests derive from. Syntax and behaviour that match CoreDNS are not repeated; the README links to the CoreDNS README of the baseline tag. `docs/compatibility.md` keeps the General, Server and zone-file sections and becomes an index of per-Plugin READMEs. Shared parsing helpers stay in `lib.rs`; per-Plugin parsing moves out of it.

Integration tests are grouped the same way: one test binary for functional tests with a module per Plugin, and one for allocation tests, which need a process-wide counting allocator and therefore run serialized. The default feature list in `crates/pharos-plugins/Cargo.toml` is written one feature per line.

## Considered Options

- One crate per Plugin, as CoreDNS has one package per Plugin: rejected. Cargo features already compile Plugins in or out, and the `plugin.cfg` generator would have to map 62 crates; cross-Plugin use (`autopath` on `kubernetes`, Self Lookup users, `metadata` readers) and shared setup helpers would become crate edges plus a common crate. The gain, parallel compilation, is not a bottleneck.
- Keep the current mix (single files, folders, and both for one Plugin; per-Plugin notes in shared files): rejected. Parallel Plugin branches conflict on every merge in `docs/compatibility.md`, `tests/differential/README.md`, the default feature list and `lib.rs`, and 72 test binaries each link the crate, costing disk and link time.

## Consequences

Adding a Plugin creates one folder plus its feature, `plugin.cfg` entry and generator mapping (ADR-0005); notes for one Plugin are edited in one place. `THIRD_PARTY_NOTICES` stays the single legal notice file at the repository root. Allocation tests must not run in parallel with each other.
