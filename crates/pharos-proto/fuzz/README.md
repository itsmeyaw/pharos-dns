# Protocol fuzzing

Install the nightly Rust toolchain and `cargo-fuzz` (`cargo install --locked cargo-fuzz`).
Run `cargo xtask fuzz --short` for 60 seconds per target, or `cargo xtask fuzz` until interrupted. Targets run concurrently. The command copies the checked-in `.bin` Message fixtures into each writable `crates/pharos-proto/fuzz/corpus/` directory without modifying the originals.

On Apple Silicon the runner disables AddressSanitizer because the installed nightly runtime hangs at startup; other platforms retain cargo-fuzz's default sanitizer.

This is a separate workspace excluded from the Pharos unsafe-code gate: libFuzzer generates instrumented code and artifacts that are not Pharos source. Pharos crates remain subject to that gate.

The round-trip target compares raw RDATA bytes, not the meaning of compressed names inside RDATA, because the builder cannot relocate arbitrary opaque RDATA. The differential target compares parse results, section boundaries and fields, except where domain accepts forward or overlapping pointers or longer pointer chains.
