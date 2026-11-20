## Project Structure

Cargo workspace (`crates/*` + `xtask`, `crates/pharos-proto/fuzz` is excluded).

- `crates/pharos` - binary: the DNS server compatible with CoreDNS Corefiles.
- `crates/pharos-corefile` - Corefile lexer and parser.
- `crates/pharos-proto` - DNS wire format, names, records, zone files, TSIG, EDNS. Has `benches/` and `fuzz/`.
- `crates/pharos-server` - listeners, Plugin Chain contract, metrics.
- `crates/pharos-plugins` - CoreDNS-compatible Plugins, one folder per Plugin (ADR 0007). Order in `plugin.cfg`.
- `crates/pharos-kubernetes` - Kubernetes API client used by the `kubernetes` Plugin.
- `crates/pharos-dnssec` - DNSSEC signing.
- `crates/pharos-kv` - small durable ordered key-value store.
- `xtask/` - dev automation, including `e2e/`.
- `tests/` - `differential/` (vs CoreDNS) and `fixtures/`.
- `deploy/kubernetes/` - Kubernetes manifests. `Dockerfile` at the root.
- `docs/` - `adr/` (decisions), `agents/` (agent skill config), plus `benchmarks.md`, `compatibility.md`, `conformance.md`.
- Root: `GLOSSARY.md` (domain terms), `CODING_STANDARDS.md`, `MIGRATION.md`, `deny.toml`, `rust-toolchain.toml`.

Each crate follows `src/` (code), `tests/` (integration tests), and `CHANGELOG.md`.

## Development

- Use `caveman` skill, including for subagents.
- Use `caveman-commit` skill for commit message.
- Use `code-review`, `rust-best-practices`, and `rust-perf` skills for review.
- Use `rust-*` skills for implementation and test.
- Commit in small functional changes.
- Always add one-line comment citation to the standard for a logic. For example: `RFC 1034 §4.3.2: xxxxx`.
- Use `implement` skills for implementation.
- Use `caveman-commit` skill for a PR title and `pr` skill for writing the PR body.

## Performance Focus

These are the target performance focus, ranked with 1 highest and 6 lowest:

1. Tail Latency (p99 and p99.9) Under Burst Load and Churn
2. Memory Footprint and OOM Resilience at High Cluster Scale
3. Negative Caching and Upstream Forwarding Throughput Under `ndots` Amplification
4. Watch-to-Serve Propagation Latency During Pod Rollouts
5. Binary Size and Cold-Start Time for Unified Node-Local Deployment
6. Peak Single-Core Throughput (Raw Cached QPS)

## Agent skills

### Issue tracker

Issues live in GitHub Issues for `itsmeyaw/pharos-dns` (via the `gh` CLI). See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.
