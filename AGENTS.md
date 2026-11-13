## Development

- Use `caveman` skill, including for subagents.
- Use `caveman-commit` skill for commit message.
- Use `code-review` skills for review.
- Use `rust-*` skills for implementation and test.
- Commit in small functional changes.
- Always add one-line comment citation to the standard for a logic. For example: `RFC 1034 §4.3.2: xxxxx`.

## Performance Focus

These are the target performance focus, ranked from top to bottom:

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
