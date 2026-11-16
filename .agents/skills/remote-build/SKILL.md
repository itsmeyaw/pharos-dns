---
name: remote-build
description: Run cargo build, test, clippy on a shared EC2 box instead of locally (local disk is limited). Not for benchmarks.
---

# Remote build

Never run `cargo` locally. Prefix every cargo command with `./.agents/skills/remote-build/scripts/remote.sh run` (`remote.sh` below). It rsyncs the current git worktree and runs the command remotely, with its own target dir per worktree, a shared `sccache`, and `mold`.

```
remote.sh run cargo nextest run -p <crate>
remote.sh run cargo clippy --workspace
```

All worktrees and subagents share one box.

## Steps

1. `remote.sh status`. If it reports no box, pick an instance type and run `remote.sh up <instance-type>`.
   - Size it for the parallel agents: about 4 vCPU and 8 GB RAM per agent building at once.
   - Ask the user if the type or architecture is unclear.
2. Run cargo through `remote.sh run …`. Done when the output shows the real result (pass or fail), not a connection error.
3. When the session's work is finished, `remote.sh down`. The box also self-terminates after 8h.

## Requirements

AWS CLI configured (region and profile via the usual env vars), a default VPC, and a key in the SSH agent (override with `REMOTE_BUILD_KEY`).
