# on

[coredns/caddy v1.1.4 `onevent`](https://github.com/coredns/caddy/tree/v1.1.4/onevent) (the `on` Directive in CoreDNS v1.15.0 `plugin.cfg`; CoreDNS has no README for it)

## on

- **Security:** the command comes only from the Corefile, a trusted source, and runs with Pharos's privileges. Pharos starts it directly, never through a shell, and never puts Query data, names or addresses in its command line or environment. Shell metacharacters in the Corefile stay literal arguments unless you name a shell yourself (`on startup sh -c '...'`).
- Events are the three that coredns/caddy v1.1.4 accepts: `startup`, `shutdown` and `certrenew`. The names `restart`, `restart-failed`, `instance-startup` and `instance-restart` are rejected, as in CoreDNS.
- `startup` fires once the instance is live (CoreDNS `InstanceStartupEvent`): at process start after the Listeners are installed, and on every successful Reload after the retired Listeners have drained and the old instance's shutdown hooks have run. A failed Reload never fires it.
- `shutdown` fires once when the process stops. A Reload does not fire it, as in CoreDNS, where the event comes from the termination signal handler only.
- `certrenew` is accepted but never fires: CoreDNS v1.15.0 defines the event and nothing emits it, and Pharos does the same.
- Arguments are joined with spaces and split again shell-style (quotes, backslash escapes and `#` comments), as CoreDNS does with go-shlex; a trailing `&` argument means non-blocking.
- Pharos never makes Query serving or Reload wait for a command. CoreDNS runs a blocking command inline, so a hung command stalls the event; Pharos runs `startup` commands, blocking or not, in the background, and several of them run concurrently rather than one after another. A blocking command's non-zero exit status, or a failure to start, is logged as an error; for `&` commands only a failure to start is.
- `shutdown` waits for a blocking command, as CoreDNS does, but for at most five seconds; then Pharos kills it, logs an error and goes on. `shutdown` commands ending in `&` are not waited for and may be cut short by process exit.
- A blocking `startup` command that is still running when its instance stops (Reload or process exit) is killed and reaped; CoreDNS has no such bound, so a hung command would stall its event forever. A `startup` command ending in `&` is left running, as in CoreDNS, which never waits for or stops it; it may outlive Reload and process exit.
- CoreDNS logs a random ID per hook; Pharos logs the command line instead.

## Differential scenarios

None: `on` changes no DNS Response, so there is nothing to compare with CoreDNS. Process-level tests in `crates/pharos/tests/on.rs` cover each event around startup, Reload and shutdown.

## Sources

- Derived from coredns/caddy v1.1.4 `onevent/on_test.go`, `onevent/hook/hook_test.go` and `onevent/on.go`.
- The command splitter ports flynn/go-shlex (Apache-2.0) `shlex.go`, with tests from `shlex_test.go`.
