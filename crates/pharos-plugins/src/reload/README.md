# reload

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/reload/README.md)

## reload

- Like CoreDNS, HTTP Listeners close and reopen on Reload; probes and scrapes can briefly fail, and re-opening an old Listener can fail if another process takes its port.
- DNS Listeners with unchanged keys and UDP counts keep their sockets.
- New Listeners are bound before existing handlers are swapped; separate Listeners are swapped individually rather than in one process-wide atomic operation.
- Pharos hashes a canonical representation of parsed, import-expanded Server Blocks instead of CoreDNS's JSON encoding, so the hash values differ.
- Pharos omits source paths and absolute line numbers from the hash; CoreDNS includes them, so adding comment lines can trigger Reload in CoreDNS but not Pharos.
- Line boundaries that affect Directive argument grouping are retained.
- The last attempted hash is reported even when a Reload fails, as in CoreDNS.
- Candidate setup can register metric series before a failed Reload is rolled back.
- Shutdown waits for Queries on replaced states to finish, so a stuck Query can delay processing subsequent signals.

## Differential scenarios

The Reload README scenarios use `whoami` instead of the unimplemented `erratic`
backend and compare DNS Responses rather than reload timing.

## Sources

- Derived from CoreDNS v1.15.0 plugin/reload/setup_test.go.

- [CoreDNS v1.15.0 `plugin/reload`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/reload)
