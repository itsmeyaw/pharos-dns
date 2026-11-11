# loop

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/loop/README.md)

## loop

- The `loop` Plugin probes only the first Domain in a Server Block at startup and after Reload, as CoreDNS does.
- Fatal loop detection logs and exits immediately with status 1, without running Shutdown hooks or removing the pidfile, as CoreDNS's fatal logger does.
- Probe Queries may allocate while running concurrently with UDP reception; ordinary Queries do not.
- Like CoreDNS, a configured port 0 is probed as port 0 rather than the actual ephemeral Listener port.

## Differential scenarios

The `loop` scenario compares Responses for a non-looping configuration. The
looping README example is covered by a binary exit test instead: this harness
expects both processes to remain available and does not compare exit codes.

## Sources

- Derived from CoreDNS v1.15.0 plugin/loop/loop_test.go.
- Derived from CoreDNS v1.15.0 plugin/loop/setup_test.go.

- [CoreDNS v1.15.0 `plugin/loop`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/loop)
