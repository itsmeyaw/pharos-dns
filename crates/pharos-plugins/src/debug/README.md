# debug

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/debug/README.md)

## debug

- Pharos disables panic containment on all Listeners when any Server Block enables `debug`; CoreDNS disables it for the Listener that includes that block, while debug logging is process-wide.
- An uncontained Rust panic terminates its Tokio task rather than necessarily terminating the process as an unhandled Go goroutine panic does. The `errors` Plugin does not add panic recovery, matching CoreDNS v1.15.0 despite its debug README.
- Debug logging is enabled after Listeners start and is reset when a Reload without `debug` succeeds; CoreDNS enables it when constructing its Listener and does not clear its global flag on Reload.
