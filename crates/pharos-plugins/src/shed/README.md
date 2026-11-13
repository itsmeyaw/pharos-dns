# shed

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/shed/README.md)

## shed

- Rust does not have Go's per-socket fdMutex limit. Pharos uses a single UDP writer with a 1,024-response newest-first stack and tracks query and response drops.
- Each socket reserves 1,026 full-size UDP Response buffers at startup (about 64 MiB of address space), rather than allocating each queued Response as CoreDNS does.
- Each Pharos UDP worker handles up to 256 waiting ordinary Queries concurrently. When capacity or Response buffers are exhausted, one ordinary Query waits and later ordinary datagrams can be dropped without a shed counter; forwarding-loop probes remain serviceable. Enabling shed uses the portable UDP path instead of Linux's batched receive path.
- Toggling `shed` on Reload replaces UDP workers; while old sockets drain, a datagram can be delivered to a retiring worker and lost.
- The README differential scenario substitutes a local Upstream for 8.8.8.8 and uses one socket for determinism.

## Sources

- [CoreDNS v1.15.0 `plugin/shed`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/shed)
