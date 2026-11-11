# chaos

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/chaos/README.md)

## chaos

- The default version is `Pharos-<version>` and the default authors are Pharos authors rather than CoreDNS's identity (ADR-0003).
- The hostname is captured at setup, not on each Query; changing the system hostname requires Reload.
- Author records use a different per-second shuffle generator than CoreDNS, so their order and the subset in a truncated Response can differ; simultaneous `authors.bind` Queries share a lock.
- An overlong version with explicit authors produces a Plugin error and SERVFAIL rather than CoreDNS's failed write; UDP callers must supply a sufficiently large Response buffer, as with `whoami`.
- When building a Response with many authors, Pharos truncates to the Query's limit before Listener processing; CoreDNS builds the full Response first. Plugins earlier in the chain can therefore observe a truncated Response.

## Differential scenarios

The two `chaos` README scenarios configure the same explicit identity on both
servers; default identity differences are covered by Rust tests instead.
