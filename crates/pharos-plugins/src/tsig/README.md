# tsig

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/tsig/README.md)

## tsig

- This Plugin is incomplete and is not enabled by default. Do not use it for authentication yet.
- Earlier Plugins can modify a Response after this Plugin signs it. For example, `nsid` removes the TSIG when adding its option. Signing must be deferred until all Response modifications and Listener finalization are complete.
- Zone Transfer streams are not yet available on this branch and therefore cannot be signed.
- Not all CoreDNS setup, error, or differential cases have been ported or checked.

## Sources

- [CoreDNS v1.15.0 `plugin/tsig`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/tsig)
