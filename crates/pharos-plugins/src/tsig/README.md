# tsig

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/tsig/README.md)

## tsig

- Zone Transfer streams are not yet available on this branch and therefore cannot be signed.
- The Listener rejects UPDATE before the Plugin Chain, as CoreDNS v1.15.0 does without an UPDATE handler; `require_opcode UPDATE` cannot yet authenticate UPDATE traffic.

## Sources

- [CoreDNS v1.15.0 `plugin/tsig`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/tsig)
