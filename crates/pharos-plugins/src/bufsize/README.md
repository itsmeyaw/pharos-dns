# bufsize

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/bufsize/README.md)

## bufsize

- When forwarding a Query with a compression pointer into the OPT CLASS bytes, Pharos rewrites those bytes in the original encoding; CoreDNS re-encodes the decoded Message and preserves the pointed-to name.

## Differential scenarios

The `bufsize` README scenarios use a local `whoami` Upstream instead of the
example's external resolver. `bufsize-file-readme` uses the documented `file`
backend. They compare Responses for both UDP and TCP, with and without EDNS.

## Sources

- [CoreDNS v1.15.0 `plugin/bufsize`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/bufsize)
