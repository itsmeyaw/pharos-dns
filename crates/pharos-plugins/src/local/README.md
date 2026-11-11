# local

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/local/README.md)

## local

- The localhost interception debug log can be enabled through the process logging API; the `debug` Directive is not implemented yet. Unlike CoreDNS, logged Query names retain their original case.
- UDP callers must supply a sufficiently large Response buffer.
- DNS names are matched as wire labels with ASCII case folding, rather than CoreDNS's lowercased presentation strings.

## Differential scenarios

The `local` README and prefix-off scenarios use `whoami` as Next to compare
both intercepted Queries and those passed through.

## Sources

- [CoreDNS v1.15.0 `plugin/local`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/local)
