# local

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/local/README.md)

## local

- Non-IN Questions pass through; CoreDNS emits this plugin's IN-class answers for them (RFC 1034 §4.3.1).
- Pharos sets AA on every intercepted local answer, including NXDOMAIN (RFC 1034 §4.3.2).
- Local NS and SOA MNAME use resolvable `localhost.`; SOA RNAME is `nobody.invalid.` (RFC 2181 §7.3; RFC 6303 §3).
- `localhost.` apex NS/SOA queries return negative NODATA responses; RFC 6761 §6.3 requires negatives for non-address QTYPEs.
- Serves the RFC 6303 reverse-zone catalogue (RFC 1918, special/documentation IPv4, and listed IPv6 zones) with AA and negative SOA data. The existing `1.0.0.127.in-addr.arpa.` PTR remains positive.
- `local { disable <zone>... }` disables selected RFC 6303 empty zones, allowing a later Plugin or explicit file Zone to answer.
- The localhost interception debug log can be enabled through the process logging API; the `debug` Directive is not implemented yet. Unlike CoreDNS, logged Query names retain their original case.
- UDP callers must supply a sufficiently large Response buffer.
- DNS names are matched as wire labels with ASCII case folding, rather than CoreDNS's lowercased presentation strings.

## Differential scenarios

The `local` README and prefix-off scenarios use `whoami` as Next to compare
both intercepted Queries and those passed through.

## Sources

- [CoreDNS v1.15.0 `plugin/local`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/local)
