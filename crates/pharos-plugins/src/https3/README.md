# https3

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/https3/README.md)

## https3

- `https3 { max_streams N; max_connections N }` configures `https3://` Server Blocks, which need a `tls` Directive and listen on UDP port 443 by default. Defaults and validation match CoreDNS: 256 streams per connection and 200 connections (`0` removes the limit). Each value may be set once, and `https3` may appear once per Server Block.

## Sources

- [CoreDNS v1.15.0 `plugin/https3`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/https3)
