# nomad

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/nomad/README.md)

## nomad

- Syntax matches CoreDNS v1.15.0: `nomad [ZONE] { address URL...; filter FILTER; token TOKEN; ttl SECONDS }`. `ZONE` defaults to `service.nomad` and only the first argument is read. The v1.15.0 plugin has no `fallthrough` property and takes one `ZONE`, not `ZONES...` as some issue text says; `fallthrough` is rejected as an unknown property.
