# multisocket

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/multisocket/README.md)

## multisocket

- With `multisocket` and no argument, Pharos uses that same worker count rather than Go's GOMAXPROCS, and does not honor the `GOMAXPROCS` environment variable.
- Pharos always uses one TCP listening socket per Listener; CoreDNS opens one per configured server. These differences affect performance, not Responses.
- Changing the UDP count on Reload briefly stages new reuseport sockets before replacing the old ones; Queries arriving during staging or rollback can be lost.

## Sources

- CoreDNS v1.15.0 plugin/multisocket/multisocket_test.go.

- [CoreDNS v1.15.0 `core/dnsserver/register.go`](https://github.com/coredns/coredns/tree/v1.15.0/core/dnsserver/register.go)
- [CoreDNS v1.15.0 `plugin/multisocket`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/multisocket)
