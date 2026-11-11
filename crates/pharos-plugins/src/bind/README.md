# bind

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/bind/README.md)

## bind

- Interface enumeration uses `getifaddrs`; scoped IPv6 Listener labels use the numeric interface index rather than CoreDNS's interface name.
- Unspecified addresses are labelled as unbound addresses.
- An unbound Listener and an explicit `bind ::` on the same port share one Listener. CoreDNS groups them separately, so its competing sockets can direct Queries to the wrong Server Block.
- Reload binds new Listeners before removing old ones, so switching between a wildcard and a specific address on the same port can fail rather than replacing the socket.

## Differential scenarios

The bind scenario compares Responses on 127.0.0.1 with an excluded IPv6 address;
the harness cannot send Queries to another bind address or scrape metrics.

## Sources

- CoreDNS plugin/bind/setup_test.go cases, with deterministic interface addresses.
- Derived from CoreDNS v1.15.0 plugin/bind/setup_test.go.

- [CoreDNS v1.15.0 `plugin/bind`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/bind)
- [CoreDNS v1.15.0 `plugin/sign/testdata`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/sign/testdata)
