# cancel

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/cancel/README.md)

## cancel

- On expiry Pharos drops the Next future and the Response. CoreDNS only signals context cancellation, so Plugins that ignore the context may continue and write a Response.
