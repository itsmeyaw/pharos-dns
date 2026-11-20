# quic

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/quic/README.md)

## quic

- `quic { max_streams N; max_connections N; worker_pool_size N }` configures `quic://` Listeners. Defaults match CoreDNS: 256 streams per connection, 200 connections (`0` removes the limit) and 1024 concurrent stream workers.

## Sources

- [CoreDNS v1.15.0 `plugin/quic`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/quic)
