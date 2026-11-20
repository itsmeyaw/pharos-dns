# proxyproto

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/proxyproto/README.md)

## proxyproto

- `proxyproto { allow CIDR... ; default use|ignore|reject|skip ; udp_session_tracking DURATION [MAX_SESSIONS] ; tlv_metadata }` is supported with CoreDNS's defaults: without `allow` and `default`, every peer's header is used; without `default`, peers outside `allow` are ignored; `MAX_SESSIONS` defaults to 10240. A zero or negative `DURATION` disables session tracking. `proxyproto` is configured once per Server Block; when Server Blocks share a Listener, the last one that configures it wins, as in CoreDNS.
- The Directive is configuration only. The Listener reads the PROXY header (v1 and v2) as soon as a TCP connection is accepted, before the TLS handshake of a `tls://` Listener and before the first DNS frame of a `dns://` Listener, and replaces the peer address of every Query on that connection. A `LOCAL` command and v1 `UNKNOWN` keep the connection's own address. The header must complete within 10 seconds, the go-proxyproto default CoreDNS relies on; the timeout is not configurable. A header is bounded to 107 octets (v1) or 4096 octets of payload (v2), and the parser never reads past the header into the DNS stream.
- Under `use` and `ignore` a connection or datagram without a header is served normally with its own address (go-proxyproto `USE` and `IGNORE`); under `reject` only a header is refused; under `skip` Pharos does not look for a header at all, so the header's bytes reach the application protocol.
- UDP datagrams carry a v2 header with the DGRAM protocol, removed from each datagram that starts with one. A malformed header, a v1 header, a stream-protocol header or a truncated header drops that datagram only. With `udp_session_tracking` the header-only first datagram of a Cloudflare Spectrum flow opens a session keyed by the Spectrum-side address, and later headerless datagrams from it take the cached client address and TLVs until the session has been idle for `DURATION`. A header-only datagram is never delivered as a Query.
- `tlv_metadata` publishes the hex TLV vector of the connection's (or UDP session's) v2 header as the `proxyproto/tlv` Metadata label. It is visible only in Server Blocks that enable `metadata` (and for the zones `metadata` lists) and only when the header carried TLVs; `view` expressions can read it with `metadata('proxyproto/tlv')`.
- `https://`, `grpc://`, `quic://` and `https3://` Listeners do not exist yet. Their accept loops are expected to call `pharos_server::proxyproto::Config::accept_stream` on each accepted TCP stream before TLS or HTTP reads it, and `accept_datagram` on each received datagram before QUIC reads it; `Handler::proxyproto` returns the Listener's `Config`, and `Handler::handle_proxied` carries the TLVs to the Plugin Chain.

## Differences from CoreDNS

- A header-only UDP datagram is dropped under every policy; CoreDNS delivers an empty datagram unless `udp_session_tracking` is set.
- The session cache is a bounded LRU like CoreDNS's, but each UDP worker holds its own share: `MAX_SESSIONS` divided by the worker count, rounded up. The kernel hashes a flow to one worker, so a flow keeps its session. Sessions survive a Reload; the capacity of a worker is fixed when the worker first needs it.
- A v2 header with the UNIX address family is rejected; go-proxyproto accepts it and CoreDNS then reports a UNIX address as the client.
- While a worker holds 256 Queries in flight, datagrams it inspects to find forwarding-loop probes are not parsed for PROXY headers, so a Spectrum header-only datagram received during that overload is lost and its flow stays unmapped until the next header.
- Reload applies new `allow`, `default`, `tlv_metadata` and `udp_session_tracking` TTL values to connections and datagrams accepted afterwards; established connections keep the peer address and TLVs they were accepted with.
- go-proxyproto's `REQUIRE` policy has no Directive option and is not offered.
- The `plugin/pkg/proxyproto` tests for `TLVListener`, `Addr` and the miekg/dns `ResponseWriter` boundary are not ported: Pharos passes the address and TLVs to the Handler directly. The TLV encoding, the session cache and the packet-header cases are ported as Rust unit tests in `pharos-server`.

## Sources

- [CoreDNS v1.15.0 `plugin/proxyproto`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/proxyproto)
- [CoreDNS v1.15.0 `plugin/pkg/proxyproto`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/pkg/proxyproto)
- [PROXY protocol specification](https://www.haproxy.org/download/2.3/doc/proxy-protocol.txt)
- [go-proxyproto v0.15.0](https://github.com/pires/go-proxyproto/tree/v0.15.0)
