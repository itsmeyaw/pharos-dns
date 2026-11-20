# https

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/https/README.md)

## https

- `https://` Server Block Keys (default port 443) serve DNS over HTTPS (RFC 8484) and require the `tls` Directive. `https { max_connections N; max_streams N }` is supported and may appear once per Server Block.
- `max_connections` defaults to 200 and `0` means unlimited. `max_streams` defaults to 250 and `0` keeps the HTTP/2 library default (hyper: 200 streams, unlike Go's 250 default for the zero value). Connections over the limit wait in the kernel accept backlog, as with Go's `netutil.LimitListener`.
- When Server Blocks share one `https://` Listener the first block's `max_connections` applies, and blocks that set `max_streams` must agree, otherwise setup fails with `conflicting max_streams values for shared HTTPS listener`. They must also share one TLS identity, client authentication policy and client CA pool.
- The Listener negotiates `h2` and `http/1.1` through ALPN. Only the path `/dns-query` is served; any other path gets 404.
- `GET` takes the Query from a single base64url `dns` parameter (padding rejected) and `POST` from the request body. A request `Content-Type` is not checked, as in CoreDNS, so RFC 8484 §4.2.1 status 415 is never sent; a body that is not a DNS Query is answered with 400. Methods other than GET and POST get 400 (CoreDNS), not RFC 9110's 405. Queries over 65,536 octets get 400 (CoreDNS's limit; RFC 8484 §6 says 65,535). A GET target is capped at 64 KiB by the HTTP parser, below the 87,382-character `dns` value CoreDNS's size check allows. The `dns` parameter name and value are matched without percent-decoding.
- A Query is accepted under miekg/dns' default accept policy (opcode QUERY or NOTIFY, one Question, at most one Answer, Authority and two Additional records); anything else is answered with 400.
- Responses carry `Content-Type: application/dns-message` and `Cache-Control: max-age=N`, with N the lowest record TTL capped at 3600 seconds (SOA `MINIMUM` is not consulted, as in CoreDNS); error and empty responses use 5 seconds. If the Plugin Chain gives no Response the status is 500.
- Plain-text error bodies follow Go's `http.Error` (`Content-Type: text/plain; charset=utf-8`, `X-Content-Type-Options: nosniff`).
- Statuses are counted in `pharos_dns_https_responses_total{server,status}`.
- The client address is the TCP peer; `proxyproto` applies to the TCP peer (`proxyproto-https`); `X-Forwarded-For` is not used.
- The TCP `read` timeout bounds the TLS handshake, HTTP/1.1 request head and request body, `write` bounds the graceful close, and `idle` closes connections with no request in flight (see `timeouts`).
- A Reload that changes `max_connections` counts connections of the old limit separately until they close, so the total can briefly exceed either limit. Pharos has no listener-wide byte budget: worst case memory is `max_connections` × `max_streams` × the 64 KiB message limit, as in CoreDNS.
- Pharos has no per-IP rate or in-flight limit beyond `max_connections` and `max_streams`.

## Sources

- [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484)
- [CoreDNS v1.15.0 `plugin/https`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/https)
- [CoreDNS v1.15.0 `core/dnsserver/server_https.go`](https://github.com/coredns/coredns/tree/v1.15.0/core/dnsserver/server_https.go)
- [CoreDNS v1.15.0 `plugin/pkg/doh`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/pkg/doh)
