# tls

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/tls/README.md)

## tls

- `tls CERT KEY [CA]`, `client_auth nocert|request|require|verify_if_given|require_and_verify` and `keylog FILE` are supported. Relative paths resolve against `root`, as in CoreDNS.
- The `tls` Directive serves `tls://` Server Block Keys (default port 853). `tls` also serves `quic://` Server Blocks (default port 853; see `quic`), `https://` Keys (see `https`) and `grpc://` Keys (default port 443; see `grpc_server`). `https3://` Keys are served the same way (see `https3`).
- A `tls://`, `https://`, `grpc://`, `quic://` or `https3://` Server Block without a `tls` Directive fails setup, as in CoreDNS. A `tls` Directive in a plain-DNS Server Block is loaded and validated but not used.
- The minimum protocol version is TLS 1.2. Pharos uses rustls with the aws-lc-rs provider; CoreDNS uses Go's `crypto/tls`, so cipher-suite preference order and supported curves follow rustls rather than Go. TLS 1.3 session tickets use a rotating stateless ticketer.
- `tls { acme DOMAIN... }` obtains and renews certificates over ACME ([RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)) with the DNS-01 challenge; see [ACME](#acme). A `tls` Directive without arguments must have that block.
- Certificates are read at startup and on every Reload. An invalid or unreadable file fails startup or the Reload (the previous configuration stays active). New connections after Reload use the new certificate on the same Listener; established connections keep their session. Replacing a certificate file alone does not trigger a Reload (as in CoreDNS); send SIGUSR1 or change the Corefile.
- Server Blocks that share a Listener must have the same TLS identity, client authentication policy and client CA pool; otherwise setup fails with `conflicting TLS configuration for shared listener`.
- `client_auth request` and `client_auth require` accept any presented client certificate without verifying its chain, like Go's `RequestClientCert` and `RequireAnyClientCert`. The handshake signature is still verified. `verify_if_given` and `require_and_verify` use `CA`, or the system trust store when `CA` is omitted.
- `keylog FILE` appends NSS Key Log lines and logs a warning at startup; as in CoreDNS, mode 0600 applies only when the file is created and the file is opened once per load. rustls cannot report a failed key-log write, so Pharos drops it silently where CoreDNS fails the handshake.
- A client that does not complete the TLS handshake within the TCP read timeout (default 3 seconds, see `timeouts`) is disconnected. The `timeouts` Directive and `max_queries` apply to DNS over TLS like TCP.
- `server_tls_test.go` cases for the gRPC Transport are covered by the `grpc_server` interop tests, which use the test CA and ALPN `h2`.

## ACME

```
tls {
    acme DOMAIN...
    email ADDRESS
    ca URL
    storage PATH
    ca_root PATH
    resolver HOST:PORT
}
```

- `acme` lists the names (at least one; `*.` wildcards allowed, no IP addresses or internationalised names) and is required. Every other option is optional and may appear once: `email` is the account contact, `ca` the ACME directory (default Let's Encrypt production, `https://acme-v02.api.letsencrypt.org/directory`; `http` is accepted for private test CAs), `storage` the directory for account keys and certificates (default `.coredns/acme` below `root`), `ca_root` a PEM bundle trusted in addition to the system roots when talking to the CA, and `resolver` a DNS server (`HOST:PORT`) that must show the challenge record before the CA is asked to validate it. Relative paths resolve against `root`.
- Only DNS-01 is implemented. Pharos answers the `_acme-challenge` TXT Query itself: every Server Block answers it once any Server Block uses ACME, from the `tls` position after `dnssec` in the Plugin Chain, with TTL 0 and AA set. Wildcard names are validated at the base domain.
- Each name gets its own certificate and P-256 key. Stored certificates are served immediately at startup; missing ones are obtained once the Listeners are up, so TLS handshakes for a name fail until its first certificate exists. Issued and renewed certificates reach new handshakes without a Reload. Renewal starts when a third of the lifetime is left and is checked every 10 minutes; failures retry after 1, 2, 5, 10, 20 and 40 minutes, then 1, 2, 3 and 6 hours (certmagic defaults).
- Blocks with equivalent ACME options (domain order ignored) share one entry and one identity; a domain configured with different options in two blocks fails setup.
- The client is Pharos's own minimal RFC 8555 implementation (JWS ES256 through aws-lc-rs). Not implemented: other challenge types, ACME Renewal Information (RFC 9773), External Account Binding, OCSP stapling, ECDSA curves other than P-256, internationalised names and IP identifiers. The `storage` layout is Pharos's own (`<storage>/<ca>/accounts/<email>.key`, `<storage>/<ca>/certificates/<name>/{certificate,key}.pem`) and not interchangeable with certmagic's. A `resolver` must answer over UDP. When polling, `Retry-After` is honoured as delay-seconds or an IMF-fixdate (RFC 9110 §5.6.7) and bounded to 1–30 s; the obsolete RFC 850 and asctime date forms are deliberately not parsed (RFC 9110 §5.6.7 marks them obsolete and forbids senders to generate them, so ACME CAs do not send them), so, like an absent or unparsable value, they poll after 1 s.
- Tests run against a local stub ACME server that verifies every JWS and nonce, not Pebble; interoperability with a real CA is untested.

## Sources

- [CoreDNS v1.15.0 `plugin/tls`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/tls)
- [RFC 8555: Automatic Certificate Management Environment](https://www.rfc-editor.org/rfc/rfc8555)
- [CoreDNS v1.15.0 `core/dnsserver/tlsconfig.go`](https://github.com/coredns/coredns/tree/v1.15.0/core/dnsserver/tlsconfig.go)
- [CoreDNS v1.15.0 `core/dnsserver/server_tls_test.go`](https://github.com/coredns/coredns/tree/v1.15.0/core/dnsserver/server_tls_test.go)
