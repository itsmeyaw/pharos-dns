# tls

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/tls/README.md)

## tls

- `tls CERT KEY [CA]`, `client_auth nocert|request|require|verify_if_given|require_and_verify` and `keylog FILE` are supported. Relative paths resolve against `root`, as in CoreDNS.
- The `tls` Directive serves `tls://` Server Block Keys (default port 853). `tls` also serves `quic://` Server Blocks (default port 853; see `quic`) and `https://` Keys (see `https`). Server Blocks with `grpc://` or `https3://` Keys fail setup with or without `tls` until those Transports exist, instead of silently serving nothing.
- A `tls://`, `https://`, `grpc://`, `quic://` or `https3://` Server Block without a `tls` Directive fails setup, as in CoreDNS. A `tls` Directive in a plain-DNS Server Block is loaded and validated but not used.
- The minimum protocol version is TLS 1.2. Pharos uses rustls with the aws-lc-rs provider; CoreDNS uses Go's `crypto/tls`, so cipher-suite preference order and supported curves follow rustls rather than Go. TLS 1.3 session tickets use a rotating stateless ticketer.
- The `tls` ACME block (`tls { acme ... }`, and `tls` without arguments) is rejected with an error; ACME certificate management is not implemented yet.
- Certificates are read at startup and on every Reload. An invalid or unreadable file fails startup or the Reload (the previous configuration stays active). New connections after Reload use the new certificate on the same Listener; established connections keep their session. Replacing a certificate file alone does not trigger a Reload (as in CoreDNS); send SIGUSR1 or change the Corefile.
- Server Blocks that share a Listener must have the same TLS identity, client authentication policy and client CA pool; otherwise setup fails with `conflicting TLS configuration for shared listener`.
- `client_auth request` and `client_auth require` accept any presented client certificate without verifying its chain, like Go's `RequestClientCert` and `RequireAnyClientCert`. The handshake signature is still verified. `verify_if_given` and `require_and_verify` use `CA`, or the system trust store when `CA` is omitted.
- `keylog FILE` appends NSS Key Log lines and logs a warning at startup; as in CoreDNS, mode 0600 applies only when the file is created and the file is opened once per load. rustls cannot report a failed key-log write, so Pharos drops it silently where CoreDNS fails the handshake.
- A client that does not complete the TLS handshake within the TCP read timeout (default 3 seconds, see `timeouts`) is disconnected. The `timeouts` Directive and `max_queries` apply to DNS over TLS like TCP.
- `server_tls_test.go` cases for gRPC Transports are not ported until those Transports exist.

## Sources

- [CoreDNS v1.15.0 `plugin/tls`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/tls)
- [CoreDNS v1.15.0 `core/dnsserver/tlsconfig.go`](https://github.com/coredns/coredns/tree/v1.15.0/core/dnsserver/tlsconfig.go)
- [CoreDNS v1.15.0 `core/dnsserver/server_tls_test.go`](https://github.com/coredns/coredns/tree/v1.15.0/core/dnsserver/server_tls_test.go)
