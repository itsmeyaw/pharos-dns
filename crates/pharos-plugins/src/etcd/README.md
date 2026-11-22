# etcd

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/etcd/README.md)

## etcd

- Syntax matches CoreDNS: `etcd [ZONE...] { stubzones; fallthrough [ZONE...]; debug; no_apex_fallback; path PATH; endpoint ENDPOINT...; upstream [...]; tls [CERT KEY] [CA]; credentials USERNAME PASSWORD; min-lease-ttl TTL; max-lease-ttl TTL }`. Without ZONE the Server Block's zones are used. The defaults are `path skydns` (the keys live under `/skydns`), `endpoint http://localhost:2379`, `min-lease-ttl 30` and `max-lease-ttl 86400`. `stubzones` and `debug` do nothing, and `upstream` reads and ignores its arguments, as in CoreDNS.
- Setup does not connect to etcd, as in CoreDNS: an unreachable endpoint is accepted and fails the Queries that need it.
- The Directive is allowed once per Server Block, because the Chain holds one `etcd` Plugin. CoreDNS accepts several.
- `ENDPOINT` is `http://HOST[:PORT]`, `https://HOST[:PORT]` or `HOST[:PORT]`, as etcd clientv3 reads it: `http://` never uses TLS, `https://` always does (the system roots verify the server unless `tls` names a CA), and a bare `HOST[:PORT]` uses TLS when the Directive has `tls`. A missing port is 443, as in grpc-go. `unix:` and `unixs:` endpoints and any other scheme are rejected at setup, where etcd clientv3 fails at dial. The TLS configuration offers ALPN `h2` only.
- `tls` takes `CA`, `CERT KEY` or `CERT KEY CA` (relative paths join `root`), or no argument for the system roots; unreadable files fail setup, and more than three arguments is an error, as in CoreDNS. The client uses the shared `pharos_server::tls` configuration (rustls with aws-lc-rs).
- `credentials` needs both arguments; an empty username or password turns authentication off, as in CoreDNS.
- `min-lease-ttl` and `max-lease-ttl` take a number of seconds or a Go duration (`30s`, `5m`, `2h30m`, `1.5h`, `ms`, `us`, `ns`), parsed as Go's `time.ParseDuration` does. A fraction of a second is dropped, and a negative value or one above 4294967295 seconds is an error.
- `etcd` Service values are JSON read as Go's `encoding/json` reads them: field names match ignoring case, unknown fields are ignored, `null` leaves a field unset, and a value of the wrong type (`"port": "80"`, `"ttl": -1`, `"port": 1.5`) is an error naming the key. Messages of JSON syntax errors differ from Go's, input that is not UTF-8 is an error where Go replaces the bytes, and nesting deeper than 128 levels is an error.
- `Domain` of a key too short to hold a name is the root where CoreDNS panics. A label that holds `/` or `..` in a Query name is joined into the etcd key unescaped, as in CoreDNS.
- TXT text is split into 255-byte strings as CoreDNS does, including its quirk that text of exactly 255 bytes (or a multiple) ends with an empty string.
- Differential scenarios against CoreDNS are skipped: they need a real etcd server, and the test rig has no network services. Setup, key and value handling are pinned by tests ported from CoreDNS (`plugin/etcd/setup_test.go`, `plugin/etcd/msg`).
- Tracing spans are not created (the `trace` Plugin is not implemented).

## Sources

- [CoreDNS v1.15.0 `plugin/etcd`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/etcd)
- [etcd clientv3 endpoint handling](https://github.com/etcd-io/etcd/blob/main/client/v3/internal/endpoint/endpoint.go)
- [Go `time.ParseDuration`](https://pkg.go.dev/time#ParseDuration)
