# dnstap

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/dnstap/README.md)

## dnstap

- The default `version` is `Pharos-<crate version>`; CoreDNS uses `CoreDNS-1.15.0`. The default `identity` is the hostname, as in CoreDNS.
- An endpoint URL (`tcp://`, `tls://`) is checked for control characters, spaces, unbalanced brackets and a non-numeric port only; Go's `net/url` also rejects some malformed percent-escapes, which Pharos accepts and fails at connect time.
- The Frame Streams writer buffers 16 KiB before writing; golang-framestream buffers 4 KiB. Frames are flushed every second as in CoreDNS.

## Sources

- Derived from CoreDNS v1.15.0 plugin/dnstap/setup_test.go and plugin/dnstap/msg/msg_test.go.

- [CoreDNS v1.15.0 `plugin/dnstap`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dnstap)
- [dnstap.proto](https://github.com/dnstap/dnstap.pb/blob/main/dnstap.proto)
- [Frame Streams (fstrm)](https://farsightsec.github.io/fstrm/) and [golang-framestream v0.3.0](https://github.com/farsightsec/golang-framestream)
