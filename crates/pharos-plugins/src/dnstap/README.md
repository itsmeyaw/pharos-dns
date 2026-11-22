# dnstap

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/dnstap/README.md)

## dnstap

- The default `version` is `Pharos-<crate version>`; CoreDNS uses `CoreDNS-1.15.0`. The default `identity` is the hostname, as in CoreDNS.
- An endpoint URL (`tcp://`, `tls://`) is checked for control characters, spaces, unbalanced brackets and a non-numeric port only; Go's `net/url` also rejects some malformed percent-escapes, which Pharos accepts and fails at connect time.
- Frame Streams is bidirectional (READY, ACCEPT, START; STOP, FINISH) for dial and listen alike, as in golang-framestream.
- Each Directive owns a queue of `queue` x 10,000 messages. Queries never wait on a collector: when the queue is full, or no collector is connected, the message is dropped and counted, and "Dropped dnstap messages: N" is logged every 10 seconds.
- A failed first connect is only logged; the writer keeps redialing. CoreDNS retries on a fixed 10 second tick; Pharos starts at 100 ms and doubles up to 10 s, and redials at once after a write error.
- `listen` writes to every collector from one background task, not from the Query's own goroutine, so a slow collector never delays a Query. A collector whose write fails is closed alone. The unix socket file is removed on close, as in Go. With no collector connected, messages are not even encoded.
- `extra` placeholders expand per message from the Query; Response labels (`{rcode}`, `{rsize}`, `{duration}`, `{>rflags}`) are `-`, as in CoreDNS where the recorder is not yet set. `extra` is not expanded for messages a Plugin taps without a Context.
- `SocketProtocol` is UDP or TCP by the client's transport, also for TLS, HTTPS and QUIC, as CoreDNS derives it from the address type.
- A Query answered after the chain returns (SERVFAIL, REFUSED, FORMERR, NOTIMP, NOTAUTH, or a Plugin error) still gets a CLIENT_RESPONSE (CoreDNS #6532). With `full` its wire message is the header-only Response the Server sends.
- Metrics, all process-wide: `pharos_dnstap_messages_enqueued_total`, `pharos_dnstap_messages_dropped_total{reason="queue_full|no_connection|write_error"}`, `pharos_dnstap_messages_written_total`, `pharos_dnstap_connect_failures_total`, `pharos_dnstap_reconnects_total`, `pharos_dnstap_connected`.
- `skipverify` on a dialer skips verification of the collector's certificate chain and name (handshake signatures are still checked); on a `tls://` listener with a CA it makes client certificates optional.
- The Frame Streams writer buffers 16 KiB before writing; golang-framestream buffers 4 KiB. Frames are flushed every second as in CoreDNS.

## Sources

- Derived from CoreDNS v1.15.0 plugin/dnstap/setup_test.go, msg/msg_test.go, io_test.go, listener_test.go and handler_test.go.

- [CoreDNS v1.15.0 `plugin/dnstap`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/dnstap)
- [dnstap.proto](https://github.com/dnstap/dnstap.pb/blob/main/dnstap.proto)
- [Frame Streams (fstrm)](https://farsightsec.github.io/fstrm/) and [golang-framestream v0.3.0](https://github.com/farsightsec/golang-framestream)
