# log

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/log/README.md)

## log

- The `log` Plugin's body uses CoreDNS's common format by default, preceded by Pharos's timestamp and `INFO log:` rather than CoreDNS's `[INFO]` prefix.
- JSON entries use Pharos's generic log fields rather than CoreDNS's access-log fields.
- `{local}` reports the configured Listener address; for wildcard Listeners it does not report the connection's actual local address.
- For unanswered errors, the logged Response size includes the Listener's synthesized EDNS OPT, whereas CoreDNS's logging-only synthetic Message has no OPT.
- For a returned Response, `{rsize}` is the size before truncation, as in CoreDNS.
- `{rflags}` also describes the Message before truncation; CoreDNS scrubs its recorded Message in place, so its `{rflags}` shows `tc` when the Listener truncates.
- A Drop is logged with `-` RCODE and flags and zero size; a Plugin error is logged as a synthesized SERVFAIL.
- Zone Transfer streams are not yet served and are logged as a Message-less outcome.
- The formatter cannot expand compressed names in unsupported RDATA when calculating Message size.

## Sources

- Derived from CoreDNS v1.15.0 plugin/log/setup_test.go.

- [CoreDNS v1.15.0 `plugin/log`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/log)
- [CoreDNS v1.15.0 `plugin/pkg/replacer`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/pkg/replacer)
- [CoreDNS v1.15.0 `plugin/pkg/response`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/pkg/response)
