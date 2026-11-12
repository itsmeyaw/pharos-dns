# erratic

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/erratic/README.md)

## erratic

- AXFR over UDP is REFUSED by the Listener (RFC 5936 §4.2); CoreDNS sends the transfer over UDP.

## Differential scenarios

The default drop and drop-plus-truncate README examples are skipped because the differential harness cannot compare timeouts. Delay scenarios compare Responses, not elapsed time. Truncated AXFR cannot be compared by the harness because it waits for a closing SOA.

## Sources

- [CoreDNS v1.15.0 `plugin/erratic`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/erratic)
