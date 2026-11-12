# tsig

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/tsig/README.md)

## tsig

- Signed Zone Transfer streams are supported by the Listener and `transfer` with the `file` and Kubernetes Zone backends; the `secondary` Plugin is not yet implemented.
- The Listener rejects UPDATE before the Plugin Chain, as CoreDNS v1.15.0 does without an UPDATE handler; `require_opcode UPDATE` cannot yet authenticate UPDATE traffic.
- A TSIG-truncated Response contains only the Question and TSIG, with NOERROR, as required by RFC 8945 §5.3; CoreDNS may retain other records.
- A Query with a nonzero TSIG Error is rejected as malformed (RFC 8945 §4.2); CoreDNS accepts it.
- A known key with an unsupported algorithm returns BADSIG, matching CoreDNS (RFC 8945 §5.2.1 specifies BADKEY). Admission-level errors, including UPDATE and BADVERS, are not TSIG-signed.
- Time Signed values are not retained for replay detection (RFC 8945 §5.2.3).

## Sources

- [CoreDNS v1.15.0 `plugin/tsig`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/tsig)
