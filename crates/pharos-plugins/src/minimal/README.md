# minimal

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/minimal/README.md)

## minimal

- Pharos edits the encoded Response in place rather than re-encoding it. It leaves a Positive Response unchanged when a retained Question or Answer name references header counts, or an Answer's compressible RDATA is malformed, to avoid corrupting names.
- Nonstandard compression in opaque RDATA is not detected; CoreDNS re-encodes the record types it understands.
- The Listener adds an OPT back to EDNS Responses after `minimal` removes it, as required by RFC 6891 §6.1.1; CoreDNS's Listener also controls the final OPT.
