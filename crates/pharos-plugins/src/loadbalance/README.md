# loadbalance

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/loadbalance/README.md)

## loadbalance

- Pharos permutes encoded records and relocates compression pointers without re-encoding names. It leaves a Response unchanged if relocation would create a forward or overlapping pointer, exceed the 14-bit pointer range, or if name encodings cannot be safely relocated. Signed TSIG Responses are not reordered. CoreDNS re-encodes its records and does not have these restrictions.
- Other RDATA is opaque, so pointers in types outside the compression-receiving list are not relocated even if a sender encodes them contrary to the RFCs.
- Weight files must be UTF-8; CoreDNS accepts arbitrary bytes.
- Pharos compares file contents directly instead of CoreDNS's MD5 checksum and keeps the last valid weights when parsing fails.
- Weight file Domains that cannot be parsed as DNS names cannot match Responses.
- Negative reload durations are accepted as zero; CoreDNS's negative ticker interval panics when started.
- Random choices use a thread-local xorshift generator rather than CoreDNS's generators.
- Equivalent escaped Domain spellings can match in Pharos, while CoreDNS compares presentation strings exactly.
- Weight file reads and parsing run on a Tokio worker and can delay other tasks.
- Successful reloads are not logged.
- When both policies are configured, subnet preference runs after weighted selection, as in CoreDNS, and can change which address appears first.

## Differential scenarios

The loadbalance scenarios compare a multi-address `hosts` Response with
round-robin and subnet preference, and a single-address weighted Response.
They do not compare randomized order or weight distributions.
