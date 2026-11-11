# nsid

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/nsid/README.md)

## nsid

- With `nsid` enabled, unsolicited NSID options in Responses from Next are removed as required by RFC 5001 §2.2; CoreDNS passes them through.
- Adding NSID requires sufficient preallocated Response buffer capacity and a Message of at most 65,535 octets; otherwise the Plugin returns an error, answered as SERVFAIL. CoreDNS allocates when encoding and may instead fail to write an oversized Response.
- If the Question and NSID-bearing OPT cannot fit the negotiated Response limit, the Listener returns SERVFAIL; CoreDNS retains the OPT even when the resulting Response exceeds that limit.
- If the Response OPT precedes other Additional records, Pharos drops those records and sets TC before modifying NSID to avoid invalidating compression pointers; CoreDNS re-encodes them. This is the same restriction as Listener scrubbing.
