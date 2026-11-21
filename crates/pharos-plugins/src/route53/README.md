# route53

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/route53/README.md)

## route53

- Each hosted zone is loaded into the shared `Zone` engine (the one `file` serves) and swapped atomically after its own full pagination succeeds. A failed refresh logs `Failed to update zones [...]` at ERROR and keeps serving the last good data; the other hosted zones still update.
- A hosted zone needs an apex SOA and an apex NS RRset, because every `Zone` does (RFC 1035 §6.1; RFC 2181 §6.1). CoreDNS loads a hosted zone without them and then answers SERVFAIL; Pharos fails setup, or keeps the previous data on a refresh.
- Record sets whose owner is not at or below the ZONE are dropped with a WARN (RFC 1034 §4.2). CoreDNS inserts them but never serves them. Consequently the NODATA SOA of a hosted zone is the SOA of its own ZONE; the CoreDNS test `split-example.gov.` answers with the `org.` SOA that its fixture inserts into the `gov.` hosted zone.
- Alias record sets have no `ResourceRecords` and are skipped, as CoreDNS does. Set identifiers (weighted, latency, geo and failover routing) are ignored: the values of every record set with the same name and type are served together, like CoreDNS. Missing TTL reads as 0.
- Several hosted zones for one ZONE are tried in Corefile order, with CoreDNS's rule: the first non-empty Answer or NODATA wins; otherwise the last hosted zone's result is used. NODATA in the first hosted zone ends the search. An empty non-terminal is a Success without Answer in CoreDNS, not NODATA, so the next hosted zone is tried.
- Fallthrough: CoreDNS falls through when `len(Answer) == 0 && result != NoData && Fall.Through(qname)`. Pharos classifies the `Zone` Response the same way (NXDOMAIN, empty non-terminal, delegation and SERVFAIL fall through; NODATA and any Answer do not), and clears the Response before the next Plugin runs. A Query with QCLASS `*` cannot be told from a delegation and is classified as NODATA. A CNAME whose target is not in the Zone is an Answer and does not fall through. No snapshot yet is SERVFAIL (or falls through).
- Without `fallthrough`, a Query below a ZONE that has no answer is NXDOMAIN or SERVFAIL, never passed on.
- Each `route53` line in a Server Block is its own stanza with its own client, refresh loop and fallthrough list; they are tried in Corefile order and a stanza passes the Query on when no ZONE of it matches. The longest matching ZONE wins within a stanza, the first on a tie.
- Setup runs the first load synchronously and fails with `plugin/route53: failed to create route53 client`, `failed to create route53 plugin` (the `ListHostedZonesByName` check) or `failed to initialize route53 plugin`. The refresh loop starts at Startup, stops at Restart and Shutdown, and starts again at RestartFailed; it sleeps `refresh` before each update. The SDK client is built a second time inside the server runtime for the loop, so its connections belong to the runtime that uses them. Failing to build it is logged and retried each interval.
- Authentication uses the AWS SDK default chain. `aws_access_key ID SECRET` is a static key without session token and still warns as deprecated. `credentials PROFILE FILE` replaces the shared config files and keeps the default credentials file, as CoreDNS's `WithSharedConfigFiles` does. `aws_endpoint` sets the endpoint URL. A region missing from the environment, the shared config and IMDS fails setup instead of hanging.
- A truncated page without `NextRecordName` or `NextRecordType` is an error; the SDK default retry policy applies to API calls.
- Deferred: alias targets and a zero-allocation Query pin (the Plugin needs a Route 53 endpoint to start, which the allocation harness has none of).

## Sources

- [CoreDNS v1.15.0 `plugin/route53`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/route53)
