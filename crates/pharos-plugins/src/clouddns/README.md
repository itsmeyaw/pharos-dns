# clouddns

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/clouddns/README.md)

## clouddns

- Syntax matches CoreDNS: `clouddns [ZONE:PROJECT_ID:HOSTED_ZONE_NAME...] { credentials [FILENAME]; endpoint ENDPOINT; fallthrough [ZONE...]; refresh DURATION; upstream [ADDRESS...] }`. The Directive may appear more than once; as in CoreDNS every line has its own credentials, refresh interval and `fallthrough`, and a Query is offered to the lines in order. A bare `clouddns` serves nothing. `upstream` and its arguments are accepted and ignored, as in CoreDNS.
- A ZONE argument splits on the first two colons (a hosted zone name may contain colons), none of the three parts may be empty, and the same ZONE:PROJECT_ID:HOSTED_ZONE_NAME twice is an error. Several hosted zones may share one ZONE; they are consulted in Corefile order. A Query goes to the longest configured ZONE that contains it, a hosted zone that answers with data or NODATA ends the lookup, and NXDOMAIN or a delegation moves on to the next hosted zone, so the SOA of a missing name comes from the last one.
- `refresh` is a number of seconds or a Go duration (`3m`, `1h30m`, `50ms`) and must be greater than zero; the default is one minute. The timer restarts when an update finishes. Each hosted zone is listed in full, every page, and replaced in one atomic step; the Query path never waits for a refresh.
- `credentials` takes `service_account`, `authorized_user`, `impersonated_service_account` and `external_account` files, and the file's `type` is checked when the Corefile is parsed (a missing file, bad JSON, no `type` or an unknown one is a setup error). Without it Application Default Credentials are used: `GOOGLE_APPLICATION_CREDENTIALS`, the gcloud well-known file, then the GCE metadata server. Access tokens are cached and renewed shortly before they expire. Tokens and secrets are never logged or put in errors. `endpoint` replaces `https://dns.googleapis.com` and is how tests point the Plugin at a local stub.
- The client is hand-written over hyper and the shared rustls configuration, not the Google SDK. `external_account` files whose `credential_source` is `aws`, `executable` or `certificate` are rejected; `file` and `url` sources, and workforce and workload identity federation through them, work.
- Records follow CoreDNS: one record per value in `rrdatas`, relative CNAME and PTR values made absolute, TXT strings as listed. Other relative names inside RDATA are read against the root. A record set that does not parse (an unknown type, a bad value) is skipped with a warning and the rest of the listing is served; CoreDNS stops at the first one and ignores the error. A record set whose owner is not under its ZONE is skipped, because a Zone holds only its own names. A listing without the apex SOA and NS is a failed update.
- The managed-zone check and the first load run at Startup, not while the Corefile is parsed, so that parsing never needs the network; a failure still stops the server. A failed refresh logs an error and keeps the last good Zone; the other hosted zones still refresh. Restart stops the refresh loops and RestartFailed brings them back; Shutdown stops them.
- Before a hosted zone has loaded (only possible between parse and Startup) its Queries get SERVFAIL, or fall through when `fallthrough` covers them.
- Answers come from the shared Zone lookup, so they follow the other zone Plugins: CNAME chains, wildcards, delegations without AA, NODATA with the SOA. A name that only exists as the parent of another record is an empty non-terminal and is NODATA (RFC 8020 §2), where CoreDNS tries the next hosted zone.
- Only class IN is served. Queries for other classes, and for names outside every ZONE, go to the next Plugin.
- No differential scenario exists: the Plugin reads Google Cloud DNS, which the harness cannot reach. The ported CoreDNS tests and the integration tests in `tests/functional/clouddns.rs` run against local stubs of the OAuth and Cloud DNS endpoints.

## Sources

- [CoreDNS v1.15.0 `plugin/clouddns`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/clouddns)
- [Cloud DNS API v1](https://cloud.google.com/dns/docs/reference/rest/v1)
- [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials)
