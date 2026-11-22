# nomad

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/nomad/README.md)

## nomad

- Syntax matches CoreDNS v1.15.0: `nomad [ZONE] { address URL...; filter FILTER; token TOKEN; ttl SECONDS }`. `ZONE` defaults to `service.nomad` and only the first argument is read. The v1.15.0 plugin has no `fallthrough` property and takes one `ZONE`, not `ZONES...` as some issue text says; `fallthrough` is rejected as an unknown property.
- Settings come from the `NOMAD_*` environment as in the Nomad Go client: `NOMAD_ADDR` (used when no `address` is set; default `http://127.0.0.1:4646`), `NOMAD_TOKEN` (a Corefile `token` wins), `NOMAD_REGION`, `NOMAD_HTTP_AUTH` (`user:password`), `NOMAD_CACERT`, `NOMAD_CLIENT_CERT` with `NOMAD_CLIENT_KEY`, `NOMAD_TLS_SERVER_NAME`. `NOMAD_SKIP_VERIFY` and `NOMAD_CAPATH` fail setup instead of being ignored. Addresses are `http://`, `https://` or `unix://` with no credentials or path; credentials never reach logs, errors or Debug output.
- Several `address` URLs fail over: a Query goes to the endpoint that answered last and moves on to the next one on any error. CoreDNS instead probes `/v1/agent/self` on every Query; Pharos spends no extra request and never panics on an empty client list.
- A failed lookup is answered once, as an authoritative NOERROR with no records. CoreDNS also hands SERVFAIL back to the server after writing that Response; Pharos writes one Message.
- A name with no registrations, a registration with an unparsable address, or a QTYPE other than A, AAAA and SRV is answered NXDOMAIN with the SOA in the ANSWER section, exactly as CoreDNS does. Records added before the failing registration stay in the Response.
- The Query name must be under the Plugin zone (RFC 1034 §3.1); CoreDNS only drops as many trailing labels as the zone has. Names at or above the zone, with fewer than two labels below it, or not in class IN or ANY go to the next Plugin. `a.b.<zone>` is service `a` in namespace `b`; labels further down are ignored.
- Service, namespace, filter and region are percent-encoded as Go's `net/url` does. Escaped dots and other presentation escapes in a Query label reach Nomad as the raw byte, not as CoreDNS's escaped text.
- Each Query asks Nomad: there is no cache. A request ends after 5 seconds, an HTTP redirect is an error, only status 200 counts, replies are capped at 8 MiB, and compression is not requested. Connections are kept alive and reused (up to 8 idle per endpoint, not aged out).
- A registration port is truncated to 16 bits as Go's `uint16(Port)` does. An SRV target is not name-compressed (RFC 2782).
