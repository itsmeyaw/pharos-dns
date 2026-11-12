# kubernetes

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/kubernetes/README.md)

## kubernetes

- The Kubernetes data crate ignores addresses in EndpointSlices with address types other than IPv4 or IPv6; CoreDNS retains them.
- With `namespace_labels` and `multicluster`, Pharos watches all ServiceImports and exposes those in matching Namespaces; CoreDNS matches the ServiceImports' own labels against `namespace_labels`, hiding imports in exposed Namespaces.
- As in CoreDNS v1.15.0, Kubernetes NS discovery snapshots local addresses per Plugin instance.
- CoreDNS's CIDR-only selection yields no local NS addresses for explicit `bind` IP literals; Pharos matches that behavior.
- API client creation and kubeconfig validation occur during Startup rather than Corefile setup.
- Kubeconfig OIDC credentials use the configured ID token without refreshing it; CoreDNS includes the client-go OIDC authentication provider.
- Kubeconfig proxy URLs are not supported; CoreDNS can connect through them.
- An unreadable or invalid in-cluster CA file fails client creation; client-go logs the CA error and proceeds without that CA file.
- DNS programming latency observations for lists occur after the whole resource batch is installed, rather than after each individual EndpointSlice.
- Kubernetes REST request duration ends when response headers arrive, rather than after processing the response body.
- Kube's internal retries are counted once per request rather than once per attempt as in client-go.
- Client-side rate-limit waits are capped at 100 years for extremely small QPS.
- CoreDNS parses `NaN` and positive infinity for `apiserver_qps`; Pharos accepts them in the Corefile but rejects them when creating the API client.
- Pharos treats non-positive `startup_timeout` as an immediate timeout; CoreDNS's startup ticker panics for those values.
- Pharos lowercases the zone when matching NS queries at the zone and `ns.dns.<zone>`, so mixed-case queries are answered (RFC 4343). CoreDNS compares the lowercased name with the zone in the query's case (`handler.go:22,53`, `ns.go:11`) and answers NODATA or NXDOMAIN.
- Glue for NS answers and `ns.dns.<zone>` addresses are deduplicated (RFC 2181 §5); CoreDNS repeats glue when a local address is in several EndpointSlices of one Service.
- The initial list is a consistent paginated list of 500 objects per page (kube-runtime default), served from etcd; CoreDNS uses a streaming WatchList or a `resourceVersion=0` read from the API server's cache. This never returns older data, but costs more etcd load when many DNS Pods restart together.
- The CA file is read once when the API client is created; a rotated CA needs a restart.
- An ExternalName name returns its CNAME for every query type (RFC 1034 §4.3.2 step 3a). CoreDNS returns it only for CNAME, A and AAAA queries and answers NODATA for other types such as TXT, SRV, MX and HTTPS (`kubernetes.go:116-121,168-185`). Pharos follows the CNAME only for A and AAAA, as CoreDNS does; for other types the client follows it.
- ExternalName A and AAAA Self Lookups allocate per Query until #86 pools their buffers and futures.
- Shared with CoreDNS v1.15.0: names with no records of their own (`dns.<zone>`, `_tcp.<service>.<namespace>.svc.<zone>`, and TXT at the zone, `svc.<zone>` and `<namespace>.svc.<zone>`) get NXDOMAIN instead of NODATA (RFC 8020; kept for CoreDNS parity, #43).
- Shared with CoreDNS v1.15.0: `dns-version.<zone>` A and non-PTR queries for existing reverse names get NXDOMAIN instead of NODATA (RFC 2308 §2.2; kept for CoreDNS parity, #43).
- Shared with CoreDNS v1.15.0: a SOA query for a name that does not exist gets NOERROR instead of NXDOMAIN (RFC 2308; kept for CoreDNS parity, #43).
- Shared with CoreDNS v1.15.0: `dns-version` in a multicluster zone returns `1.1.0`; the multicluster DNS specification 1.0.0 (KEP-1645) says `1.0.0`.
- Shared with CoreDNS v1.15.0: a ServiceImport without ports gets NXDOMAIN for A/AAAA, and a ServiceImport port without a protocol never matches `_tcp`; the MCS API defaults the protocol to TCP only in its documentation.
- Shared with CoreDNS v1.15.0: ANY queries get NODATA, even at the zone (RFC 8482 §4 recommends at least one RRset).
- Shared with CoreDNS v1.15.0: the SOA serial uses the last change's Unix time in seconds. A Secondary Server can miss a second change within the same second, even after NOTIFY.
- Shared with CoreDNS v1.15.0: a multicluster Zone Transfer uses the internal SOA serial, which can differ from a multicluster SOA Query.
- Shared with CoreDNS v1.15.0: some DNS-visible changes, including Service IP and endpoint Pod-name changes, do not change the SOA serial; a Secondary Server may skip an update even after NOTIFY.
- Kubernetes sends NOTIFY after the initial sync, when the transfer Plugin is rebound, and on data changes (RFC 1996 §§3.1, 4.1); CoreDNS's Kubernetes Plugin does not send NOTIFY.
- Zone Transfers encode the entire Zone synchronously under the store's read lock before sending. Memory and worker time therefore grow with Zone size; CoreDNS streams the transfer in batches.
- Zone Transfers allocate one encoded snapshot and one shared Stream producer, not per record. macOS also allocates the producer's mutex on first use.
- Kubernetes NOTIFY coalesces changes received while an earlier NOTIFY is being sent, then sends again for the latest state.

## Sources

- Adapted from CoreDNS v1.15.0 plugin/kubernetes/parse_test.go.
- Derived from CoreDNS v1.15.0 plugin/kubernetes/metadata_test.go TestMetadataPodsVerified.

- [CoreDNS v1.15.0 `plugin/backend_lookup.go`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/backend_lookup.go)
- [CoreDNS v1.15.0 `plugin/kubernetes`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/kubernetes)
- [CoreDNS v1.15.0 `plugin/kubernetes/README.md`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/kubernetes/README.md)
- [CoreDNS v1.15.0 `plugin/kubernetes/metadata_test.go`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/kubernetes/metadata_test.go)
- [CoreDNS v1.15.0 `plugin/metadata`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/metadata)
- [CoreDNS v1.15.0 `plugin/pkg/dnsutil`](https://github.com/coredns/coredns/tree/v1.15.0/plugin/pkg/dnsutil)
