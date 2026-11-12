# Migrating from CoreDNS

## Deployment

Replace the CoreDNS image with your Pharos image (build or obtain one for your
platform; this repository does not specify a published image). Keep the mounted
Corefile and change arguments such as `-conf /etc/coredns/Corefile` to
`--conf /etc/coredns/Corefile`. Pharos uses POSIX-style flags; old single-dash
long flags report their replacements. DNS ports and the configured health,
readiness, and metrics ports and probe paths are unchanged. Check the
[compatibility document](docs/compatibility.md) for endpoint differences.

For a new installation, `deploy/kubernetes/pharos.yaml` is an example using
the kubeadm Corefile and least-privilege watch RBAC. Set its image to one
available to your nodes and its Service `clusterIP` to the kubelet's configured
cluster DNS address. It creates a `kube-dns` Service and is not an
in-place migration manifest: do not apply it over an existing kubeadm DNS
installation. For that case, patch the existing CoreDNS Deployment instead,
retaining its ConfigMap, RBAC, probes, security context and Service.

For `dnssec` keys stored in AWS Secrets Manager, build with
`cargo build --release -p pharos-dns --features pharos-plugins/dnssec-aws`.
The feature is off by default; without it, `key aws_secretsmanager` is a
configuration error. The SDK uses its default AWS credential chain.

Before rollout, run:

```sh
pharos check --conf /etc/coredns/Corefile
```

Without `--conf`, Pharos looks for `/etc/pharos/pharos.conf`, then `./Corefile`,
then uses its built-in default. `check` parses imports and runs Plugin setup,
but does not bind Listeners or run Startup hooks; it cannot validate connectivity
or credentials that are checked at Startup. It returns 0 on success, 1 for a
configuration error, and 2 for an invalid flag.

With the `kubernetes` option `multicluster`, the ServiceImport CRD
(`serviceimports.multicluster.x-k8s.io`) must be installed and readable by the
Pharos service account. Without it the Plugin never becomes ready and answers
SERVFAIL for names it cannot find, as CoreDNS does. The example manifest's
RBAC does not grant ServiceImports; add `list` and `watch` on
`serviceimports` in API group `multicluster.x-k8s.io`.

## Metrics

Rewrite `coredns_` to `pharos_` in PromQL alerts and Grafana dashboards, for
example `rate(coredns_dns_requests_total[5m])` becomes
`rate(pharos_dns_requests_total[5m])`. Histogram `_bucket`, `_sum`, and `_count`
samples follow their family name. Availability depends on configuration and
observed traffic. The `goversion` build-info label is `rustc`; the remaining
labels and buckets are intended to match CoreDNS. Pharos exports no `go_*`
runtime metrics. Process metrics retain their `process_` names; Linux collects
them when `/proc` data is available, macOS only open file descriptors, and
other platforms omit them.

The following table lists metric families, not individual histogram samples.

| Pharos | CoreDNS |
| --- | --- |
| `pharos_build_info` | `coredns_build_info` |
| `pharos_cache_drops_total` | `coredns_cache_drops_total` |
| `pharos_cache_entries` | `coredns_cache_entries` |
| `pharos_cache_evictions_total` | `coredns_cache_evictions_total` |
| `pharos_cache_hits_total` | `coredns_cache_hits_total` |
| `pharos_cache_misses_total` | `coredns_cache_misses_total` |
| `pharos_cache_prefetch_total` | `coredns_cache_prefetch_total` |
| `pharos_cache_requests_total` | `coredns_cache_requests_total` |
| `pharos_cache_served_stale_total` | `coredns_cache_served_stale_total` |
| `pharos_dns_do_requests_total` | `coredns_dns_do_requests_total` |
| `pharos_dns_https3_responses_total` | `coredns_dns_https3_responses_total` |
| `pharos_dns_https_responses_total` | `coredns_dns_https_responses_total` |
| `pharos_dns_quic_responses_total` | `coredns_dns_quic_responses_total` |
| `pharos_dns_request_duration_seconds` | `coredns_dns_request_duration_seconds` |
| `pharos_dns_request_size_bytes` | `coredns_dns_request_size_bytes` |
| `pharos_dns_requests_total` | `coredns_dns_requests_total` |
| `pharos_dns_response_size_bytes` | `coredns_dns_response_size_bytes` |
| `pharos_dns_responses_total` | `coredns_dns_responses_total` |
| `pharos_dnssec_cache_entries` | `coredns_dnssec_cache_entries` |
| `pharos_dnssec_cache_hits_total` | `coredns_dnssec_cache_hits_total` |
| `pharos_dnssec_cache_misses_total` | `coredns_dnssec_cache_misses_total` |
| `pharos_forward_healthcheck_broken_total` | `coredns_forward_healthcheck_broken_total` |
| `pharos_forward_max_concurrent_rejects_total` | `coredns_forward_max_concurrent_rejects_total` |
| `pharos_health_request_duration_seconds` | `coredns_health_request_duration_seconds` |
| `pharos_health_request_failures_total` | `coredns_health_request_failures_total` |
| `pharos_hosts_entries` | `coredns_hosts_entries` |
| `pharos_hosts_reload_timestamp_seconds` | `coredns_hosts_reload_timestamp_seconds` |
| `pharos_kubernetes_dns_programming_duration_seconds` | `coredns_kubernetes_dns_programming_duration_seconds` |
| `pharos_kubernetes_rest_client_rate_limiter_duration_seconds` | `coredns_kubernetes_rest_client_rate_limiter_duration_seconds` |
| `pharos_kubernetes_rest_client_request_duration_seconds` | `coredns_kubernetes_rest_client_request_duration_seconds` |
| `pharos_kubernetes_rest_client_requests_total` | `coredns_kubernetes_rest_client_requests_total` |
| `pharos_local_localhost_requests_total` | `coredns_local_localhost_requests_total` |
| `pharos_panics_total` | `coredns_panics_total` |
| `pharos_plugin_enabled` | `coredns_plugin_enabled` |
| `pharos_proxy_conn_cache_hits_total` | `coredns_proxy_conn_cache_hits_total` |
| `pharos_proxy_conn_cache_misses_total` | `coredns_proxy_conn_cache_misses_total` |
| `pharos_proxy_healthcheck_failures_total` | `coredns_proxy_healthcheck_failures_total` |
| `pharos_proxy_request_duration_seconds` | `coredns_proxy_request_duration_seconds` |
| `pharos_reload_failed_total` | `coredns_reload_failed_total` |
| `pharos_reload_version_info` | `coredns_reload_version_info` |
| `process_cpu_seconds_total` | `process_cpu_seconds_total` |
| `process_max_fds` | `process_max_fds` |
| `process_open_fds` | `process_open_fds` |
| `process_resident_memory_bytes` | `process_resident_memory_bytes` |
| `process_start_time_seconds` | `process_start_time_seconds` |
| `process_virtual_memory_bytes` | `process_virtual_memory_bytes` |

## Logs

Pharos writes log entries to stdout with UTC RFC3339 timestamps, unbracketed
levels, and an optional Plugin name. The default text format is, for example:

```text
2024-01-02T03:04:05Z ERROR whoami: bad query
```

Use `--log-format json` for JSON lines with `timestamp`, `level`, `plugin`, and
`message` string fields:

```json
{"timestamp":"2024-01-02T03:04:05Z","level":"ERROR","plugin":"whoami","message":"bad query"}
```

The `log` Plugin's common-format Query line is the message, not separate JSON
fields. Update log parsers accordingly. Startup banners remain text even with
JSON logging; `--quiet` suppresses startup output. CLI and startup errors may
be written to stderr.
