# metadata

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/metadata/README.md)

## metadata

- Invalid configured Domains that cannot be normalized or represented as DNS names are ignored; CoreDNS retains some malformed Domain strings.
- Query-derived Kubernetes values use ASCII lowercasing and require UTF-8; CoreDNS uses Go's Unicode lowercasing and DNS presentation escaping.
- The fixed copied-value buffer is limited to 12 labels and 1,024 bytes; CoreDNS's map is unbounded. Kubernetes client Pod labels use a shared snapshot and are not subject to this limit.
- Collection currently runs after routing, so future View filters will need to collect Metadata before evaluating expressions, as CoreDNS does.
- Kubernetes multicluster labels use the matched Kubernetes Domain; CoreDNS's server collection leaves the request's Zone empty, so it may parse these labels as ordinary service/port names.

## Differential scenarios

The metadata scenarios compare DNS Responses with inherited and explicit Domains.
The Metadata README mentions `rewrite` without a concrete Corefile; those scenarios
use Kubernetes and whoami instead. Metadata values and log formatting are checked
by Rust tests, not the differential harness.

## Sources

- Derived from CoreDNS v1.15.0 plugin/kubernetes/metadata_test.go.
- Derived from CoreDNS v1.15.0 plugin/metadata/metadata_test.go TestLabelFormat.
- Derived from CoreDNS v1.15.0 plugin/metadata/setup_test.go TestSetupHealth.
- Derived from CoreDNS v1.15.0 plugin/metadata/setup_test.go.
