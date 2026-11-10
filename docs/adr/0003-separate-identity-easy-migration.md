# Pharos is a separate project that CoreDNS operators can migrate to easily

Pharos is not a CoreDNS clone: it keeps its own identity (name, binary, image, log format, metric prefix, CLI style) while making migration from CoreDNS v1.15.0 as easy as possible for operations engineers. The compatibility contract is therefore limited to what operators cannot cheaply change: every Corefile CoreDNS accepts is accepted with the same meaning (and every one it rejects is rejected), the same command-line capabilities and signal handling exist, and the same ports, HTTP endpoints and probe responses are served. Metrics keep CoreDNS's names, labels and buckets with the `coredns_` prefix replaced by `pharos_`, so dashboards migrate by renaming. Log format, container image layout and flag spelling are Pharos's own, following common POSIX/Rust CLI conventions.

## Consequences

Migrating is a manifest change (image, arguments, metric prefix in dashboards and alerts), never a Corefile rewrite. Third-party CoreDNS plugins are not supported: a Corefile using one fails at startup with an unknown-Directive error.
