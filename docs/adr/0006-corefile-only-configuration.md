# Corefile is the only configuration format in v1

Pharos must accept every CoreDNS Corefile anyway (ADR-0003), so v1 uses Corefile syntax as its only configuration format; its own file is `/etc/pharos/pharos.conf` (FHS 3.0 places host configuration in `/etc/<package>/`), looked up after `--conf` and before `./Corefile`, which is kept only to ease migration. The parsed configuration is converted into a typed model that Plugins consume, so a second, versioned format can be added later without touching any Plugin.

## Considered Options

- Versioned YAML alongside the Corefile: deferred. It would give a schema, editor validation and a version field, but costs a schema and documentation for all 62 Plugins, a converter and equivalence tests, on the most compatibility-sensitive part of v1. If added later, YAML is preferred over KDL for operator familiarity, and `serde_yaml`/`serde_yml` are not options (deprecated; RUSTSEC-2025-0068).
- KDL: fits Corefile's structure almost one-to-one but is unfamiliar to operations engineers.
- TOML: awkward for ordered Server Blocks with per-Plugin positional arguments.
