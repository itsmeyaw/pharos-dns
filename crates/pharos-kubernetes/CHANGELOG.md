# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/itsmeyaw/pharos-dns/compare/pharos-kubernetes-v0.1.0...pharos-kubernetes-v0.2.0) - 2026-11-18

### Added

- *(kubernetes)* expose external lookups
- *(kubernetes)* expose transfer data
- *(kubernetes)* track external serial
- *(kubernetes)* signal DNS data changes

### Fixed

- *(kubernetes)* skip non-IP reverse keys
- *(k8s)* return 404 for unknown mock routes
- *(k8s)* enforce RFC 9110 mock methods
- *(kubernetes)* close conformance gaps
- *(k8s_external)* snapshot endpoint queries
- *(k8s_external)* retain Service snapshot
- *(kubernetes)* transfer Services in CoreDNS name order

### Other

- *(kubernetes)* drop unused endpoint node name
- *(kubernetes)* name memory counters
- *(kubernetes)* measure unready endpoint retention
- *(kubernetes)* scope size assertion to 64-bit
- *(kubernetes)* [**breaking**] pack readiness within object sizes
- *(kubernetes)* print cache object sizes
- *(pharos-kubernetes)* cite spec sections above protocol logic
- *(rewrite)* cover metadata example
- *(k8s_external)* compare CoreDNS
- *(kubernetes)* [**breaking**] type config errors
- *(kubernetes)* index ExternalName targets
