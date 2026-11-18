# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/itsmeyaw/pharos-dns/compare/pharos-dnssec-v0.1.0...pharos-dnssec-v0.2.0) - 2026-11-18

### Added

- *(dnssec)* verify RFC 6605 ECDSA signatures

### Fixed

- *(dnssec)* reject URL-safe PEM alphabet
- *(dnssec)* accept RFC 7468 PEM text
- *(dnssec)* enforce RFC 3110 RSA key encoding
- *(dnssec)* tighten review tests and citations
- *(dnssec)* prepare signing keys before queries
- *(dnssec)* fail closed on incomplete denial proofs
- *(dnssec)* correct proof and response handling
- *(dnssec)* [**breaking**] reject unsafe signing algorithms
- *(dnssec)* canonicalize DNAME targets

### Other

- drop hand-written CHANGELOG.md stubs
- *(release)* add per-crate CHANGELOG.md for release-plz
- *(dnssec)* cite ECDSA verifier coverage
- *(dnssec)* assert parsed key identity
- *(dnssec)* format remediation changes
- *(dnssec)* cover RFC 6605 verifier bounds
- *(dnssec)* sign ECDSA and Ed25519 with aws-lc-rs
- *(dnssec)* assert algorithm 10 refusal
- *(dnssec)* record RFC behavior differences
- *(pharos-dnssec)* cite spec sections above protocol logic
- main into m2-query-plugins
