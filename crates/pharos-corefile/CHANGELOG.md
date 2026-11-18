# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/itsmeyaw/pharos-dns/compare/pharos-corefile-v0.1.0...pharos-corefile-v0.2.0) - 2026-11-18

### Fixed

- *(corefile)* escape Unicode server-block keys
- *(corefile)* clarify glob limit errors
- *(corefile)* align DNS key validation
- *(corefile)* honor DNS key rules
- *(corefile)* bound expansion history memory

### Other

- drop hand-written CHANGELOG.md stubs
- *(release)* add per-crate CHANGELOG.md for release-plz
- *(corefile)* pin reviewed DNS behavior
- *(corefile)* pin CoreDNS glob limits
- *(pharos-corefile)* cite spec sections above protocol logic
