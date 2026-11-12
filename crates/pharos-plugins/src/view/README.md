# view

[CoreDNS v1.15.0 README](https://github.com/coredns/coredns/blob/v1.15.0/plugin/view/README.md)

## view

- Expressions use the [expression subset](../expression/README.md).
- Evaluation uses a reusable 65,535-byte per-thread scratch buffer. Expressions
  whose intermediate strings exceed it do not match; CoreDNS can evaluate them.

## Sources

- Derived from CoreDNS v1.15.0 `plugin/view`.
