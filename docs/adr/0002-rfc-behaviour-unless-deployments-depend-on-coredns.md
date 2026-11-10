# Behaviour follows RFC MUSTs unless deployments depend on CoreDNS

ADR-0001 settles names; this settles behaviour. When CoreDNS v1.15.0 contradicts a MUST in the DNS RFCs, Pharos follows the RFC, unless there is evidence that clients or deployments rely on CoreDNS's behaviour, in which case Pharos matches CoreDNS. Every behaviour that differs from CoreDNS, in either direction, is recorded in the compatibility document so operators migrating from CoreDNS can find it.

## Considered Options

- Match CoreDNS exactly, bugs included: rejected, it would import known RFC violations into a new project.
- Always follow the RFC: rejected, it would break deployments that quietly depend on CoreDNS quirks.
