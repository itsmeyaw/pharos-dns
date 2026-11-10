# DNS terms follow the RFCs, everything else follows CoreDNS

Pharos is a rewrite of CoreDNS, but CoreDNS uses several DNS terms in ways that contradict the DNS RFCs (for example "Delegation" for a referral response, "zone" for any routable domain, "Server" for a listener, "master" for a primary server). We decided that DNS terms follow the RFCs, with RFC 9499 (BCP 219) as the first reference, and that only terms the RFCs do not define (Corefile, Server Block, Directive, Plugin, Plugin Chain, Fallthrough, Readiness, Reload, ...) are taken from CoreDNS. Faithful RFC vocabulary matters more to us than familiarity for CoreDNS users, so names in `GLOSSARY.md` that differ from CoreDNS are deliberate and should not be changed back.

## Consequences

Corefile syntax is not renamed by this decision: keywords such as a plugin's `ZONES` arguments or `transfer from` stay compatible with CoreDNS until a separate decision says otherwise.
