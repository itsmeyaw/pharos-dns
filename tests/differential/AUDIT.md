# M2 README example audit

CoreDNS v1.15.0 `plugin/<name>/README.md`; examples are listed in README order.
Scenario names refer to directories alongside this file. Local fixtures replace
external Upstreams and paths. Syntax templates and `dig` output are not
independent Corefile examples. Skipped entries explain why they cannot run.

| Plugin and README example | Differential scenario or reason |
| --- | --- |
| root: filesystem root | `root-readme` |
| root: TLS and root | Skipped: TLS Listeners are deferred to M3. |
| metadata: prose refers to rewrite | No Corefile; `rewrite-name-metadata` exercises the referenced use. |
| cancel: default; one second | `cancel-default`; `cancel-custom` |
| timeouts: TLS; HTTPS; QUIC | Skipped: encrypted Listeners are deferred to M3. |
| timeouts: TCP read/write; max queries | `timeouts-tcp`; `timeouts-max` |
| nsid: explicit string | `nsid` |
| bufsize: forward; file | `bufsize-forward`; `bufsize-file-readme` |
| debug: default | `debug` |
| shed: forward | `shed` |
| local: default | `local-readme` |
| dns64: default; prefix argument; prefix block; translate_all; allow_ipv4 | `dns64-default`; `dns64-prefix`; `dns64-prefix-block`; `dns64-translate-all`; `dns64-allow-ipv4` |
| siit: IPv6 prefix | `siit-prefix` |
| any: whoami | `any` |
| chaos: explicit zones; root | `chaos-zones`; `chaos-root` |
| tsig: transfer; forward; opcode | `tsig-transfer-readme`; `tsig-forward`; `tsig-opcode` |
| rewrite: substring; regex; suffix | `rewrite-name-substring`; `rewrite-name-regex`; `rewrite-name-suffix` |
| rewrite: metadata in names | `rewrite-name-metadata` |
| rewrite: regex response example; auto answer; explicit answer | `rewrite-regex`; `rewrite-name-auto`; `rewrite-regex` |
| rewrite: PTR answer value; exact name | `rewrite-ptr-value`; `rewrite-name-exact` |
| rewrite: TTL regex; four ranges | `rewrite-ttl`; `rewrite-ttl-ranges` |
| rewrite: textual and numeric SERVFAIL RCODE | `rewrite-rcode-servfail`; `rewrite-rcode-numeric` |
| rewrite: EDNS local hexadecimal; literal; client IP; unset | `rewrite-edns-hex`; `rewrite-edns-local`; `rewrite-edns-variables`; `rewrite-edns-unset` |
| rewrite: EDNS imaginary metadata provider | Skipped: `some-plugin` is explicitly imaginary and does not exist. |
| rewrite: EDNS subnet set; unset; single revert; chained revert | `rewrite-edns-subnet`; `rewrite-edns-subnet-unset`; `rewrite-edns-single-revert`; `rewrite-edns-revert` |
| rewrite: CNAME regex chain | `rewrite-cname-readme` |
| autopath: resolv.conf; Kubernetes | `autopath-resolv`; `autopath-kubernetes` |
| acl: block A; filter A; exception; allow two networks; zone; drop | `acl-block-loopback`; `acl-filter-loopback`; `acl-allow`. `acl-block` and `acl-filter` run the README networks, which the loopback client never matches, so they compare only the default allow; `acl-exception`, `acl-zone` and `acl-drop` do the same. The loopback variants compare the block and filter actions with EDNS Queries; CoreDNS's non-EDNS EDE OPT is the documented Server deviation in `docs/compatibility.md`. Other documented non-loopback client addresses cannot be sourced by the harness; matching branches have Rust tests. |
| header: set RA; set RA/AA and clear RD; set query RD | `header-response-ra`; `header-response-flags`; `header-query-rd` |
| dnssec: whoami key; AWS key; Kubernetes key | `dnssec-whoami`; AWS skipped because live credentials and a secret are required; `dnssec-kubernetes` |
| minimal: whoami and forwarding | `minimal-readme` |
| template: all NXDOMAIN; invalid TLD | `template-nxdomain`; `template-invalid` |
| template: search zone; search regex; A/PTR | `template-search-zone`; `template-search-regex`; `template-address` |
| template: LAN address; hexadecimal; multiple patterns | `template-lan`; `template-hex`; `template-patterns` |
| template: A/MX; authority; CNAME | `template-mx`; `template-authority`; `template-cname` |
| transfer: ACL; source address | `transfer-acl-readme`; `transfer-source-readme` (remote source/recipient cannot be exercised locally) |
| dynupdate: memory; persistent | `dynupdate-readme`; `dynupdate-persistent-readme` |
| k8s_external: basic; transfer; fallthrough | `k8s-external-basic`; `k8s-external-transfer`; `k8s-external-fallthrough` (local Next replaces the external resolver) |
| file: Zone and transfer; shared file; invalid root | `file-readme`; `file-shared-readme`; invalid root checked by `coredns_readme_root_without_zone_is_invalid` because no Responses can be served. |
| file: explicit Zone; Server Block Zone | `file-readme-explicit-zone`; `file-readme-server-zone` |
| auto: transfer; filename regex | `auto-transfer-readme`; `auto-regexp-readme` |
| secondary: fallback; re-export; catalog | `secondary-fallback-readme`; `secondary-transfer-readme`; `secondary-catalog-readme` |
| erratic: drop 3; default drop; delay; delay and truncate; drop/truncate | `erratic-drop`; default drop skipped because timeouts abort comparisons; `erratic-delay`; `erratic-truncate-delay`; drop/truncate skipped for the same reason. |
| sign: file output; two directory-key examples; unspecified origin pitfall | `sign-readme`; directory-key examples skipped because CoreDNS rejects the unimplemented option; pitfall has no stable Response. |
| view: CIDR; type; regex | `view-cidr`; `view-type`; `view-regex`. Non-loopback CIDR branches require Rust tests. |
