# auto

See [CoreDNS auto](https://coredns.io/plugins/auto/) for syntax and behavior.

## auto

- Directory patterns use Rust regex syntax rather than Go RE2; character classes
  such as `\d` and `\w` are Unicode-aware by default.
- The shared Zone lookup may allocate for CNAME or DNAME Self Lookups for missing
  tree names, NS queries, and apex SOA targets; see #86 and the file Plugin notes.
- Zone Transfer streams allocate once per transfer, as in the shared Zone module.
