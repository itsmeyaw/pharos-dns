# Differential scenarios

Run `cargo xtask coredns` once with Go installed, then `cargo xtask diff`.
`cargo xtask check` runs the scenarios when that binary is cached. The cache
is `target/coredns/v1.15.0/coredns`. `cargo xtask diff --self-test` deliberately
changes a Response and must fail with a diagnostic.

Each scenario is a directory containing:

- `Corefile`: the same configuration for both processes; `{port}` is replaced
  by the chosen Listener port. Omit it to exercise each built-in default in an
  empty working directory.
- `queries`: one Query per line, `name type class udp|tcp [flags...]`.
  Names are absolute; comments begin with `#`. Supported flags are `+dnssec`,
  `+bufsize=N`, `+norec`, `+ednsversion=N`, and `+opcode=NAME` or a number.
- `expect` (optional): one setting per line. `ttl N` permits a TTL difference
  of N seconds for ordinary records; default is zero. `mask
  additional.srv.port` ignores only the SRV port in Additional (whoami reports
  each client's ephemeral port). `deviation Heading` records an expected
  operational difference and must refer to an existing level-two heading in
  `docs/compatibility.md`. For a documented header difference only,
  `deviation Heading | exact Query line | flags=0xPHAROS:0xCOREDNS` allows
  that exact pair of flag values on that Query; other fields remain checked.
- Any other files or subdirectories are copied into separate temporary working
  directories for both processes, preserving relative paths.

IDs and RR order within each section are ignored; all other fields are compared.
The default scenario records the documented built-in `log` difference, which
does not change DNS Responses. The current whoami Responses cannot exceed the
512-octet UDP minimum for these short Queries, so truncation is not covered.
