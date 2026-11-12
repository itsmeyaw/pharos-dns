# Expression subset

The expression engine is under construction. It currently accepts boolean,
integer and quoted string literals; parentheses; `!`, `not`, unary `-`, integer
arithmetic, comparisons, `&&`, `and`, `||`, `or`, `in` with a literal list,
`contains`, `startsWith`, `endsWith` and `matches` with a literal pattern. The Query functions
`type`, `name`, `class`, `proto`, `size`, `client_ip`, `port`, `id`, `opcode`,
`do`, `bufsize`, `server_ip`, `server_port` and `metadata` are supported.
Other constructs fail compilation. Evaluation uses caller-provided scratch
storage and returns an error if the buffer is too small. The uncompressed
`size` inherits the log formatter's documented limitation on unsupported or
malformed name-bearing RDATA.

`matches` uses Rust regex syntax and Unicode rules rather than Go RE2, and
rejects nonliteral patterns at setup so patterns can be compiled once. This
differs from expr-lang, which permits dynamic patterns.
