# Expression subset

The expression engine is under construction. It currently accepts boolean,
integer and quoted string literals; parentheses; `!`, `not`, unary `-`, integer
arithmetic, comparisons, `&&`, `and`, `||`, `or`, `in` with a literal list,
string concatenation, `contains`, `startsWith`, `endsWith` and `matches` with a literal pattern. Declared typed variables, `group`, `int`, `replace`, and `any` with a homogeneous literal list and a `#` predicate are supported. The Query functions
`type`, `name`, `class`, `proto`, `size`, `client_ip`, `port`, `id`, `opcode`,
`do`, `bufsize`, `server_ip`, `server_port`, `metadata` and `incidr` are supported.
Other constructs fail compilation. Evaluation uses caller-provided scratch
storage and returns an error if the buffer is too small. The uncompressed
`size` inherits the log formatter's documented limitation on unsupported or
malformed name-bearing RDATA.

`#` requires a nonempty homogeneous list so its type is known at setup;
`any([], true)` is accepted. List values cannot otherwise be returned from
an expression. String conversion uses the caller's scratch space.

`matches` uses Rust regex syntax and Unicode rules rather than Go RE2, and
rejects nonliteral patterns at setup so patterns can be compiled once. This
differs from expr-lang, which permits dynamic patterns.
