# Expression subset

The expression engine accepts boolean, decimal and `0x`/`0o`/`0b` integer,
floating-point and quoted
string literals; parentheses; `!`, `not`, unary `-`, numeric arithmetic,
comparisons, `&&`, `and`, `||`, `or`, `in` with a literal list,
string concatenation, `contains`, `startsWith`, `endsWith` and `matches` with a literal pattern. Declared typed variables, `group`, `int`, `replace`, and `any` with a homogeneous literal list and a `#` predicate are supported. The Query functions
`type`, `name`, `class`, `proto`, `size`, `client_ip`, `port`, `id`, `opcode`,
`do`, `bufsize`, `server_ip`, `server_port`, `metadata` and `incidr` are supported.
Other constructs fail compilation. Evaluation uses caller-provided scratch
storage and returns an error if the buffer is too small. The uncompressed
`size` inherits the log formatter's documented limitation on unsupported or
malformed name-bearing RDATA.

For scoped IPv6 addresses, `client_ip` and `server_ip` use the numeric scope
ID; CoreDNS may use an interface name. The Listener exposes only a wildcard
local address when the destination address is not tracked.

`#` requires a nonempty homogeneous list so its type is known at setup;
`any([], true)` is accepted. List values cannot otherwise be returned from
an expression. String conversion uses the caller's scratch space.

Expressions exceeding 1,024 tokens or 256 recursive parse levels fail at
setup to bound stack use. expr-lang's default limit is 10,000 AST nodes.

`matches` uses Rust regex syntax and Unicode rules rather than Go RE2, and
rejects nonliteral patterns at setup so patterns can be compiled once. This
differs from expr-lang, which permits dynamic patterns.
