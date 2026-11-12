# Expression subset

Compiled expressions evaluate against a borrowed Query and Metadata using a
caller-provided scratch buffer. A result may borrow that buffer; use separate
buffers to retain string-valued variables across evaluations. `value_type`
provides the type to pass to `compile_with_variables` for subsequent variables.

## Supported

- `nil`, Boolean, decimal/hex/octal/binary integer, floating-point, quoted and raw
  string literals; parentheses; typed variables.
- Unary `!`, `not`, `-`; numeric `+`, `-`, `*`, `/`, `%`; string `+`;
  comparisons; `&&`/`and`, `||`/`or`; `in` with a literal list; `contains`,
  `startsWith`, `endsWith`, and `matches` with a literal pattern. These last
  five operators also accept the `not` form, for example `not in`.
- `type`, `name`, `class`, `proto`, `size`, `client_ip`, `port`, `id`,
  `opcode`, `do`, `bufsize`, `server_ip`, `server_port`, `metadata`, `incidr`,
  `group`, `int`, `replace`, and `any` with a literal list and `#` predicate.
  `replace` accepts its optional replacement count. `any` accepts empty and
  mixed-type lists; operations on a mixed list's `#` are checked at runtime.
- A bare Query function, `metadata`, `incidr`, or `group` is a borrowed
  function value; it may be passed to the Go template `call` function.

## Errors and differences

- Unknown names, wrong argument types or counts, malformed literals, invalid
  regexes and unsupported constructs fail at setup. Unsupported constructs
  include maps, indexing, list-valued results or variables, nonliteral `in`
  and `any` lists, nested lists, ternaries, ranges, exponentiation,
  pipelines, closures and other expr-lang built-ins.
- `matches` compiles literal patterns at setup using Rust regex syntax and
  Unicode rules rather than Go RE2. Unlike expr-lang, dynamic patterns are
  rejected at setup.
- Expressions exceeding 1,024 tokens or 16 parse/evaluation levels fail at
  setup to bound worker stack use. expr-lang's default limit is 10,000 AST nodes.
- Evaluation returns an error on insufficient scratch space, invalid `int` or
  `incidr` input, division by zero for `%`, or missing/mistyped variable values.
  Out-of-range floating-point `int` conversion uses Rust's saturating cast;
  Go's result is architecture-specific.
- The uncompressed `size` inherits the log formatter's limitation for
  unsupported or malformed name-bearing RDATA.
- Scoped IPv6 addresses use numeric scope IDs; CoreDNS may use interface names.
  Wildcard Listener addresses remain wildcard when the destination is unknown.
