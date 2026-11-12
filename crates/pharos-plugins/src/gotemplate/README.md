# Go template subset

Templates are compiled at setup and rendered into a caller-provided `String`.
`Data.variables` accepts borrowed expression values, including Query functions.

## Supported

- `.Zone`, `.Name`, `.Class`, `.Type`, `.Remote`, `.Regex`, `.Match`,
  `.Group.name`, `.Var.name`, and `.Meta` with a string argument.
- `.Question`, its `Name`, `Qtype`, and `Qclass` fields, and `.Message` header
  fields (`Id`, `Opcode`, `Rcode`, and flag booleans). `.Message.Question`
  supports `index`, `slice`, and `range` with the same Question fields.
- Pipelines and parenthesized pipelines; `if`/`else if`/`else`/`end`; `range`
  over capture lists, named maps, Message Questions, or integers; scoped range
  index/value variables; `.` and `$.Field`; comments and whitespace trim markers.
- Go's `and`, `or`, `not`, `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `index`,
  `slice`, `len`, `print`, `println`, `printf`, `html`, `js`, and `urlquery`,
  plus CoreDNS's `parseInt`. `call` supports the borrowed Query, `metadata`,
  `incidr`, and `group` function values produced by the expression engine.
- `printf` handles `%s`, `%d`, `%x`, `%X`, `%o`, `%b`, `%c`, `%f`, `%F`, `%e`, `%E`, `%g`, `%G`,
  `%t`, `%q`, `%T`, `%v`, and `%%`, with selected widths, flags, and precision.

## Errors and differences

- Like Go `text/template`'s `strconv.Unquote`, surrogate `\u` escapes are rejected.
- Unsupported template actions, unknown functions, undefined range variables,
  invalid syntax, and invalid string escapes fail at setup. Unsupported syntax
  includes `with`, `define`, `template`, `block`, `break`, `continue`, and
  variable declarations or assignments outside a range. As in Go, unknown
  fields and incorrect function argument counts fail when rendered.
- Other Message sections and the complete Message string representation are
  not implemented. Go function values not produced by the expression engine
  cannot be supplied to `call`.
- Integer ranges above 65,535 iterations fail at render time; CoreDNS's Go
  `text/template` does not impose this cap.
- `printf` is a subset of Go's `fmt`: other verbs and some
  formatting flags are unsupported or produce format diagnostics. Floating
  point formatting follows Go's common exponent notation, but edge-case
  rounding or Unicode behavior may differ.
- String literals decoding to non-UTF-8 bytes are rejected because the output
  buffer is a Rust `String`. String slices require UTF-8 boundaries; capture
  slices cannot expose capacity beyond their supplied length.
- `render` uses a 65,535-byte workspace allocated at setup and serializes
  concurrent renders of that template. `render_with_scratch` uses caller-owned
  storage and permits parallel rendering and larger intermediates. At most 64
  argument values may be live across nested pipelines, and the combined action
  and parenthesis nesting limit is eight; deeper or larger templates fail at
  setup to bound worker stack use. Nested pipelines share one value workspace;
  malformed actions and exhausted workspaces return errors.
- Map ranges and printing use quadratic scans for Go's sorted key order without
  allocation. `js` and `printf %q` use Rust regex Unicode categories, which may differ from
  the Unicode version used by Go.
