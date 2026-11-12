# Go template subset

The engine is under construction. It currently accepts literal text, `.Name`,
`.Zone`, `.Class`, `.Type`, `.Remote`, `.Regex`, `.Group.name`, `.Var.name`,
`index .Match N`, `.Meta "label"`, trim markers, `if`/`else`/`end`, `range` over capture lists, maps, or integers (including pipelines, `.`, `$.Field`, and scoped index/value variables), `eq`, `len`, and `parseInt` with a field or a simple
quoted string and literal base and bit size. Missing Metadata renders as an
empty string; an out-of-range match or invalid `parseInt` fails at render time.
Pipelines and nested parentheses support `and`, `or`, `not`, `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `index`, `slice`, `len`, `print`, `println`, `printf`, `html`, `js`, `urlquery`, `parseInt`, and the `.Meta` method. `printf` supports `%s`, `%d`, `%x`, `%X`, `%g`, `%t`, `%q`, `%T`, `%v`, and `%%`, with basic integer/string widths. Other verbs and formatting flags return a rendering error. Go quoted-string escapes and raw strings are supported. Other actions fail compilation; in particular `call` and other range values are not yet supported. Map ranges are ordered but use quadratic scans to avoid allocation.

Nesting of actions and pipelines is limited to 255 levels to bound recursion.
String literals that decode to non-UTF-8 bytes are rejected because the output buffer is a Rust `String`.
String slices must end at UTF-8 boundaries; capture slices cannot expose capacity beyond their supplied length.
Pipeline formatting uses a 65,535-byte stack scratch buffer and at most 1,024 arguments; overflowing either bound is an error.
`js` uses Rust regex Unicode character categories, which may differ from Go's Unicode version.
When `Data.message` is supplied, `.Message` exposes the header fields (`Id`,
`Opcode`, `Rcode`, and flag booleans), `.Message.Question` supports indexing
and range, and `.Question` exposes `Name`, `Qtype`, and `Qclass`. Other Message
fields and sections are not yet implemented.
