# Go template subset

The engine is under construction. It currently accepts literal text, `.Name`,
`.Zone`, `.Class`, `.Type`, `.Remote`, `.Regex`, `.Group.name`, `.Var.name`,
`index .Match N`, `.Meta "label"`, trim markers, `if`/`else`/`end` with a field, `range .Match`/`.Group`/`.Var` (including `.` and `$.Field`), `eq`, `len`, and `parseInt` with a field or a simple
quoted string and literal base and bit size. Missing Metadata renders as an
empty string; an out-of-range match or invalid `parseInt` fails at render time.
Pipelines and nested parentheses support `and`, `or`, `not`, `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `index`, `slice`, `len`, and `parseInt`. Go quoted-string escapes and raw strings are supported. Other actions fail compilation; in particular other pipeline functions and other range values are not yet supported. Map ranges are ordered but use quadratic scans to avoid allocation.

Nesting of actions and pipelines is limited to 255 levels to bound recursion.
String literals that decode to non-UTF-8 bytes are rejected because the output buffer is a Rust `String`.
String slices must end at UTF-8 boundaries; capture slices cannot expose capacity beyond their supplied length.
