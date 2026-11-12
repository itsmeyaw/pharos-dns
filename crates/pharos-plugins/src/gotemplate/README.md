# Go template subset

The engine is under construction. It currently accepts literal text, `.Name`,
`.Zone`, `.Class`, `.Type`, `.Remote`, `.Regex`, `.Group.name`, `.Var.name`,
`index .Match N`, `.Meta "label"`, trim markers, `if`/`else`/`end` with a field, `range .Match` (including `.` and `$.Field`), `eq`, `len`, and `parseInt` with a field or a simple
quoted string and literal base and bit size. Missing Metadata renders as an
empty string; an out-of-range match or invalid `parseInt` fails at render time.
Simple pipelines support `and`, `or`, `not`, `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `len`, and `parseInt`. Other actions fail compilation; in particular other pipeline functions, other range values and Go
quoted-string escapes are not yet supported.

Nesting is limited to 255 levels to bound recursive rendering.
