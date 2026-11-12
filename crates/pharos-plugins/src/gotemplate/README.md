# Go template subset

The engine is under construction. It currently accepts literal text, `.Name`,
`.Zone`, `.Class`, `.Type`, `.Remote`, `.Regex`, `.Group.name`, `.Var.name`,
`index .Match N`, `.Meta "label"`, `if`/`else`/`end` with a field, and `parseInt` with a field or a simple
quoted string and literal base and bit size. Missing Metadata renders as an
empty string; an out-of-range match or invalid `parseInt` fails at render time.
Other actions fail compilation; in particular pipelines, range,
trim markers and Go quoted-string escapes are not yet supported.

Nesting is limited to 255 levels to bound recursive rendering.
