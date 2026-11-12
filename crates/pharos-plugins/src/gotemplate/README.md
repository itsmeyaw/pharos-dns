# Go template subset

The engine is under construction. It currently accepts literal text, `{{ .Name }}`
and `{{ .Meta "label" }}`. Missing Metadata renders as an empty string. Other
actions fail compilation; in particular fields, functions, pipelines, control
actions, trim markers and Go quoted-string escapes are not yet supported.
