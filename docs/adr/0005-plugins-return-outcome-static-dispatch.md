# Plugins return their outcome and are dispatched statically

CoreDNS Plugins write to a shared response writer and return a status code that the server mostly ignores, so "has a Response been written?" is implicit and Plugin errors are lost. Pharos Plugins instead return an outcome (a Response, a stream of Messages for Zone Transfer, a deliberate drop, an unanswered RCODE for the Listener to answer, or an error that is logged and answered with SERVFAIL), and Plugins earlier in the Plugin Chain alter the returned Response on its way back. Static dispatch uses a `plugin.cfg`-generated struct of optional Plugins and a monomorphised Next per position; the hot path does not allocate per Query.

## Considered Options

- CoreDNS-style response writer: rejected, it reproduces the ambiguity ADR-0002 asks us to fix.
- `dyn` Plugins with boxed futures: rejected for per-call allocation.
- Recursive async dispatch over an enum slice: rejected because each hop requires boxing.
- Synchronous fast path with async only where needed: rejected as two contracts to maintain.

## Consequences

Adding a Plugin requires a module, a Cargo feature, a `plugin.cfg` entry and a generator mapping; the positional chain is regenerated at build time.
