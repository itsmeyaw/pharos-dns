---
name: conformance-audit
description: Multi-level subagent swarm that audits Pharos DNS against every RFC and Kubernetes KEP/spec it touches, both directions (spec → code, code → spec), and records the non-conformant findings in docs/conformance.md, then adds missing citation comments to conformant code.
disable-model-invocation: true
---

# Conformance audit

You are the **orchestrator** (level 0). You write no verdicts yourself: you build the inventory, dispatch a swarm of subagents in levels, check their coverage, and merge their output into `docs/conformance.md`. The audit is **relentless**: every section of every in-scope document, and every protocol-relevant line of code, ends up in a row or a coverage-ledger line of the fragments under `target/conformance/`. `docs/conformance.md` publishes only the rows that are not conformant. Use `caveman` skill. No compile or live testing, code-based only. Long-running task.

Two sweeps run in parallel and meet in the merge:

- **Spec-down**: for each document, walk every section and find the code that implements it (or record that none does).
- **Code-up**: for each source file, walk every protocol behaviour and find the section that governs it (or record that none does).

A row that only one sweep found is a coverage gap to chase, never a row to drop.

## Scope

- Code: every `*.rs` under `crates/`, `xtask/`, `tests/`, plus plugin `README.md` files and `docs/`. Skip any `target/` directory (including `crates/pharos-proto/fuzz/target/`).
- Documents:
  - Every RFC cited anywhere in scope: `rg -oN --no-filename 'RFC ?[0-9]{3,5}' crates xtask tests docs -g '!**/target/**' | sort -u`.
  - Every RFC that **updates or obsoletes** an in-scope RFC (`updated_by` / `obsoleted_by` in its `rfcN.meta.json`), recursively, when it changes DNS behaviour Pharos implements.
  - Every KEP cited in scope (`rg -o 'KEP-?[0-9]+'`), plus the KEPs behind the Kubernetes behaviour Pharos serves (Services, EndpointSlices, dual-stack, Multi-Cluster Services, topology), found from `crates/pharos-kubernetes` and `crates/pharos-plugins/src/kubernetes`.
  - The Kubernetes DNS-Based Service Discovery spec (id `k8s-dns`).

## Spec library

All spec text lives in `target/conformance/specs/`, fetched once by you in step 1 with the bundled script (path relative to this skill's directory):

```sh
scripts/fetch-spec.sh target/conformance/specs RFC1035 RFC2181 KEP-1645 k8s-dns …
```

Per id it writes and prints: `rfcN.txt`, `rfcN.meta.json` (updates, updated by, obsoleted by), `rfcN.errata.json` (non-rejected errata; only `Verified` is normative), `kep-N.md` (resolved under any SIG, printed with its GitHub URL), `k8s-dns-spec.md`. It exits non-zero naming any id it could not fetch. Subagents read from this library and never fetch spec text themselves; give every prompt the library path.

## Row format

Subagents return full rows only for verdicts that are not conformant (**Deviation**, **Violation**, **Partial**, **Missing**), in exactly this shape, one table per document:

```markdown
| Section | Code location | Explanation | Documented |
|---|---|---|---|
| §4.1.1 RCODE | `crates/pharos-proto/src/header.rs:88-104` | **Partial**: … | Yes |
```

**Conformant** and **N/A** requirements get no row. Instead, every subagent appends a coverage ledger, one line per section or file it checked, so coverage stays provable without the text:

```markdown
Coverage
- RFC 1035 §4.1.1: C3 P1 · header.rs:88-104
- RFC 1035 §1: NA1
- crates/pharos-proto/src/header.rs: RFC 1035 §4.1.1, RFC 6891 §6.1.3
- Cite crates/pharos-proto/src/header.rs:91 · `// RFC 1035 §4.1.1: RCODE 3 means the queried name does not exist.`
```

- Section lines: verdict counts (`C` Conformant, `NA` N/A, `D` Deviation, `V` Violation, `P` Partial, `M` Missing; omit zeros), then the main code location for any `C` count, or nothing if all are `NA`.
- File lines: the sections the file was mapped to, or `Unmapped code` (any unmapped behaviour also gets a full row).
- Cite lines: one per **Conformant** requirement whose code carries no citation, or a citation naming the wrong section: the line the logic starts on, and the exact comment to put above it. The comment follows the house style already in the code: `// <document> §<section>: <what this code does, one sentence>.`, where `<document>` is `RFC NNNN`, `KEP-NNNN`, or `Kubernetes DNS spec <version>`. A miscited line replaces the wrong comment instead of adding one.

- **Section**: section number and title. One row per normative requirement (MUST/SHOULD/MAY or equivalent prose), so a section can span several rows.
- **Code location**: `path:line` or `path:start-end`, repo-relative; several locations comma-separated; `—` when nothing implements it.
- **Explanation**: starts with one verdict, then one or two sentences of evidence.
  - **Conformant**: code does what the text requires.
  - **Deviation**: differs on purpose; name the ADR (`docs/adr/`) or plugin README that justifies it (ADR 0002 allows CoreDNS-compatible behaviour).
  - **Violation**: differs with no recorded justification.
  - **Partial**: some of the requirement is met; say what is missing.
  - **Missing**: requirement applies to Pharos but no code implements it.
  - **N/A**: does not apply to Pharos (say why), or informative text.
- **Documented**: `Yes` when a citation comment at the code location names this document and section (AGENTS.md rule, e.g. `RFC 1034 §4.3.2: …`) or a plugin README / ADR records it; otherwise `No`. A citation naming the wrong section is `No`, with the miscitation stated in Explanation.

## Levels

### Level 1: leads

One **document lead** per in-scope document, one **code lead** per crate (plus one for `xtask/` + `tests/`). A lead plans and dispatches; it splits work for level 2 and merges its workers' rows into one fragment.

- Document lead: reads the document, its errata, and its updating RFCs from the spec library; lists every section from the table of contents down to the deepest numbered subsection; groups them into chunks of about 5 sections; dispatches one level-2 auditor per chunk.
- Code lead: lists every source file in its crate; groups them into chunks of about 3 files (one large file alone); dispatches one level-2 sweeper per chunk.

### Level 2: workers

- **Section auditor**: for each assigned section, reads the current normative text from the spec library (base RFC + `Verified` errata + updating RFCs), extracts every requirement, then searches the code (rg on the field names, constants, record types, and section number) and reads the code it finds. Returns non-conformant rows and its coverage ledger.
- **Code sweeper**: reads every function in its files; for each protocol behaviour (parsing, encoding, limits, defaults, error codes, timing, record selection, Kubernetes object mapping) maps it to the governing section and checks existing citation comments for accuracy. Returns non-conformant rows keyed by document and its coverage ledger; behaviour with no governing section goes under a document heading `Unmapped code` with Section `—`.

### Level 3: verifiers

After merge, one **verifier** per document fragment re-reads every row in the fragment, plus at least 10% of its ledger's `C` sections chosen at random, against the text and code. It corrects wrong rows in place. A ledger section that turns out not to be conformant gets a full row, with its counts fixed. It also checks every Cite line in the fragment: the section must govern that code, and the comment must state what the code does; it fixes or drops bad ones. It returns only the changes it made.

### Level 4: citers

After the report is written, one **citer** per crate (plus one for `xtask/` + `tests/`) applies that crate's Cite lines, so no two citers touch the same file. It works file by file from the bottom line up, so earlier line numbers stay valid, and matches the indentation of the line below. It edits comments only; it reports any Cite line whose target line no longer holds the described logic, without applying it.

A lead without the subagent tool returns its chunk plan (chunk list, each with its sections or files) as its whole result and audits nothing itself; you then dispatch level 2 for each chunk directly, writing to `target/conformance/<doc-or-crate>/<chunk>.md`, and merge the chunks into the lead's fragment.

## Steps

1. **Inventory**. Record `git rev-parse HEAD`. Build the document list and the file list from Scope. Fetch every document into the spec library, then re-run the fetch for each new id in the `updated_by` / `obsoleted_by` fields of the fetched `rfcN.meta.json` files until no new in-scope RFC appears. Write the document list (with local path and source URL) and the file list to `target/conformance/inventory.md`. Done when every citation from the `rg` command maps to a document entry, the fetch script exits 0 for every document, and every in-scope file is listed.
2. **Dispatch level 1** in waves of up to 8 concurrent leads until every document and crate has one. Each lead's prompt carries: its document or crate, the Scope and Row format sections verbatim, the level-2 brief for its workers, the output path `target/conformance/<doc-or-crate>.md`, the spec library path, and the commit SHA. Tell leads to write fragments (non-conformant rows plus the merged ledger) to that path and return only a summary (sections or files covered, row count, verdict counts).
3. **Coverage check**, from the ledgers. Done when, for every document, every section in its table of contents has a ledger line, and every in-scope file has a file line. Re-dispatch a lead for each gap until clean.
4. **Cross-reconcile** spec-down and code-up per document: merge rows with the same section and location. For a row that only one sweep found, or a ledger section whose verdicts differ between the sweeps, dispatch a section auditor to confirm and complete it.
5. **Dispatch level 3** verifiers; apply their corrections.
6. **Write `docs/conformance.md`**:
   - Header: date, the audited commit SHA (all line numbers refer to it), document count.
   - Summary table: one row per document with counts per verdict (all verdicts; **Conformant** and **N/A** counts come from the ledgers), the count of `Documented: No` among its rows, and the count of Cite lines.
   - Only the non-conformant rows: **Deviation**, **Violation**, **Partial** and **Missing**. Ledgers stay in the fragments.
   - One `## RFC NNNN: Title` (or `## KEP-NNNN: Title`, `## Kubernetes DNS spec`) section per document with at least one such row, ordered by RFC number then KEPs, each holding its table sorted by section number. A document with none appears only in the summary table.
   - Final `## Unmapped code` table, if it has rows.
   Done when every non-conformant fragment row appears exactly once and the summary counts match the fragments. Commit the report on its own.
7. **Cite**. Collect every Cite line from the fragments, drop duplicates (both sweeps can propose the same one; keep the clearer comment), group them by crate, and dispatch level 4. Done when every Cite line is applied or reported stale, `git diff -U0 | rg '^[+-][^+-]' | rg -v '^[+-]\s*//'` prints nothing (only comment lines changed), and `cargo check --workspace --all-targets` passes. Commit once per crate.
8. Report to the user: path, summary table, the list of **Violation** and **Missing** rows, the number of citations added or corrected, and any stale Cite lines.
