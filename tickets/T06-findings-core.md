# T06 — Findings core

Model: Sonnet
Status: blocked
Depends on: T01, T02, T04
Parallel group: G2
Branch: ticket/T06-findings

## Goal

Pure construction of normalized findings and document metadata from adapter candidates: sanitization, truncation, identity guards, fingerprints, grouping, severity aggregation, limits, completeness and authority.

## Read first

- `specs/04-finding-schema.md`: Finding, Text field paragraphs, Severity, Fingerprints, Identifier and location limits, Diagnostics and reasons
- `specs/01-scope-and-decisions.md`: Fixed limits
- `src/contracts/adapter.ts` (the `Candidate`, `NormalizeOutput`, `RawDiagnostic` types from T01)

## Owns

`src/core/findings/**`, `tests/unit/findings/**`.

## Requirements

- `buildFindings(candidates, { producer }): { findings: Finding[]; diagnostics: RawDiagnostic[]; coverageLoss: RawDiagnostic[]; reasons: ScanReason[] }`.
- Field representations follow the T02 schemas (spec 04):
  - Structured `{text, truncated, original_length}`: `title`, `description`, `confidence` (null when unsupplied), snippet and every evidence text value, diagnostic `detail`. Replace U+0000–U+0008, U+000B, U+000C, U+000E–U+001F, U+007F with U+FFFD (tab, LF, CR kept), then truncate after redaction at the limit by code points, never splitting a code point. `original_length` is a code-point count.
  - Plain strings: `severity_original` (finding and occurrence), `category`, `references[]`, `message_id`. Sanitize with the same U+FFFD replacement; never turn them into structured objects.
- `references`: strings, already redacted by the caller; sanitize; omit any longer than 2,048 code points (never truncate); sort by code-point order and deduplicate; keep at most 20; emit one `resource_limit_exceeded` warning recording the counts of omitted items; reference omission does not change completeness.
- Identity values go through `guardIdentity` (T04). A placeholder makes the finding `degraded` with reason `fingerprint_degraded`, plus a `resource_limit_exceeded` (oversized) or `malformed_report` (invalid) warning. ZAP `producerReference` missing, empty or not a string gives null, material `""`, degraded.
- Semgrep fingerprints: snippet `ok` gives `semgrepExact` with `canonicalizeSnippet`; snippet failed, over-limit path, or invalid path gives `semgrepDegraded` and `fingerprint_degraded`. ZAP uses `normalizeUrl(...).targetPath`; a URL that cannot be normalized or fails the guard uses the placeholder.
- Group by fingerprint: `occurrence_count` is the total; `occurrences[]` sorted with `compareOccurrences` and capped at 100 (excess dropped, `partial_coverage` in `coverageLoss`). Each occurrence keeps its own `severity` and `severity_original`.
- Severity: group severity is the highest-ranked known occurrence severity; finding `severity_original` is the first occurrence in canonical order with that severity; any unknown occurrence gives `severity_complete: false` plus reason `unmapped_severity`; all unknown gives `unknown` with `severity_original` from the first occurrence.
- Findings sorted by fingerprint and capped at 10,000 (excess dropped, `partial_coverage`).
- `redactions_applied` is true if any occurrence candidate had `redactionsApplied`.
- `finalizeDiagnostics(raw[])`: builds schema `Diagnostic` objects; `message` passes through unchanged; `detail` becomes a sanitized, truncated, `untrusted: true` structured text.
- `classify(input)`: inputs are the `NormalizeOutput`, the `ScanOutput` facts (`coverageLoss`, `reasons`), `buildFindings` results and the finding count. Returns final `completeness`, `authoritative` and `non_authoritative_reasons`: `partial_scan` when partial; `registry_rules`/`auto_rules`/`offline_report` carried from the unioned scan and normalize reasons; `fingerprint_degraded` and `unmapped_severity` from findings. Unusable entries: `malformed_report` diagnostic with count; partial if findings remain, failed if none remain. Reasons sorted and deduplicated. An `unverified` adapter result stays `unverified` unless coverage loss makes it partial.

## Tests (same ticket)

- Table-driven candidates for both producers: exact and degraded paths, every guard outcome, grouping of identical fingerprints, occurrence cap at 99/100/101, finding cap at 10,000 using generated candidates (**[verify] V9**: limits are constants from T01).
- References: redaction-token strings pass through, control characters replaced, over-limit omitted, sorted, deduplicated, cap 20, warning emitted once with counts, completeness unchanged; references stay strings in the output.
- `severity_original`, `category`, `message_id` sanitized but still plain strings; `confidence`, `title`, `description` structured.
- Severity aggregation cases from spec 04 (mixed known, partly unknown, all unknown, tie-break by canonical order).
- Truncation at a code-point boundary with an astral character at the cut.
- `classify` truth table, including empty findings plus unusable entries giving failed, unverified input, partial from coverage loss.
- Determinism: shuffled candidate input produces identical output.

## Done when

`npm run build && node --test dist/tests/unit/findings` passes.

## Verification items

V9 (limit values) stays `[verify]`; use only `src/contracts/limits.ts` constants, no literals.

## Notes

No IO, no redaction call (inputs are already redacted), no file reads (snippets arrive on the candidate).

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done.

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** V9. For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
