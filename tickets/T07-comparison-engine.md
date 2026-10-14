# T07 — Comparison engine

Model: Haiku
Status: blocked
Depends on: T01, T02
Parallel group: G2
Branch: ticket/T07-comparison

## Goal

A pure function implementing spec 07 completely.

## Read first

- `specs/07-comparison.md`: whole file
- `specs/04-finding-schema.md`: Severity, Compare-level reasons, Finding table
- `specs/03-cli-contract.md`: `compare` section only

## Owns

`src/core/comparison/**`, `tests/unit/comparison/**`.

## Requirements

- `compareDocuments(base: NormalizedDocument, head: NormalizedDocument, opts: { allowPartial: boolean }): CompareOutcome` where `CompareOutcome` is `{ ok: true; result: CompareResult } | { ok: false; error: 'incompatible_reports' | 'partial_input_refused' }`. Input is already schema-validated by the caller.
- Refusals: different `producer` gives `incompatible_reports`; an input with `completeness: partial` without `allowPartial` gives `partial_input_refused`. `unverified` inputs never need the flag.
- Authority and reasons exactly as spec 07: input reasons kept separately; `base_input_non_authoritative` / `head_input_non_authoritative`; `partial_input_allowed`; producer version mismatch or incomparable (null on either side); `rules_digest`, `redaction_policy_version`, `fingerprint_version`, `severity_mapping_version` mismatches; target comparability per kind; `configuration_digest` difference only in `metadata.configuration_digest_equal`.
- Per finding: build Finding references (`rule_id`, `producer_reference`, `title`, `fingerprint_quality`, `severity`, `severity_original`, `severity_complete`, `confidence`, `occurrence_count`, `occurrence_severities` = sorted multiset of occurrence `severity_original`).
- State precedence: differing `fingerprint_version` gives one `incomparable` one-sided entry per finding per side, no matching; otherwise one-sided entries are `incomparable` when absence is untrusted (list in spec 07) else `new`/`resolved`; both-sided entries follow severity increase/decrease, then `changed`, then `unchanged`.
- `severity_comparison`: `comparable` only if both severities known, both `severity_complete`, and equal `severity_mapping_version`; one-sided entries are always `incomparable` with `changed_fields: []`.
- `changed_fields` (sorted) from `confidence`, `evidence`, `occurrence_count`, `occurrence_severities`, `severity_original`, `title`. `evidence` compares the sorted multiset of text values found in each occurrence's evidence (`{text}` fields only; ignore `message_id`, locations and line numbers).
- Entries sorted by fingerprint, base entries before head entries; `summary` has one count per state plus `severity_comparison_incomparable`; `base`/`head` sections as defined by the T02 schema (`asserted_revision` echoed with `asserted: true`).

## Tests (same ticket)

- Every state; precedence (`severity_increased` with other `changed_fields`); head-only and base-only shapes; differing fingerprint versions.
- Each absence trigger (partial or unverified lacking side, rules mismatch, redaction policy mismatch, subject mismatch, either input `fingerprint_degraded`) and each non-trigger (producer version, mapping mismatch, null digest alone, `unmapped_severity`, `partial_input_allowed`).
- Severity comparison for `unknown`, `severity_complete: false`, mapping mismatch.
- Target comparability matrix for git, directory, http_origin; two complete live ZAP documents with asserted revisions are authoritative; an offline document never is.
- Refusals; `allowPartial` adds `partial_input_allowed`; output validates against the T02 `CompareResult` schema; same inputs give identical output.

## Done when

`npm run build && node --test dist/tests/unit/comparison` passes.

## Notes

File reading, schema validation and printing belong to T13.

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done.

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** none owned by this ticket. For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
