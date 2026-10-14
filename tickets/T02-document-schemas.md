# T02 — Document schemas and JSON Schema emission

Model: Haiku
Status: blocked
Depends on: T01
Parallel group: G1 (with T03, T04, T10)
Branch: ticket/T02-schemas

## Goal

Zod schemas for every JSON document Scanbridge emits or reads (except the config file, T08), plus committed JSON Schema files and the drift and equivalence tests.

## Read first

- `specs/04-finding-schema.md`: whole file (shapes, examples)
- `specs/03-cli-contract.md`: Envelopes, doctor JSON example, compare output line
- `specs/07-comparison.md`: `findings[]`, Finding reference
- `specs/06-testing-and-acceptance.md`: Schema validation bullet

## Owns

`src/schemas/**`, `schemas/**`, `scripts/gen-schemas.mjs`, `tests/unit/schemas/**`.

## Requirements

- Build all schemas with Zod 4. Every object is strict (unknown keys rejected). Enums come from `src/contracts/enums.ts`. Integers only (no floats). Avoid Zod features that `z.toJSONSchema()` cannot represent.
- Schemas: `NormalizedDocument` (with `Finding`, `Occurrence`, `TextField`, `Target` as a discriminated union on `kind`, `RedactionSummary`), `ScanResult` envelope (including `exclusions[]`, `diagnostics[]`, `artifacts` with nullable fields), `ErrorEnvelope`, `DoctorResult`, `CompareResult` (entries and Finding reference per spec 07; `base`/`head` sections: `producer_version`, `completeness`, `authoritative`, `non_authoritative_reasons`, `asserted_revision` marked `asserted: true`; plus `metadata.configuration_digest_equal`).
- Representations follow spec 04 exactly. Structured `TextField` `{text, truncated, original_length}`: `title`, `description`, `confidence` (nullable), snippet, evidence text values, and a diagnostic `detail` (`TextField` plus `untrusted: true`). Plain strings: `severity_original` (finding and occurrence), `category` (nullable), `references[]`, evidence `message_id`.
- `content_trust` is the literal `"untrusted_producer_content"`; `status` on findings is the literal `"open"`.
- Export inferred types and `OBJECT_TYPES: Record<string, ZodObject>` listing every object type by name (T05 uses it to prove field-order coverage).
- `scripts/gen-schemas.mjs` (plain Node, imports compiled `dist/`): writes `schemas/<name>.schema.json` with 2-space indent, LF, one trailing newline, stable key order; `--check` regenerates in memory and exits non-zero on any difference or missing file.
- Commit the generated `schemas/*.json`.

## Tests (same ticket)

- `check:schemas` equivalent: committed files equal regenerated output.
- Equivalence corpus per schema, at least 5 valid and 8 invalid documents (unknown key, wrong enum, float, wrong literal, missing field, bad target kind, wrong completeness): the verdict from Zod and from the emitted schema (validated with `ajv`, strict mode) is identical for every document.
- The spec 04 Semgrep and ZAP finding examples (with `<64 hex>` replaced by real-looking hex) validate.

## Done when

`npm run build && npm run gen:schemas && npm run check:schemas && npm test` pass.

## Notes

Do not implement the serializer (T05) or any logic. `compare` base/head and `metadata` shapes are minimal and locked: only the fields listed in Requirements, no others.

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done.

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** none owned by this ticket. For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
