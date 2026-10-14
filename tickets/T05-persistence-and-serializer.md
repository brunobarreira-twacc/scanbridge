# T05 — Persistence: serializers, report store, output directory

Model: Haiku
Status: blocked
Depends on: T01, T02, T04
Parallel group: G2
Branch: ticket/T05-persistence

## Goal

Everything that turns documents into persisted bytes and artifacts: the canonical serializer, the raw serializer, the exclusive-create report store, output-directory validation, and `scan_id`.

## Read first

- `specs/02-architecture.md`: Report storage, Deterministic serialization
- `specs/03-cli-contract.md`: Output directory (`--output`)
- `specs/04-finding-schema.md`: `normalized.json` table (field set), Finding table (field set)

## Owns

`src/core/serialization/**`, `src/cli/store/**`, `src/cli/output-dir.ts`, `tests/unit/serialization/**`, `tests/unit/store/**`.

## Requirements

- `serializeCanonical(typeName, value): string` (pure, in `core/serialization`): declared field-order list for every object type in `OBJECT_TYPES` (T02) at every level; sort findings by fingerprint, occurrences with `compareOccurrences` (T04), and every non-semantic array (`references`, reason lists, redaction counts by rule id, `changed_fields`) by code-point order of its canonical string, deduplicated; 2-space indent; LF; exactly one trailing newline; integers only. Applies to `normalized.json` and `scan-result.json` (and compare output).
- `serializeRaw(parsed): string`: preserves the parsed object-key and array order exactly (never sorts); same format (2-space, LF, one trailing newline). Provide `sha256` of the exact UTF-8 bytes.
- `makeScanId(date: Date, digestHex: string)`: `YYYYMMDDTHHMMSS.mmmZ-<first 8 hex>`; the caller supplies the clock value.
- `ReportStore` (`src/cli/store`): `createScanDirectory(outputBase, scanId)` exclusive and never overwriting (create the missing base first with realpath and symlink checks, then create the scan directory non-recursively and fail if it exists); `writeRaw(name, text)`, `writeNormalized(text)`, `writeScanResult(text)` all with exclusive file creation; refuse empty content. It is the only module that writes artifacts.
- `validateOutputDir({ root, output, target?: string })` (`src/cli/output-dir.ts`): realpath; must resolve to a directory (create if missing); must not equal `target`; returns `{ outputBase, excludeRelToTarget: string | null }` where the exclusion is the normalized target-relative path when output is a strict descendant of the target. Returns typed errors (`not_a_directory`, `equals_target`, `symlink_escape`) for the caller to map to exit 1.

## Tests (same ticket)

- Same logical object built with different key insertion orders and different array input orders gives identical bytes; every declared order list covers exactly the keys of the matching Zod object (use `OBJECT_TYPES`); LF only; exactly one trailing newline.
- Raw: an unsorted fixture keeps its key and array order; hash equals SHA-256 of the exact bytes written (read back from the store).
- Store (temp directories): exclusive creation, second create of the same scan id fails and leaves existing files untouched, missing base created, empty content refused, no partial directory left after a refused write.
- Output directory: non-directory, equals target, descendant (relative exclusion path), sibling, ancestor, outside, symlinked base.
- `makeScanId` format and millisecond padding.

## Done when

`npm run build && node --test dist/tests/unit/serialization dist/tests/unit/store` passes.

## Notes

Do not decide when the scan directory is created in the pipeline; that is T14. No normalization logic here.

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done.

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** none owned by this ticket. For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
