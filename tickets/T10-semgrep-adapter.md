# T10 — Semgrep adapter

Model: Haiku
Status: blocked
Depends on: T01
Parallel group: G1 (with T02, T03, T04)
Branch: ticket/T10-semgrep

## Goal

The built-in Semgrep adapter: `probe`, `scan` (via the injected `Runner`), `parse`, `sourceRefs`, `normalize`, with sanitized fixtures. It satisfies the T01 `Adapter<SemgrepProbeContext, SemgrepScanContext>` contract without editing T01 files.

## Read first

- `specs/05-tool-adapters.md`: Adapter contract, Semgrep section (all tables)
- `specs/04-finding-schema.md`: Severity, Fingerprints (what the adapter hands over), Identifier limits (Unusable entry)
- `specs/03-cli-contract.md`: Output directory (the `--exclude` rule), `doctor` Semgrep bullet
- `src/contracts/adapter.ts` and `ports.ts` (T01)

## Owns

`src/adapters/semgrep/**` (including its own `index.ts` exporting the assembled adapter), `tests/unit/adapters/semgrep/**`, `tests/fixtures/semgrep/**`.

## Requirements

- `probe(ctx: SemgrepProbeContext, deps)`: needs no target, rules or root; runs `semgrep --version` through `deps.runner`; lenient parse of the first version-looking token; missing binary gives `status: unavailable` + `tool_unavailable`.
- `scan(ctx: SemgrepScanContext, deps)`: argv exactly `semgrep scan --json --metrics=off --disable-version-check --disable-nosem --timeout <ctx.ruleTimeoutSeconds> --config <rule>… [--exclude <ctx.excludeRelToTarget>] <ctx.targetRel>` with cwd `ctx.rootAbs`, process timeout `ctx.timeoutSeconds`, stdout cap from limits. `ctx.rules.mode` `registry`: `--config <id>` each; `auto`: `--config auto`; both omit `--metrics=off`, return reason `registry_rules` / `auto_rules` in `ScanOutput.reasons` and a `non_deterministic_rules` diagnostic in `ScanOutput.diagnostics`. Never pass `--error`, `--verbose`, `--strict`. Outcome: exit 0 gives `ok` with raw stdout; any non-zero exit gives `failed` + `tool_execution_failed` with a bounded stderr tail as untrusted `detail` (**[verify] V1**: exit 7 stays `failed`; do not guess otherwise); timeout gives `failed` + `tool_timeout`; stdout cap exceeded gives `failed` + `resource_limit_exceeded`; spawn failure gives `unavailable` + `tool_unavailable`. `coverageLoss` is empty at scan time.
- `parse`: JSON object with `results[]`, `errors[]`, `paths.scanned`; otherwise `unsupported_shape` or `invalid_json`.
- `sourceRefs`: one ref per usable result with key `<path>:<start>:<end>`.
- `normalize(doc, ctx, sources)`: treats every field as untrusted `unknown`. Per result: `ruleId` = `check_id`, `title` = rule id, `description` = `extra.message`, `severityOriginal` = `extra.severity`, severity via the `semgrep-1` table (anything else `unknown`), `confidence`/`category`/`references` only from `extra.metadata` when they have the expected types, `producerFingerprint` = `extra.fingerprint` when a string, positions from `start`/`end` (line, col; ignore offset), repository-root-relative POSIX path, evidence `producer_lines` from `extra.lines` as given (already redacted), `snippet` from `sources[key]` (`SourceText` mapped to the candidate shape). `redactionsApplied` is true when any pointer in `ctx.redactionTouched` starts with `/results/<index>/` or the matching `SourceText.redacted` is true. Entries missing `check_id`, `path` or positions count in `unusableCount`.
- Completeness (exit 0 only) per the spec 05 error table, returned in `NormalizeOutput.coverageLoss`/`completeness`/`diagnostics`: coverage-loss and rule-problem rows give `partial_coverage` and `partial`; `Internal matching error` and `Fatal error` give partial only when findings and scanned files remain, else `failed`; informational entries and `SemgrepWarning` without coverage impact become diagnostics only; any other type gives partial with `unmapped_error_type` (**[verify] V2**: list-encoded types such as `["PartialParsing", …]` are handled per the documented classification, wire format unverified). Empty or missing `paths.scanned` gives partial + `no_files_scanned`. Intentional exclusions never cause partial (**[verify] V6**: whether timeout-threshold skips appear in `paths.scanned` or `paths.skipped` is unknown; rely on `errors[]` only). Producer error messages go to `detail`. `producerVersion` = JSON `version` else `ctx.producerVersion` else null. `severityMappingVersion` = `semgrep-1`. `reasons` is empty at normalize time.
- `--disable-nosem` is unconditional (**[verify] V4**: confirm against the pinned Semgrep version; the argv test pins the flag but does not claim behavior).

## Tests (same ticket)

- Fixtures under `tests/fixtures/semgrep/<case>/` (raw input, expected candidates, `PROVENANCE.md` with a `Producer version:` line and `verify against real Semgrep`): clean scan, findings with all mapped severities and one unknown, each error-table row including list-encoded types, empty `paths.scanned`, malformed entries, metavars present, `lines` present.
- Adapter tests with a fake `Runner`: exact argv for local, registry and auto modes (with and without exclusion), reasons and diagnostics returned by `scan`, exit-code outcomes, timeout, spawn failure, stdout cap (**[verify] V9**: constants from T01).
- Purity: `parse`, `sourceRefs`, `normalize` run without filesystem or process access.

## Done when

`npm run build && node --test dist/tests/unit/adapters/semgrep` passes.

## Verification items

V1, V2, V4, V5 (fixture `PROVENANCE.md` version lines are written as `unknown — verify against real Semgrep`), V6, V7 (registry/auto digest handled as `null` by T08; the adapter only flags the reasons) and V9 stay `[verify]` in code comments and fixtures; do not invent resolutions.

## Notes

Optional split: pure (`parse`/`sourceRefs`/`normalize`) versus `probe`/`scan`.

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done.

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** V1, V2, V4, V5, V6, V7, V9. For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
