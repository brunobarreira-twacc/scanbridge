# T11 — ZAP adapter: parse and normalize (live and offline input)

Model: Haiku
Status: blocked
Depends on: T01, T04
Parallel group: G2 (parallel with T12; no shared files, no dependency between them)
Branch: ticket/T11-zap-normalize

## Goal

Pure parsing and normalization of the alerts-API dump `{"alerts":[...]}`, shared by live scans and `--from-report`. Exports plain functions; the final adapter assembly is T14's job.

## Read first

- `specs/05-tool-adapters.md`: ZAP section (Raw format, Normalization, severity mapping, Offline, Limitations)
- `specs/04-finding-schema.md`: Severity, Fingerprints (ZAP rows and URL normalization), Identifier limits
- `specs/03-cli-contract.md`: the offline scan section
- `src/contracts/adapter.ts` (T01)

## Owns

`src/adapters/zap/parse.ts`, `src/adapters/zap/normalize.ts`, `src/adapters/zap/severity.ts`, `tests/unit/adapters/zap-pure/**`, `tests/fixtures/zap/**`.

## Requirements

- Export `parse(raw: Uint8Array): ParseResult`, `sourceRefs(doc): SourceRef[]` (always `[]`) and `normalize(doc, ctx, sources): NormalizeOutput` with exactly the T01 signatures. Do not create `src/adapters/zap/index.ts`, `probe.ts` or `scan.ts`; do not import from T12 files.
- `parse`: accept exactly an object with an `alerts` array; reject Traditional JSON report shape and anything else (`unsupported_shape`), invalid JSON (`invalid_json`). Tolerate numeric-looking strings.
- `normalize`: read each alert as untrusted `unknown`: `pluginId`, `alertRef`, `name`/`alert`, `description`, `risk`, `confidence`, `url`, `method`, `param`, `attack`, `evidence`, `other`, `inputVector`, `messageId`, `reference`. Field names and casing come from ZAP source (**[verify] V3**): centralize them in one `FIELDS` table in this file.
  - Candidate: `ruleId` = `pluginId`, `producerReference` = `alertRef` (null if missing, empty or not a string), `title` = alert name, `description`, `confidence` = text verbatim (never mapped), `severityOriginal` = `risk` text, severity via `zap-1` in `severity.ts` (exact, case-sensitive: `Informational→info`, `Low→low`, `Medium→medium`, `High→high`, else `unknown`; **[verify] V3** strings on real ZAP), `references` from `reference` split on whitespace, `location.runtime` = `{ url, method, param }` using the redacted raw URL string (T06 normalizes), evidence `attack`, `evidence`, `other`, `input_vector`, `message_id`. No source mapping; no request/response data.
  - Scope: with `ctx.targetOrigin`, each alert URL is checked with T04 `normalizeUrl`; outside-origin alerts are excluded and counted in one `out_of_scope_target` diagnostic. A URL containing control characters or that cannot be parsed cannot be origin-checked: exclude it and count it in the same diagnostic (locked decision).
  - Entries missing `pluginId` or `url` (missing or not strings) count in `unusableCount`.
  - Deduplicate identical alerts (all compared fields equal) and sort deterministically before emitting candidates.
  - Completeness: `ctx.mode === 'offline'` gives `unverified` with reason `offline_report`; otherwise a non-empty `ctx.coverageLoss` gives `partial` (its diagnostics returned in `NormalizeOutput.coverageLoss`); else `complete`. Offline plus coverage loss does not occur. `severityMappingVersion` = `zap-1`; `producerVersion` = `ctx.producerVersion`.

## Tests (same ticket)

- Fixtures under `tests/fixtures/zap/<case>/` with `PROVENANCE.md` (`Producer version: unknown — verify against real ZAP`): normal dump, empty alerts, duplicates, unknown risk text, missing and non-string `alertRef`, out-of-scope URLs, URL with control characters, Traditional JSON report (rejected), malformed entries, numeric fields as strings.
- Mapping table with exact-match checks (case-sensitive) and unknown values.
- Live versus offline `ctx` give `complete`/`partial` versus `unverified` + `offline_report`.
- Same dump twice gives identical output; shuffled alert order gives identical output.
- Purity: no filesystem or network access.

## Done when

`npm run build && node --test dist/tests/unit/adapters/zap-pure` passes.

## Verification items

V3 (field names and casing, risk strings) stays `[verify]` in the `FIELDS` table and the fixtures' `PROVENANCE.md`. V5: each `PROVENANCE.md` carries `Producer version: unknown — verify against real ZAP`; no version is pinned.

## Notes

T11 and T12 edit no common file; the assembled adapter lives in T14.

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done.

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** V3, V5. For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
