# T14 — Scan orchestration, adapter assembly and end-to-end contract tests

Model: Sonnet
Status: blocked
Depends on: T03, T05, T06, T08, T09, T10, T11, T12, T13
Parallel group: G4 (alone)
Branch: ticket/T14-scan

## Goal

Assemble the ZAP adapter and the tool catalog, wire everything into the scan pipeline for Semgrep, live ZAP and offline ZAP, and prove the contracts end to end.

## Read first

- `specs/02-architecture.md`: Scan pipeline, Report storage, Redaction, Deterministic serialization
- `specs/03-cli-contract.md`: Exit codes, `scan` sections, Output directory, Envelopes
- `specs/05-tool-adapters.md`: Adapter contract; completeness rules per tool
- `specs/06-testing-and-acceptance.md`: Contract layer, Secret canary, Required coverage (CLI, ZAP flow, output, determinism)
- `src/contracts/*` and the public exports of T03, T05, T06, T08, T09, T10, T11, T12

## Owns

`src/cli/scan/**`, `src/cli/commands/scan.ts` (replaces the T13 stub), `src/adapters/zap/index.ts` (assembles `parse`/`sourceRefs`/`normalize` from T11 with `zapProbe`/`zapScan` from T12), `src/adapters/index.ts` (the `ToolCatalog`), `tests/contract/scan/**`, `tests/fixtures/e2e/**`. May make minimal fixes in other `src/` files only if a merged ticket has a defect; list each in the PR summary.

## Requirements

- Implement the pipeline in order (spec 02): validate flags and config, resolve root, build the redaction policy, `configuration_digest`, resolve ZAP inputs with the purpose-specific T08 function (live: `resolveZapLiveInputs`; offline: `resolveZapOfflineInputs`; `resolveZapDoctorInputs` is never used here), build `SemgrepScanContext` (Semgrep) or `ZapLiveScanContext` (live ZAP; the API key travels only inside `ZapProbeContext.apiKey` and `ZapLiveScanContext.apiKey`), output directory validation; probe with `{ producer: 'semgrep' }` or a `ZapProbeContext` built from the same live API URL and key (offline ZAP: no probe); target identity first reading (Semgrep); `scan` or offline file read (50 MiB cap, in memory); hash original output; `parse`; `redactTree` (with `removePaths: ['results.*.extra.metavars']` for Semgrep); serialize redacted raw and hash; `sourceRefs`, `SourceReader`, `redactText`, `normalize`; union `ScanOutput.reasons` with `NormalizeOutput.reasons`; `buildFindings`/`classify` (T06); second target reading (a changed digest adds partial `target_changed_during_scan`); enforce `normalized.json` 25 MiB (**[verify] V9**; exceeded gives failed, exit 3, raw kept); persist raw, `normalized.json`, then `scan-result.json` through the store; print the same envelope to stdout.
- Directory creation timing (locked decision, see README): create the exclusive scan directory right after step 1 validation succeeds and before probing, so every later failure can still write `scan-result.json`. Failures before that print the envelope with `artifacts` null.
- Outcomes and exit codes exactly as spec 03: complete and unverified exit 0; partial exit 4; unavailable exit 2; failed exit 3. No raw artifact when redaction fails (`redaction_failed`) or when the producer output was never accepted; never an empty report; no `normalized.json` for failed scans.
- Offline ZAP: neither `probe` nor `scan` is called (no probe context and no scan context exist); `mode: 'offline'`; the target origin for `NormalizeContext` comes from `resolveZapOfflineInputs`; no ZAP API URL or key is read or required; `unverified` and `offline_report`.
- `scan-result.json` fields per spec 03 including `exclusions[]`, `findings_count` (number of normalized findings), run data from the injected `Clock`; `scan_id` from `makeScanId` with a digest of config and target. The API key never appears in the envelope, diagnostics, artifacts, stderr or digests.
- Production `main` wires real ports (T09) and the real catalog.

## Tests (same ticket)

Contract tests run the built CLI as a subprocess in a temp repo. Semgrep: a fake `semgrep` executable (Node script written by the test, first on `PATH`) replays fixtures. ZAP: an in-process `127.0.0.1` HTTP server fakes the API.
- Semgrep: complete, findings, partial (each error class sample), failed (non-zero exit, timeout), unavailable, `no_files_scanned`, degraded fingerprint (unreadable file), output directory inside the target excluded from argv and digest, previous-run artifacts never rescanned, `target_changed_during_scan`, registry and auto modes (`registry_rules`/`auto_rules`, non-authoritative).
- ZAP live: happy path, dirty session (exit 3, no raw, no normalized, `scan-result.json` present, stdout equals it), reset mode, bad key and closed connection (exit 2), spider deadline (exit 4), zero URLs, out-of-scope alerts. ZAP offline: flag/env/override/neither, `--target-revision`, `--producer-version`, malformed and oversized input (exit 3, `scan-result.json` only), unverified exit 0, no API key needed.
- Offline ZAP also asserts, with a fake catalog whose `probe` and `scan` throw, that neither is called, and that unset API URL and key variables never matter. Semgrep and ZAP probe contexts contain no dummy target, scan ID or key values.
- Cross-cutting: secret canary in fake producer input (snippets per built-in pattern, a configured env value) and a canary ZAP API key never appear in artifacts, stdout, stderr or diagnostics; `normalized.json` byte-identical across two runs on identical input; stdout is exactly the content of `scan-result.json`; exclusive creation (second identical `scan_id` refused); disabled adapter is a usage error.
- **V5 and fixtures:** a test walks `tests/fixtures/{semgrep,zap}/*/` and fails if a case lacks `PROVENANCE.md`, a `Producer version:` line (a version or `unknown — verify against real <tool>`), or the `verify against real <tool>` marker where the version is unknown. Pinning versions is left to the live-verification follow-up and is not guessed here.
- **V9 final validation:** a test asserts that numeric limits appear only in `src/contracts/limits.ts` (no duplicated literals in `src/`), and boundary tests (one below, exactly at, one above) exist for the limits enforced in this ticket (raw size, normalized size).

## Done when

`npm ci && npm run build && npm test` passes from a clean checkout of merged `main`; `npm run check:schemas` passes.

## Verification items

V5 and V9 are owned here for final integration; V1–V4, V6–V8 stay `[verify]` in their owning tickets and are never resolved by this ticket.

## Notes

Largest ticket. If it must be split, do it by files and sequentially: (a) pipeline plus the Semgrep path with Semgrep contract tests, then (b) ZAP live and offline paths plus the cross-cutting suites. Never in parallel; they share `src/cli/scan/**`.

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done. List every minimal fix made outside owned paths, with file and reason, under "Files changed".

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** V5 and V9 (final validation); V1–V4 and V6–V8 stay untouched in their owning tickets. For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
