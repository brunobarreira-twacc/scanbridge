# T13 — CLI shell, `doctor`, `compare`

Model: Haiku
Status: blocked
Depends on: T01, T02, T05, T07, T08
Parallel group: G3 (alone)
Branch: ticket/T13-cli-shell

## Goal

The executable entry point, argument validation for all commands, envelopes and exit codes, and the complete `doctor` and `compare` commands. `scan` is routed to a stub that T14 replaces.

## Read first

- `specs/03-cli-contract.md`: whole file
- `specs/07-comparison.md`: Authority (only to know `compare` output comes from T07)
- `specs/06-testing-and-acceptance.md`: CLI contract bullet

## Owns

`src/cli/main.ts`, `src/cli/args.ts`, `src/cli/envelope.ts`, `src/cli/exit.ts`, `src/cli/commands/doctor.ts`, `src/cli/commands/compare.ts`, `src/cli/commands/scan.ts` (stub only; T14 owns it afterwards), `tests/unit/cli/**`, `tests/contract/cli-shell/**`.

## Requirements

- `main(argv, deps)` takes injected ports and a `ToolCatalog` so tests can fake everything; `bin` entry reads `process.argv` and exits with the mapped code. Stdout receives exactly one JSON document plus a newline on every path; stderr receives human logs only; nothing else is written.
- `parseArgs` in strict mode. Validate per command: `doctor [--config] [--json]`; `compare --base-report --head-report [--allow-partial] [--json]`; `scan --adapter semgrep|zap --output ...` with the flag matrix from spec 03 (semgrep needs `--target`; `--target-url`/`--from-report` invalid for semgrep; zap rejects `--target`; `--from-report` conflicts with live-only flags; `--producer-version` only with `--from-report`; revision and version validated as length ≤ 128 and `[A-Za-z0-9._/@:+-]`). Violations are `usage_error` (exit 1) through the T02 `ErrorEnvelope`. Unknown flags and missing required flags are usage errors.
- Envelope helpers use the T05 serializer and T02 schemas; error envelopes carry Scanbridge-authored messages only.
- `doctor`: load config (T08; failures `invalid_configuration`, exit 1), then for each enabled tool call `probe` through the catalog; disabled tools `skipped`; Semgrep probe receives `{ producer: 'semgrep' }` (no target). ZAP: call T08 `resolveZapDoctorInputs({ config, env })` (never the live or offline resolvers; doctor never reads or requires a target URL, `--target-url` or `target_url_env`). Resolution problems count as readiness failures (exit 2) and the probe is skipped. When `apiUrl` and `apiKey` are both resolved, pass the `SensitiveString` unchanged inside `ZapProbeContext` to `catalog.zap.probe`. Doctor output exposes only key presence: `api_key: "present" | "missing"` (from `apiKeyPresent`) and `api_key_verified: false`; the key value, its length and any derived form are never printed, logged, persisted or put in diagnostics, and doctor never calls `reveal()`. Output shape per spec 03; exit 0 only if every enabled tool is ready, else 2. Doctor never scans and makes at most the single ZAP version request through the adapter.
- `compare`: read both files, validate against the T02 `NormalizedDocument` schema (`invalid_report` exit 5; unsupported `schema_version` too), call `compareDocuments` (T07), map refusals (`incompatible_reports` 5, `partial_input_refused` 4), print the result serialized with T05, exit 0 including non-authoritative comparisons. Never writes files.
- `scan` stub: returns an error envelope with exit 1 and message `scan not implemented` (replaced by T14).

## Tests (same ticket)

- Unit: the full flag-validation matrix (every valid and invalid combination), exit-code mapping, envelope shape and trailing newline.
- Doctor ZAP: a canary key passed through the fake catalog arrives in `ZapProbeContext` as the same `SensitiveString` and never appears in stdout, stderr or any diagnostic; with `target_url_env` unset, doctor is still ready; the env reader throws if `target_url_env` is read; missing key gives `api_key: "missing"`, no probe call, exit 2; the Semgrep probe context has no target field.
- Contract (call `main` in-process with injected fake ports and catalog, capturing real stdout and stderr streams; one smoke test also runs the built `dist` bin for `compare` and a usage error): `doctor` ready, unavailable tool, invalid config, disabled tool; `compare` of valid, malformed, schema-invalid, mismatched-producer and partial inputs with and without `--allow-partial`; stdout is exactly one JSON document in every case and stderr never holds JSON results.

## Done when

`npm run build && node --test dist/tests/unit/cli dist/tests/contract/cli-shell` passes.

## Notes

Do not implement `scan`. If a test-only injection hook is needed, keep it out of the production code path (dependency injection through `main`, not env flags in the bin).

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done.

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** none owned by this ticket. For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
