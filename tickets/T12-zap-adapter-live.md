# T12 — ZAP adapter: probe and live scan

Model: Sonnet
Status: blocked
Depends on: T01, T04
Parallel group: G2 (parallel with T11; no shared files, no dependency between them)
Branch: ticket/T12-zap-live

## Goal

`probe` and live `scan` for the running ZAP daemon through the injected `HttpClient`. Exports plain functions with the T01 signatures. No parsing, normalization, adapter assembly, or stubs of T11 files.

## Read first

- `specs/05-tool-adapters.md`: ZAP section (Authentication, Live scan steps, Completeness)
- `specs/03-cli-contract.md`: `doctor` ZAP bullet, ZAP input rule
- `specs/01-scope-and-decisions.md`: Fixed limits (ZAP rows)
- `src/contracts/adapter.ts` (`ZapProbeContext`, `ZapLiveScanContext`), `ports.ts`, `sensitive.ts` (T01)

## Owns

`src/adapters/zap/probe.ts`, `src/adapters/zap/scan.ts`, `tests/unit/adapters/zap-live/**`.

## Requirements

- Export `zapProbe(ctx: ZapProbeContext, deps: Deps): Promise<ProbeResult>` and `zapScan(ctx: ZapLiveScanContext, deps: Deps): Promise<ScanOutput>`. `zapProbe` uses only `ctx.apiUrl` and `ctx.apiKey`: it needs no target, scan ID or session mode, and tests pass no such fields. Offline ZAP never reaches these functions. Do not create `src/adapters/zap/index.ts` (T14 assembles the adapter).
- All requests are GET through `deps.http`. The API key goes only in `sensitiveHeaders['X-ZAP-API-Key']` as the same `SensitiveString` object from `ctx.apiKey` (never `reveal()` it here, never in a query parameter, never in `diagnostics`, `detail` or messages). The key and API URL are non-null by type; there is no missing-key branch.
- `zapProbe`: exactly one `GET <ctx.apiUrl>/JSON/core/view/version/` (short timeout, no redirect following); returns version; a `closed` response gives `zap_unreachable_or_rejected`; unreachable gives `tool_unavailable`.
- `zapScan` steps in order (endpoints and parameters are read from ZAP source: **[verify] V3**, keep them in one table in `scan.ts`):
  1. First keyed action failure maps to `bad_api_key` (structured rejection) or `zap_unreachable_or_rejected` (closed/empty response); outcome `unavailable`.
  2. `ctx.sessionMode === 'require_clean'`: `numberOfAlerts` for the origin must be 0, else outcome `failed` + `zap_session_not_clean`. `reset`: `newSession` first; failure gives `failed` before any contact with the target.
  3. Create context `scanbridge-<ctx.scanId>` with an anchored, escaped include regex built from `ctx.targetOrigin`, mark it in scope, run the spider in that context.
  4. Poll spider status to `100` within `ctx.spiderTimeoutSeconds`, then passive `recordsToScan` to `"0"` within `ctx.passiveTimeoutSeconds` (use `deps.clock.sleep`). A deadline hit sends a stop request and adds a coverage-loss `tool_timeout` even if ZAP then reports 100.
  5. Read spider results; zero in-scope URLs adds coverage-loss `no_urls_discovered`.
  6. Read `numberOfAlerts`, page `/JSON/alert/view/alerts/` with page size 500 and `baseurl` = origin, re-read `numberOfAlerts`; a changed count adds coverage-loss `partial_coverage`. Accumulate response bytes across pages with the 50 MiB cap (**[verify] V9**; exceeded gives `failed` + `resource_limit_exceeded`).
  7. Assemble the producer-shaped `{"alerts":[...]}` in memory keeping page order and duplicates and return its RFC 8785 canonical serialization (T04 `canonicalJson`) as `raw`.
- API failure before any alerts were retrieved gives `failed` (`tool_execution_failed`); after retrieval the collected evidence is returned with a coverage-loss diagnostic. Operational diagnostics go in `ScanOutput.diagnostics`, concrete coverage loss in `ScanOutput.coverageLoss`; `reasons` is empty.

## Tests (same ticket)

Fake `HttpClient` (scripted responses) and a fake `Clock`:
- Probe success, closed response, timeout; the probe is called with a `ZapProbeContext` only (no target origin, scan ID, session mode or timeouts).
- Happy path: expected request sequence and an `ok` outcome with the assembled raw document (page order and duplicates preserved).
- Dirty session; reset mode and reset failure; bad key; closed response on the first keyed action.
- Spider deadline, passive deadline, stop request sent, zero URLs, count change while paging, size cap, API failure before and after evidence.
- The key is passed only through `sensitiveHeaders`; a canary key value never appears in any request URL, `headers`, diagnostic, `detail` or message.

## Done when

`npm run build && node --test dist/tests/unit/adapters/zap-live` passes.

## Verification items

V3 (endpoints, parameters, field names read from source) and V9 (page size, caps, deadlines) stay `[verify]` in the table and comments; do not invent parameters.

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done.

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** V3, V9. For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
