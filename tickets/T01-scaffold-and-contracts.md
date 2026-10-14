# T01 — Scaffold and shared contracts

Model: Sonnet
Status: ready
Depends on: none
Parallel group: G0 (alone)
Branch: ticket/T01-scaffold

## Goal

Create the minimal TypeScript project and the shared contracts every other ticket compiles against. After this ticket nobody else touches `package.json` or `src/contracts/`.

## Read first

- `specs/01-scope-and-decisions.md`: Runtime and packaging, Fixed limits
- `specs/02-architecture.md`: Source layout, the `core/` purity rule, Scan pipeline
- `specs/03-cli-contract.md`: Exit codes, Envelopes, ZAP input rule
- `specs/04-finding-schema.md`: Severity, Identifier limits, Diagnostics and reasons
- `specs/05-tool-adapters.md`: Adapter contract, ZAP live scan steps

## Owns

`package.json`, `package-lock.json`, `tsconfig.json`, `.gitignore` (append `node_modules/`, `dist/` only), `src/contracts/**`, `tests/unit/contracts/**`.

## Requirements

- ESM, TypeScript `strict` plus `noUncheckedIndexedAccess`, `module`/`moduleResolution` `NodeNext`; relative imports use the `.js` suffix. `engines.node` `>=22`; `bin.scanbridge` points to `dist/src/cli/main.js`.
- Install once, here only: runtime `yaml`, `zod` (v4); dev `typescript`, `@types/node`, `ajv`. No other dependency, ever.
- `tsconfig` compiles `src` and `tests` to `dist/` (`rootDir` `.`).
- npm scripts: `build` (`tsc`), `typecheck` (`tsc --noEmit`), `test` (`npm run build && node --test dist/tests/unit dist/tests/contract`), `test:unit`, `gen:schemas` (`node scripts/gen-schemas.mjs`), `check:schemas` (same with `--check`). The script file is created by T02.
- `src/contracts/enums.ts`: `as const` arrays and derived types for the closed lists in specs 03 and 04: diagnostic codes (20), scan reasons (6: `partial_scan`, `registry_rules`, `auto_rules`, `fingerprint_degraded`, `unmapped_severity`, `offline_report`), compare reasons (10), completeness (`complete|partial|unverified|failed`), severities with `SEVERITY_RANK`, fingerprint quality, compare states, error codes, exit codes (named 0–5), and versions (`SCHEMA_VERSION` `"1"`, `FINGERPRINT_VERSION` `"v1"`, `SEMGREP_MAPPING_VERSION` `"semgrep-1"`, `ZAP_MAPPING_VERSION` `"zap-1"`, `BUILTIN_REDACTION_VERSION` `"1"`). Export `JsonValue`.
- `src/contracts/limits.ts`: every numeric limit from specs 01 and 04, as named constants **[verify] V9** (values are revisited with real fixtures).
- `src/contracts/sensitive.ts` (the only runtime code besides constants): `SensitiveString` wrapping a secret; `reveal()` returns the value; `toString()`, `toJSON()` and `util.inspect.custom` all return `[REDACTED]`. Used for the ZAP API key everywhere in memory.
- `src/contracts/ports.ts` and `src/contracts/adapter.ts` as sketched below. Keep them minimal; no plugin system. Downstream tickets (T08, T10, T11, T12, T13, T14 in particular) meet their requirements with these exact types; no ticket may add a dummy target, scan ID or key to satisfy a context.

```ts
// ports.ts
Runner.run(cmd: 'semgrep' | 'git', args: readonly string[], o: { cwd: string; timeoutMs: number; maxStdoutBytes: number }): Promise<RunResult>
RunResult = { exitCode: number | null; signal: string | null; timedOut: boolean; spawnFailed: boolean; stdout: Uint8Array; stdoutTruncated: boolean; stderrTail: string }
HttpClient.request(r: { url: string; headers: Record<string, string>; sensitiveHeaders?: Record<string, SensitiveString>; timeoutMs: number; maxBytes: number }): Promise<HttpResult>  // GET only
HttpResult = { kind: 'response'; status: number; body: Uint8Array; truncated: boolean } | { kind: 'closed' } | { kind: 'timeout' } | { kind: 'error'; code: string }
Clock { now(): Date; sleep(ms: number): Promise<void> }          EnvReader { get(name: string): string | undefined }
SourceReader.readLines(pathFromRoot: string, startLine: number, endLine: number): Promise<{ ok: true; text: string } | { ok: false; reason: SourceFailure }>
SourceFailure = 'outside_target' | 'symlink' | 'too_large' | 'invalid_utf8' | 'missing' | 'changed' | 'unreadable'
SourceText = { ok: true; text: string; redacted: boolean } | { ok: false; reason: SourceFailure }   // after orchestrator redaction
TargetIdentityReader.read(o: { targetRel: string; excludeRel: string[] }): Promise<{ kind: 'git' | 'directory'; relative_path: string; revision: string | null; dirty: boolean | null; content_digest: string | null; diagnostics: RawDiagnostic[] }>

// adapter.ts
RuleSource = { mode: 'local'; ruleFiles: readonly string[] } | { mode: 'registry'; ids: readonly string[] } | { mode: 'auto' }
// Probe contexts: what `doctor` and the scan pre-flight can supply. Scan contexts: what a scan needs. They are separate types; no dummy values anywhere.
SemgrepProbeContext = { producer: 'semgrep' }                                                  // no target, no rules
ZapProbeContext = { producer: 'zap'; apiUrl: string; apiKey: SensitiveString }                // no target, no scan ID
SemgrepScanContext = { producer: 'semgrep'; rootAbs: string; targetRel: string; rules: RuleSource; ruleTimeoutSeconds: number; timeoutSeconds: number; excludeRelToTarget: string | null }
ZapLiveScanContext = { producer: 'zap'; mode: 'live'; scanId: string; targetOrigin: string; apiUrl: string; apiKey: SensitiveString;
                       sessionMode: 'require_clean' | 'reset'; spiderTimeoutSeconds: number; passiveTimeoutSeconds: number }
// Offline ZAP has no probe context and no scan context: the orchestrator calls neither `probe` nor `scan`; it calls `parse`, `sourceRefs`, `normalize` only.
Deps = { runner: Runner; http: HttpClient; clock: Clock }
Adapter<P extends SemgrepProbeContext | ZapProbeContext, S extends SemgrepScanContext | ZapLiveScanContext> { name: 'semgrep' | 'zap'
  probe(c: P, d: Deps): Promise<ProbeResult>;  scan(c: S, d: Deps): Promise<ScanOutput>
  parse(raw: Uint8Array): ParseResult;  sourceRefs(doc: JsonValue): SourceRef[]
  normalize(doc: JsonValue, c: NormalizeContext, sources: ReadonlyMap<string, SourceText>): NormalizeOutput }
ProbeResult = { status: 'ready' | 'unavailable'; version: string | null; diagnostics: RawDiagnostic[] }
ParseResult = { ok: true; doc: JsonValue } | { ok: false; reason: 'invalid_json' | 'unsupported_shape' }
ScanOutput = { outcome: 'ok' | 'failed' | 'unavailable'; raw: Uint8Array | null;
  diagnostics: RawDiagnostic[];      // operational: non_deterministic_rules, tool_timeout (when failed), bad_api_key, ...
  coverageLoss: RawDiagnostic[];     // concrete coverage loss seen while scanning: makes the scan partial
  reasons: ScanReason[] }            // scan-level non-authoritative reasons known at scan time (registry_rules, auto_rules)
NormalizeContext = { mode: 'live' | 'offline'; targetRel: string; targetOrigin: string | null; producerVersion: string | null;
  redactionTouched: ReadonlySet<string> /* RFC 6901 pointers */; coverageLoss: readonly RawDiagnostic[]; scanDiagnostics: readonly RawDiagnostic[]; scanReasons: readonly ScanReason[] }
NormalizeOutput = { candidates: Candidate[]; unusableCount: number; diagnostics: RawDiagnostic[]; coverageLoss: RawDiagnostic[];
  completeness: Completeness;        // offline gives 'unverified'; any coverage loss gives 'partial'; else 'complete'
  reasons: ScanReason[];             // derived at normalize time (offline_report); orchestrator unions with ScanOutput.reasons
  severityMappingVersion: string; producerVersion: string | null }
RawDiagnostic = { code: DiagnosticCode; level: 'info' | 'warn' | 'error'; tool?: string; message: string; detail?: string }  // detail: untrusted, unsanitized
Candidate = { producer: 'semgrep' | 'zap'; ruleId: string; producerReference: string | null; producerFingerprint: string | null; title: string; description: string | null;
  confidence: string | null; category: string | null; references: string[]; severityOriginal: string; severity: Severity;
  location: { source?: { path; startLine; startCol; endLine; endCol }; runtime?: { url; method; param } };
  evidence: Record<string, string | null>; snippet?: { ok: true; text: string } | { ok: false; reason: SourceFailure }; redactionsApplied: boolean }
SourceRef = { key: string; path: string; startLine: number; endLine: number }
ToolCatalog = { semgrep: Adapter<SemgrepProbeContext, SemgrepScanContext>; zap: Adapter<ZapProbeContext, ZapLiveScanContext> }
```

Contract coverage check (every requirement has a home):

| Need | Where |
|---|---|
| `registry_rules`, `auto_rules`, `offline_report`, `non_deterministic_rules` | `ScanReason`, `ScanOutput.reasons`, `NormalizeOutput.reasons`, `ScanOutput.diagnostics` |
| Live, partial, offline/unverified | `NormalizeContext.mode`, `coverageLoss`, `NormalizeOutput.completeness` |
| Operational diagnostics versus coverage loss | `ScanOutput.diagnostics` vs `ScanOutput.coverageLoss` |
| Probe without a target (Semgrep) | `SemgrepProbeContext` |
| Probe with only API URL and key (ZAP) | `ZapProbeContext` |
| Semgrep scan target, rules, timeouts | `SemgrepScanContext` |
| ZAP live scan target origin, scan ID, API URL/key, session mode, timeouts | `ZapLiveScanContext` |
| Offline ZAP calls neither probe nor scan | no context type exists; `Adapter` is used only for `parse`, `sourceRefs`, `normalize` |
| API key in memory only | `ZapProbeContext.apiKey` and `ZapLiveScanContext.apiKey: SensitiveString`, `HttpClient` `sensitiveHeaders`; never in `NormalizeContext`, `RawDiagnostic`, config types |
| Producer version | `ProbeResult.version`, `NormalizeContext.producerVersion`, `NormalizeOutput.producerVersion` |
| Snippets and redaction touch | `SourceText.redacted`, `Candidate.snippet`, `NormalizeContext.redactionTouched`, `Candidate.redactionsApplied` |

## Tests (same ticket)

`tests/unit/contracts/`:
- Enum sizes and members match the spec lists exactly; exit-code and rank maps; limit values match the specs.
- Contexts: type-level tests (`satisfies` and `@ts-expect-error`) prove `SemgrepProbeContext` has no target or rules field, `ZapProbeContext` has exactly `producer`, `apiUrl`, `apiKey`, and `ZapLiveScanContext` has no `null` API URL or key. A runtime sample of each context serialized with `JSON.stringify` never contains a canary API key.
- `SensitiveString`: `String(x)`, template literals, `JSON.stringify`, `util.inspect` and `console.log` capture never reveal the value; `reveal()` does.
- `boundaries.test.ts`: walks `src/core/**` and `src/adapters/**` and fails if a file imports `fs`, `node:fs`, `node:fs/promises`, or uses `process.env`, `Date.now`, `new Date(` (adapters other than `src/adapters/io` may not touch the filesystem or network clients either); fails if `.reveal(` appears outside `src/adapters/io/**`. It passes on an empty tree.

## Done when

`npm ci && npm run build && npm test` passes; `git status` shows only owned files; no dependency beyond the list above.

## Notes

Downstream tickets may not edit these files. If a contract is wrong, report it in the summary and stop; the integrator amends T01. These types are internal design consistent with spec 05, not spec text.

## Handoff

Required before requesting merge: put every item below in the PR description and in the final session summary. A missing item means the ticket is not done.

- **Files changed:** the full list from `git diff --name-only main`, one path per line.
- **Behavior implemented:** one bullet per Requirement, saying what now works; name anything not implemented.
- **Tests and results:** the exact commands from "Done when" and their outcome (pass/fail, test counts); paste the failing output for anything that fails.
- **`[verify]` items:** V9 (limit constants). For each, where it is marked (file and comment, or fixture) and a statement that it was not resolved by guessing.
- **Blockers:** contract defects, spec gaps or unfinished work; write "none" if there are none.
- **Owned paths:** confirmation that only paths listed under "Owns" changed (the `git diff --name-only main` output is the evidence).
