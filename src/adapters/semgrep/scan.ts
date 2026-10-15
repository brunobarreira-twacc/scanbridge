import type { Deps, RawDiagnostic, ScanOutput, SemgrepScanContext } from '../../contracts/adapter.js';
import type { ScanReason } from '../../contracts/enums.js';
import { RAW_JSON_MAX_BYTES, TEXT_FIELD_MAX } from '../../contracts/limits.js';

export function scanArgs(ctx: SemgrepScanContext): string[] {
  const rules = ctx.rules;
  const configs =
    rules.mode === 'local'
      ? rules.ruleFiles.flatMap((f) => ['--config', f])
      : rules.mode === 'registry'
        ? rules.ids.flatMap((id) => ['--config', id])
        : ['--config', 'auto'];
  return [
    'scan',
    '--json',
    // Semgrep requires metrics to be on for registry and auto rules, so `--metrics=off` is omitted there.
    ...(rules.mode === 'local' ? ['--metrics=off'] : []),
    '--disable-version-check',
    // Verified on Semgrep 1.180.0 (V4): plain Semgrep suppresses `// nosemgrep`; this flag keeps the finding.
    '--disable-nosem',
    '--timeout',
    String(ctx.ruleTimeoutSeconds),
    ...configs,
    ...(ctx.excludeRelToTarget === null ? [] : ['--exclude', ctx.excludeRelToTarget]),
    ctx.targetRel,
  ];
}

export async function scan(ctx: SemgrepScanContext, deps: Deps): Promise<ScanOutput> {
  const nonDeterministic = ctx.rules.mode === 'registry' || ctx.rules.mode === 'auto';
  // rules_digest stays null (V7); the adapter only flags the reasons.
  const reasons: ScanReason[] = nonDeterministic ? [ctx.rules.mode === 'registry' ? 'registry_rules' : 'auto_rules'] : [];
  const diagnostics: RawDiagnostic[] = nonDeterministic
    ? [{ code: 'non_deterministic_rules', level: 'warn', tool: 'semgrep', message: 'Registry or auto rules are not pinned; results may change between runs' }]
    : [];
  const base = { raw: null, coverageLoss: [], reasons };

  // [verify] V9: the stdout cap is the shared raw limit, revisited with real fixtures.
  const r = await deps.runner.run('semgrep', scanArgs(ctx), {
    cwd: ctx.rootAbs,
    timeoutMs: ctx.timeoutSeconds * 1000,
    maxStdoutBytes: RAW_JSON_MAX_BYTES,
  });
  if (r.spawnFailed) {
    return { ...base, outcome: 'unavailable', diagnostics: [...diagnostics, { code: 'tool_unavailable', level: 'error', tool: 'semgrep', message: 'semgrep could not be started' }] };
  }
  if (r.timedOut) {
    return { ...base, outcome: 'failed', diagnostics: [...diagnostics, { code: 'tool_timeout', level: 'error', tool: 'semgrep', message: 'semgrep exceeded the scan timeout' }] };
  }
  if (r.stdoutTruncated) {
    return { ...base, outcome: 'failed', diagnostics: [...diagnostics, { code: 'resource_limit_exceeded', level: 'error', tool: 'semgrep', message: 'semgrep output exceeded the raw size limit' }] };
  }
  // Verified on Semgrep 1.180.0 (V1): exit 7 emits parseable JSON with empty results and paths.scanned, so every non-zero exit is failed.
  if (r.exitCode !== 0) {
    const tail = [...r.stderrTail].slice(-TEXT_FIELD_MAX).join('');
    const failure: RawDiagnostic = { code: 'tool_execution_failed', level: 'error', tool: 'semgrep', message: 'semgrep exited without success' };
    if (tail !== '') failure.detail = tail;
    return { ...base, outcome: 'failed', diagnostics: [...diagnostics, failure] };
  }
  return { ...base, outcome: 'ok', raw: r.stdout, diagnostics };
}
