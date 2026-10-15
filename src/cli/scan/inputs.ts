import { realpath, stat } from 'node:fs/promises';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { configurationDigest, resolveZapLiveInputs, resolveZapOfflineInputs, rulesDigest } from '../../config/index.js';
import type { Config, Env } from '../../config/types.js';
import type { RawDiagnostic, SemgrepScanContext, ZapLiveScanContext, ZapProbeContext } from '../../contracts/adapter.js';
import type { ErrorCode } from '../../contracts/enums.js';
import type { EnvReader } from '../../contracts/ports.js';
import { canonicalJson, normalizeUrl, sha256Hex } from '../../core/fingerprints/index.js';
import type { Policy } from '../../core/redaction/index.js';
import { makeScanId } from '../../core/serialization/index.js';
import type { ScanArgs } from '../args.js';
import { validateOutputDir } from '../output-dir.js';
import type { Exclusion } from './result.js';

export type Base = {
  cwd: string;
  config: Config;
  policy: Policy;
  env: Env;
  reader: EnvReader;
  startedAt: Date;
  configurationDigest: string;
  hasPorts: boolean;
};

export type Plan = {
  adapter: 'semgrep' | 'zap';
  mode: 'semgrep' | 'live' | 'offline';
  scanId: string;
  startedAt: Date;
  policy: Policy;
  configurationDigest: string;
  rulesDigest: string | null;
  outputBase: string;
  exclusions: Exclusion[];
  preDiagnostics: RawDiagnostic[];
  semgrep?: { scan: SemgrepScanContext; excludeRel: string[] };
  live?: { probe: ZapProbeContext; scan: ZapLiveScanContext };
  offline?: { reportPath: string; producerVersion: string | null };
  targetOrigin: string | null;
  assertedRevision: string | null;
};

export type Prepared =
  | { kind: 'error'; code: ErrorCode; message: string }
  /** Before the scan directory exists: the envelope is printed with `artifacts` null. */
  | { kind: 'preflight'; scanId: string; diagnostics: RawDiagnostic[]; exclusions: Exclusion[] }
  | { kind: 'plan'; plan: Plan };

type SemgrepArgs = Extract<ScanArgs, { adapter: 'semgrep' }>;
type ZapArgs = Extract<ScanArgs, { adapter: 'zap' }>;

export function configDigestFor(config: Config, tool: 'semgrep' | 'zap'): string {
  const rules = config.tools.semgrep.rules;
  return configurationDigest({
    tool,
    config,
    redactionPolicyInput: config.redaction,
    ruleFiles: tool === 'semgrep' && rules.mode === 'local' ? rules.files : [],
  });
}

function scanIdFor(base: Base, targetKey: string | null): string {
  return makeScanId(base.startedAt, sha256Hex(canonicalJson([base.configurationDigest, targetKey])));
}

const unavailable = (tool: 'semgrep' | 'zap', message: string): RawDiagnostic => ({
  code: 'tool_unavailable',
  level: 'error',
  tool,
  message,
});

export async function prepareSemgrep(args: SemgrepArgs, base: Base): Promise<Prepared> {
  const target = await resolveTarget(base.cwd, args.target);
  if (target === null) return usage('--target must be an existing directory inside the repository root');
  if (!base.hasPorts) return preflight(base, target.rel, [unavailable('semgrep', 'semgrep adapter is not wired into this build')]);

  const output = await validateOutputDir({ root: base.cwd, output: args.output, target: args.target });
  if (!output.ok) return usage(outputMessage(output.error));

  const scanId = scanIdFor(base, target.rel);
  const semgrep = base.config.tools.semgrep;
  const rules: SemgrepScanContext['rules'] =
    semgrep.rules.mode === 'local'
      ? { mode: 'local', ruleFiles: semgrep.rules.files.map((file) => file.path) }
      : semgrep.rules.mode === 'registry'
        ? { mode: 'registry', ids: semgrep.rules.ids }
        : { mode: 'auto' };
  const exclude = output.excludeRelToTarget;
  return {
    kind: 'plan',
    plan: {
      adapter: 'semgrep',
      mode: 'semgrep',
      scanId,
      startedAt: base.startedAt,
      policy: base.policy,
      configurationDigest: base.configurationDigest,
      // [verify] V7: registry and auto rules have no digest.
      rulesDigest: semgrep.rules.mode === 'local' ? rulesDigest(semgrep.rules.files) : null,
      outputBase: output.outputBase,
      exclusions: exclude === null ? [] : [{ path: exclude, reason: 'output_directory' }],
      preDiagnostics: [],
      semgrep: {
        scan: {
          producer: 'semgrep',
          rootAbs: base.cwd,
          targetRel: target.rel,
          rules,
          ruleTimeoutSeconds: semgrep.ruleTimeoutSeconds,
          timeoutSeconds: semgrep.timeoutSeconds,
          excludeRelToTarget: exclude,
        },
        excludeRel: exclude === null ? [] : [exclude],
      },
      targetOrigin: null,
      assertedRevision: null,
    },
  };
}

export async function prepareZap(args: ZapArgs, base: Base): Promise<Prepared> {
  const offline = args.fromReport !== undefined;
  const flags = args.targetUrl === undefined ? {} : { targetUrl: args.targetUrl };
  const live = offline ? null : resolveZapLiveInputs({ config: base.config, env: base.env, flags });
  const off = offline ? resolveZapOfflineInputs({ config: base.config, env: base.env, flags }) : null;
  const problems = live?.problems ?? off?.problems ?? [];
  const targetUrl = live?.targetUrl ?? off?.targetUrl ?? null;
  const origin = targetUrl === null ? null : normalizeUrl(targetUrl).origin;

  // A bad flag value is a usage error (exit 1); a bad environment value is a readiness failure (exit 2).
  const flagProblem = problems.find((problem) => problem.source === 'flag');
  if (flagProblem) return usage(flagProblem.message);
  if (problems.length > 0) {
    return preflight(base, origin, problems.map((problem) => unavailable('zap', problem.message)));
  }
  if (origin === null) return preflight(base, null, [unavailable('zap', 'no target URL is available')]);
  if (!base.hasPorts) return preflight(base, origin, [unavailable('zap', 'zap adapter is not wired into this build')]);

  const output = await validateOutputDir({ root: base.cwd, output: args.output });
  if (!output.ok) return usage(outputMessage(output.error));

  const preDiagnostics: RawDiagnostic[] = [];
  const overridden = (live?.targetUrlOverridden ?? off?.targetUrlOverridden ?? false) && hasValue(base.reader, base.config.tools.zap.targetUrlEnv);
  if (overridden) {
    preDiagnostics.push({
      code: 'target_url_overridden',
      level: 'info',
      tool: 'zap',
      message: `--target-url overrides ${base.config.tools.zap.targetUrlEnv}`,
    });
  }

  const scanId = scanIdFor(base, origin);
  const zap = base.config.tools.zap;
  const common = {
    adapter: 'zap' as const,
    scanId,
    startedAt: base.startedAt,
    policy: base.policy,
    configurationDigest: base.configurationDigest,
    rulesDigest: null,
    outputBase: output.outputBase,
    exclusions: [],
    preDiagnostics,
    targetOrigin: origin,
    assertedRevision: args.targetRevision ?? null,
  };

  if (args.fromReport !== undefined) {
    return {
      kind: 'plan',
      plan: {
        ...common,
        mode: 'offline',
        offline: { reportPath: resolve(base.cwd, args.fromReport), producerVersion: args.producerVersion ?? null },
      },
    };
  }
  if (live === null || live.apiUrl === null || live.apiKey === null) {
    return preflight(base, origin, [unavailable('zap', 'ZAP API inputs are not available')]);
  }
  return {
    kind: 'plan',
    plan: {
      ...common,
      mode: 'live',
      live: {
        // The key travels only inside these two contexts.
        probe: { producer: 'zap', apiUrl: live.apiUrl, apiKey: live.apiKey },
        scan: {
          producer: 'zap',
          mode: 'live',
          scanId,
          targetOrigin: origin,
          apiUrl: live.apiUrl,
          apiKey: live.apiKey,
          sessionMode: zap.sessionMode,
          spiderTimeoutSeconds: zap.spiderTimeoutSeconds,
          passiveTimeoutSeconds: zap.passiveTimeoutSeconds,
        },
      },
    },
  };
}

function preflight(base: Base, targetKey: string | null, diagnostics: RawDiagnostic[]): Prepared {
  return { kind: 'preflight', scanId: scanIdFor(base, targetKey), diagnostics, exclusions: [] };
}

function usage(message: string): Prepared {
  return { kind: 'error', code: 'usage_error', message };
}

function hasValue(reader: EnvReader, name: string): boolean {
  const value = reader.get(name);
  return value !== undefined && value !== '';
}

function outputMessage(error: 'not_a_directory' | 'equals_target' | 'symlink_escape'): string {
  switch (error) {
    case 'not_a_directory':
      return '--output must be a directory';
    case 'equals_target':
      return '--output must not equal --target';
    case 'symlink_escape':
      return '--output resolves outside the repository root through a symlink';
  }
}

/** The target as a root-relative POSIX path, or null unless it is an existing directory inside the real root. */
async function resolveTarget(root: string, target: string): Promise<{ rel: string } | null> {
  let real: string;
  try {
    real = await realpath(resolve(root, target));
    if (!(await stat(real)).isDirectory()) return null;
  } catch {
    return null;
  }
  const rel = relative(root, real);
  if (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return null;
  return { rel: rel === '' ? '.' : rel.split(sep).join('/') };
}
