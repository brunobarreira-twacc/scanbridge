import { resolve } from 'node:path';
import { loadConfig } from '../../config/index.js';
import type { RawDiagnostic } from '../../contracts/adapter.js';
import { EXIT_CODES } from '../../contracts/enums.js';
import { buildPolicy, PolicyError, type Policy } from '../../core/redaction/index.js';
import type { ScanArgs } from '../args.js';
import { errorEnvelope } from '../envelope.js';
import { ERROR_EXIT_CODES } from '../exit.js';
import type { CliDeps } from '../main.js';
import { ReportStore, ScanDirectoryExistsError } from '../store/report-store.js';
import { configDigestFor, prepareSemgrep, prepareZap, type Base, type Plan, type Prepared } from './inputs.js';
import { envView } from './env.js';
import { runPipeline } from './pipeline.js';
import { scanResultText, type Exclusion, type ScanSummary } from './result.js';

type Outcome = { exitCode: number; output: string };

/** The `scan` command: validates, creates the exclusive scan directory, runs the pipeline, prints `scan-result.json`. */
export async function runScan(args: ScanArgs, deps: CliDeps): Promise<Outcome> {
  const env = envView(deps.env);
  const loaded = loadConfig(resolve(deps.cwd, args.config), { root: deps.cwd, env });
  if (!loaded.ok) {
    for (const error of loaded.errors) deps.stderr.write(`configuration ${error.path}: ${error.message}\n`);
    return usageOutcome('invalid_configuration', 'configuration is invalid');
  }
  const config = loaded.config;
  if (!config.tools[args.adapter].enabled) return usageOutcome('usage_error', `adapter ${args.adapter} is disabled in the configuration`);

  let policy: Policy;
  try {
    policy = buildPolicy(config.redaction, env);
  } catch (error) {
    if (!(error instanceof PolicyError)) throw error;
    return usageOutcome('invalid_configuration', 'configuration is invalid');
  }

  const base: Base = {
    cwd: deps.cwd,
    config,
    policy,
    env,
    reader: deps.env,
    startedAt: deps.clock.now(),
    configurationDigest: configDigestFor(config, args.adapter),
    hasPorts: deps.ports !== undefined,
  };
  const prepared: Prepared = args.adapter === 'semgrep' ? await prepareSemgrep(args, base) : await prepareZap(args, base);

  switch (prepared.kind) {
    case 'error':
      return usageOutcome(prepared.code, prepared.message);
    case 'preflight':
      return preflightOutcome(args.adapter, base, policy, prepared.scanId, prepared.diagnostics, prepared.exclusions, deps);
    case 'plan':
      return executePlan(prepared.plan, deps);
  }
}

function usageOutcome(code: Parameters<typeof errorEnvelope>[0], message: string): Outcome {
  return { exitCode: ERROR_EXIT_CODES[code], output: errorEnvelope(code, message) };
}

/** Failures before the scan directory exists: the envelope is printed with `artifacts` null. */
function preflightOutcome(
  adapter: 'semgrep' | 'zap',
  base: Base,
  policy: Policy,
  scanId: string,
  diagnostics: RawDiagnostic[],
  exclusions: Exclusion[],
  deps: CliDeps,
): Outcome {
  const output = scanResultText(
    {
      status: 'failed',
      exitCode: EXIT_CODES.TOOL_UNAVAILABLE,
      scanId,
      adapter,
      startedAt: base.startedAt,
      finishedAt: deps.clock.now(),
      authoritative: false,
      reasons: [],
      findingsCount: 0,
      exclusions,
      diagnostics,
      artifacts: { directory: null, raw: null, normalized: null },
    },
    policy,
  );
  return { exitCode: EXIT_CODES.TOOL_UNAVAILABLE, output };
}

async function executePlan(plan: Plan, deps: CliDeps): Promise<Outcome> {
  const ports = deps.ports;
  if (ports === undefined) throw new TypeError('scan needs ports');
  const summary = (partial: Pick<ScanSummary, 'status' | 'exitCode' | 'authoritative' | 'reasons' | 'findingsCount' | 'diagnostics' | 'artifacts'>): ScanSummary => ({
    ...partial,
    scanId: plan.scanId,
    adapter: plan.adapter,
    startedAt: plan.startedAt,
    finishedAt: deps.clock.now(),
    exclusions: plan.exclusions,
  });
  const finish = (s: ScanSummary): Outcome => ({ exitCode: s.exitCode, output: scanResultText(s, plan.policy) });

  if (plan.preDiagnostics.some((d) => d.code === 'target_url_overridden')) {
    deps.stderr.write('info: --target-url overrides the target URL environment variable\n');
  }

  // Created right after validation and before probing, so every later failure can still write scan-result.json.
  let store: ReportStore;
  try {
    store = await ReportStore.createScanDirectory(plan.outputBase, plan.scanId);
  } catch (error) {
    const message = error instanceof ScanDirectoryExistsError ? 'The scan directory already exists; nothing was written' : 'The scan directory could not be created';
    return finish(
      summary({
        status: 'failed',
        exitCode: EXIT_CODES.SCAN_FAILED,
        authoritative: false,
        reasons: [],
        findingsCount: 0,
        diagnostics: [{ code: 'tool_execution_failed', level: 'error', message }],
        artifacts: { directory: null, raw: null, normalized: null },
      }),
    );
  }

  const result = await runPipeline(plan, store, deps, ports);
  const built = summary({
    status: result.status,
    exitCode: result.exitCode,
    authoritative: result.authoritative,
    reasons: result.reasons,
    findingsCount: result.findingsCount,
    diagnostics: result.diagnostics,
    artifacts: { directory: store.directory, raw: result.raw.length > 0 ? result.raw : null, normalized: result.normalized },
  });
  const outcome = finish(built);
  try {
    await store.writeScanResult(outcome.output);
  } catch {
    // The envelope is still printed; the missing file is visible to the caller.
  }
  return outcome;
}
