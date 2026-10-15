import { resolve } from 'node:path';
import { loadConfig, resolveZapDoctorInputs } from '../../config/index.js';
import type { Config, Env } from '../../config/types.js';
import type { Deps, ProbeResult } from '../../contracts/adapter.js';
import type { EnvReader } from '../../contracts/ports.js';
import type { DoctorArgs } from '../args.js';
import { doctorEnvelope, errorEnvelope, type DoctorToolReport } from '../envelope.js';
import { doctorExitCode, ERROR_EXIT_CODES } from '../exit.js';
import type { CliDeps } from '../main.js';

type Outcome = { exitCode: number; output: string };

/** Read-only readiness check. Never scans; at most one ZAP version request through the adapter. */
export async function runDoctor(args: DoctorArgs, deps: CliDeps): Promise<Outcome> {
  const loaded = loadConfig(resolve(deps.cwd, args.config), { root: deps.cwd, env: envView(deps.env) });
  if (!loaded.ok) {
    for (const error of loaded.errors) deps.stderr.write(`configuration ${error.path}: ${error.message}\n`);
    return { exitCode: ERROR_EXIT_CODES.invalid_configuration, output: errorEnvelope('invalid_configuration', 'configuration is invalid') };
  }

  const tools = [await semgrepTool(loaded.config, deps), await zapTool(loaded.config, deps)];
  const ok = tools.every((tool) => tool.status === 'ready' || tool.status === 'skipped');
  return {
    exitCode: doctorExitCode(ok),
    output: doctorEnvelope({ schema_version: '1', command: 'doctor', ok, tools }),
  };
}

async function semgrepTool(config: Config, deps: CliDeps): Promise<DoctorToolReport> {
  if (!config.tools.semgrep.enabled) return skipped('semgrep');
  const ports = deps.ports;
  if (ports === undefined) return unwired('semgrep');
  const result = await probeSafely('semgrep', () =>
    ports.catalog.semgrep.probe({ producer: 'semgrep' }, adapterDeps(ports, deps)),
  );
  return { name: 'semgrep', ...reportFields(result) };
}

async function zapTool(config: Config, deps: CliDeps): Promise<DoctorToolReport> {
  if (!config.tools.zap.enabled) return skipped('zap');

  // Doctor reads the API URL and API key only; the target URL is never resolved here.
  const inputs = resolveZapDoctorInputs({ config, env: envView(deps.env) });
  const keyFields = { api_key: inputs.apiKeyPresent ? 'present' : 'missing', api_key_verified: false } as const;
  const { apiUrl, apiKey } = inputs;
  if (inputs.problems.length > 0 || apiUrl === null || apiKey === null) {
    const problems = inputs.problems.map((problem) => ({ code: 'tool_unavailable' as const, message: problem.message }));
    return { name: 'zap', status: 'unavailable', version: null, ...keyFields, problems };
  }

  const ports = deps.ports;
  if (ports === undefined) return { name: 'zap', status: 'unavailable', version: null, ...keyFields, problems: [unwiredProblem('zap')] };
  // The SensitiveString is passed through unchanged; doctor never reveals it.
  const result = await probeSafely('zap', () =>
    ports.catalog.zap.probe({ producer: 'zap', apiUrl, apiKey }, adapterDeps(ports, deps)),
  );
  return { name: 'zap', ...reportFields(result), ...keyFields };
}

function skipped(name: 'semgrep' | 'zap'): DoctorToolReport {
  return { name, status: 'skipped', version: null, problems: [] };
}

function unwired(name: 'semgrep' | 'zap'): DoctorToolReport {
  return { name, status: 'unavailable', version: null, problems: [unwiredProblem(name)] };
}

function unwiredProblem(name: 'semgrep' | 'zap'): { code: 'tool_unavailable'; message: string } {
  return { code: 'tool_unavailable', message: `${name} adapter is not wired into this build` };
}

/** A probe that throws counts as not ready; the thrown value is never copied into the output. */
async function probeSafely(name: 'semgrep' | 'zap', probe: () => Promise<ProbeResult>): Promise<ProbeResult> {
  try {
    return await probe();
  } catch {
    return {
      status: 'unavailable',
      version: null,
      diagnostics: [{ code: 'tool_unavailable', level: 'error', tool: name, message: `${name} probe did not complete` }],
    };
  }
}

function reportFields(result: ProbeResult): Omit<DoctorToolReport, 'name'> {
  return {
    status: result.status,
    version: result.version,
    problems: result.diagnostics.map((diagnostic) => ({ code: diagnostic.code, message: diagnostic.message })),
  };
}

function adapterDeps(ports: NonNullable<CliDeps['ports']>, deps: CliDeps): Deps {
  return { runner: ports.runner, http: ports.http, clock: deps.clock };
}

/** Config loading reads variables only by name through the injected reader; nothing is copied eagerly. */
function envView(reader: EnvReader): Env {
  return new Proxy({} as Record<string, string | undefined>, {
    get: (_target, name) => (typeof name === 'string' ? reader.get(name) : undefined),
  });
}
