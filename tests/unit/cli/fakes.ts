import type {
  Adapter,
  Deps,
  ProbeResult,
  SemgrepProbeContext,
  SemgrepScanContext,
  SonarQubeProbeContext,
  SonarQubeScanContext,
  ZapLiveScanContext,
  ZapProbeContext,
} from '../../../src/contracts/adapter.js';
import type { Clock, EnvReader, HttpClient, Runner } from '../../../src/contracts/ports.js';
import type { CliDeps, CliPorts, Sink } from '../../../src/cli/main.js';

/** Synthetic test value. Not a working credential. */
export const CANARY_KEY = 'canary-zap-api-key-5c2e9b7a';

const never = (): never => {
  throw new Error('not used by the CLI shell tests');
};

export const readyProbe = (version: string): ProbeResult => ({ status: 'ready', version, diagnostics: [] });

export const unavailableProbe = (tool: 'semgrep' | 'zap' | 'sonarqube'): ProbeResult => ({
  status: 'unavailable',
  version: null,
  diagnostics: [{ code: 'tool_unavailable', level: 'error', tool, message: `${tool} did not respond` }],
});

type Probe<C> = (context: C) => Promise<ProbeResult>;

export type FakePorts = CliPorts & { calls: { semgrep: SemgrepProbeContext[]; zap: ZapProbeContext[]; sonarqube: SonarQubeProbeContext[] } };

/** Catalog whose probes record their contexts. Defaults: all tools ready. */
export function fakePorts(options: { semgrep?: Probe<SemgrepProbeContext>; zap?: Probe<ZapProbeContext>; sonarqube?: Probe<SonarQubeProbeContext> } = {}): FakePorts {
  const calls: FakePorts['calls'] = { semgrep: [], zap: [], sonarqube: [] };
  const semgrepProbe = options.semgrep ?? (async () => readyProbe('1.2.3'));
  const zapProbe = options.zap ?? (async () => readyProbe('2.10.0'));
  const sonarqubeProbe = options.sonarqube ?? (async () => readyProbe('10.6.0'));
  return {
    calls,
    catalog: {
      semgrep: adapter<SemgrepProbeContext, SemgrepScanContext>('semgrep', async (context) => {
        calls.semgrep.push(context);
        return semgrepProbe(context);
      }),
      zap: adapter<ZapProbeContext, ZapLiveScanContext>('zap', async (context) => {
        calls.zap.push(context);
        return zapProbe(context);
      }),
      sonarqube: adapter<SonarQubeProbeContext, SonarQubeScanContext>('sonarqube', async (context) => {
        calls.sonarqube.push(context);
        return sonarqubeProbe(context);
      }),
    },
    runner: { run: never } satisfies Runner,
    http: { request: never } satisfies HttpClient,
  };
}

function adapter<
  P extends SemgrepProbeContext | ZapProbeContext | SonarQubeProbeContext,
  S extends SemgrepScanContext | ZapLiveScanContext | SonarQubeScanContext,
>(
  name: 'semgrep' | 'zap' | 'sonarqube',
  probe: (context: P, deps: Deps) => Promise<ProbeResult>,
): Adapter<P, S> {
  return { name, probe, scan: never, parse: never, sourceRefs: never, normalize: never };
}

export const clock: Clock = { now: () => new Date(0), sleep: async () => {} };

export function envOf(values: Record<string, string | undefined>): EnvReader {
  return { get: (name) => values[name] };
}

/** Records every chunk written; the text is what a real stream would have received. */
export class Capture implements Sink {
  readonly chunks: string[] = [];

  write(chunk: string): boolean {
    this.chunks.push(chunk);
    return true;
  }

  get text(): string {
    return this.chunks.join('');
  }
}

/** Deps with fresh captures; `ports` is omitted unless given, which models an unwired build. */
export function cliDeps({
  cwd,
  env = envOf({}),
  ports,
}: {
  cwd: string;
  env?: EnvReader;
  ports?: CliPorts;
}): { deps: CliDeps; stdout: Capture; stderr: Capture } {
  const stdout = new Capture();
  const stderr = new Capture();
  return { deps: { cwd, env, clock, ports, stdout, stderr }, stdout, stderr };
}
