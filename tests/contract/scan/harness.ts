import { execFile } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { after } from 'node:test';
import { fileURLToPath } from 'node:url';

// dist/tests/contract/scan -> dist/src/cli/main.js
const BIN = resolve(dirname(fileURLToPath(import.meta.url)), '../../../src/cli/main.js');
export const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../tests/fixtures');

// Synthetic, test-only values. None is a working credential.
export const CANARY_API_KEY = 'canary-zap-api-key-91d3f7c2';
export const CANARY_ENV_VALUE = 'canary-env-value-4b8e61aa';
export const ORIGIN = 'http://127.0.0.1:8080';

const scratch: string[] = [];
after(() => {
  for (const dir of scratch) rmSync(dir, { recursive: true, force: true });
});

export function tempDir(prefix = 'scanbridge-e2e-'): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  scratch.push(dir);
  return dir;
}

export type ConfigOptions = {
  semgrepEnabled?: boolean;
  zapEnabled?: boolean;
  sonarqubeEnabled?: boolean;
  semgrepConfig?: string;
  sessionMode?: 'require_clean' | 'reset';
  spiderTimeout?: number;
  passiveTimeout?: number;
  envVars?: string[];
};

export function configYaml(o: ConfigOptions = {}): string {
  const envVars = o.envVars ? `  env_vars: [${o.envVars.join(', ')}]\n` : '';
  return `version: 1
redaction:
${envVars === '' ? '  headers: []\n' : envVars}tools:
  semgrep:
    enabled: ${o.semgrepEnabled ?? true}
    config:
${o.semgrepConfig ?? '      rules: [rules/security.yaml]\n'}  zap:
    enabled: ${o.zapEnabled ?? true}
    config:
      api_url_env: SCANBRIDGE_ZAP_API_URL
      api_key_env: SCANBRIDGE_ZAP_API_KEY
      target_url_env: SCANBRIDGE_ZAP_TARGET_URL
      allowed_target_origins: ["${ORIGIN}"]
      session_mode: ${o.sessionMode ?? 'require_clean'}
      spider_timeout_seconds: ${o.spiderTimeout ?? 5}
      passive_timeout_seconds: ${o.passiveTimeout ?? 5}
  sonarqube:
    enabled: ${o.sonarqubeEnabled ?? false}
    config:
      api_url_env: SONARQUBE_URL
      api_key_env: SONARQUBE_TOKEN
      project_key_env: SONARQUBE_PROJECT
`;
}

const RULE_FILE = 'rules:\n  - id: synthetic-rule\n    languages: [javascript]\n    severity: ERROR\n    message: Synthetic.\n    pattern: call($X)\n';

export type Repo = { root: string; bin: string; specPath: string; argvOut: string };

/** Temp repo with config, a rule file, source files and a `bin/` directory for the fake `semgrep`. */
export function makeRepo(files: Record<string, string> = {}, config = configYaml()): Repo {
  const root = tempDir();
  mkdirSync(join(root, 'rules'), { recursive: true });
  mkdirSync(join(root, '.pr-review'), { recursive: true });
  writeFileSync(join(root, 'rules', 'security.yaml'), RULE_FILE);
  writeFileSync(join(root, '.pr-review', 'tools.yaml'), config);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  const bin = tempDir('scanbridge-bin-');
  return { root, bin, specPath: join(bin, 'spec.json'), argvOut: join(bin, 'argv.jsonl') };
}

export const SOURCE_LINES = Array.from({ length: 60 }, (_, i) => `const line${i + 1} = call(${i + 1});`).join('\n') + '\n';

const FAKE_SEMGREP = `#!/usr/bin/env node
const fs = require('node:fs');
const spec = JSON.parse(fs.readFileSync(process.env.FAKE_SEMGREP_SPEC, 'utf8'));
const argv = process.argv.slice(2);
fs.appendFileSync(spec.argvOut, JSON.stringify(argv) + '\\n');
if (argv[0] === '--version') {
  if (spec.versionExit) process.exit(spec.versionExit);
  process.stdout.write((spec.version ?? '1.2.3') + '\\n');
  process.exit(0);
}
if (spec.mutate) fs.writeFileSync(spec.mutate.path, spec.mutate.content);
if (spec.stderr) process.stderr.write(spec.stderr);
let out = '';
if (spec.stdoutGenerator) {
  const n = spec.stdoutGenerator.results;
  const results = [];
  for (let i = 0; i < n; i++) {
    results.push({ check_id: 'rules.r' + i, path: spec.stdoutGenerator.path, start: { line: 1, col: 1, offset: 0 }, end: { line: 1, col: 5, offset: 4 },
      extra: { message: 'x'.repeat(spec.stdoutGenerator.messageLength), severity: 'ERROR' } });
  }
  out = JSON.stringify({ results, errors: [], paths: { scanned: [spec.stdoutGenerator.path] }, version: '1.2.3' });
} else if (spec.stdoutFile) {
  out = fs.readFileSync(spec.stdoutFile);
} else if (spec.stdout !== undefined) {
  out = spec.stdout;
}
// Exit only after stdout drained: a piped, large write is otherwise cut short.
process.stdout.write(out, () => process.exit(spec.exitCode ?? 0));
`;

export type SemgrepSpec = {
  version?: string;
  versionExit?: number;
  exitCode?: number;
  stdout?: string;
  stdoutFile?: string;
  stdoutGenerator?: { results: number; path: string; messageLength: number };
  stderr?: string;
  mutate?: { path: string; content: string };
};

/** Installs the fake `semgrep` executable (a Node script) in `repo.bin`. */
export function installFakeSemgrep(repo: Repo, spec: SemgrepSpec): void {
  writeFileSync(repo.specPath, JSON.stringify({ ...spec, argvOut: repo.argvOut }));
  const path = join(repo.bin, 'semgrep');
  writeFileSync(path, FAKE_SEMGREP);
  chmodSync(path, 0o755);
}

export function semgrepArgv(repo: Repo): string[][] {
  try {
    return readFileSync(repo.argvOut, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l) as string[]);
  } catch {
    return [];
  }
}

export type CliRun = { status: number | null; stdout: string; stderr: string };

export function runCli(repo: Repo, args: string[], env: Record<string, string> = {}): Promise<CliRun> {
  return new Promise((resolvePromise) => {
    execFile(
      process.execPath,
      [BIN, ...args],
      {
        cwd: repo.root,
        encoding: 'utf8',
        maxBuffer: 256 * 1024 * 1024,
        env: { PATH: `${repo.bin}${delimiter}${process.env.PATH ?? ''}`, FAKE_SEMGREP_SPEC: repo.specPath, ...env },
      },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === 'number' ? error.code : null;
        resolvePromise({ status: code, stdout, stderr });
      },
    );
  });
}

export type ScanEnvelope = {
  status: string;
  exit_code: number;
  scan_id: string;
  adapter: string;
  authoritative: boolean;
  non_authoritative_reasons: string[];
  findings_count: number;
  exclusions: { path: string; reason: string }[];
  diagnostics: { code: string; level: string; message: string; detail?: { text: string } }[];
  artifacts: { directory: string | null; raw: string[] | null; normalized: string | null };
};

export function envelope(run: CliRun): ScanEnvelope {
  return JSON.parse(run.stdout) as ScanEnvelope;
}

export function codes(env: ScanEnvelope): string[] {
  return env.diagnostics.map((d) => d.code);
}

/** The only scan directory under `<root>/<output>`, or null. */
export function scanDirectory(repo: Repo, output = 'out'): string | null {
  try {
    const entries = readdirSync(join(repo.root, output));
    return entries.length === 1 ? join(repo.root, output, entries[0] as string) : null;
  } catch {
    return null;
  }
}

export function filesIn(dir: string): string[] {
  const out: string[] = [];
  const walk = (current: string, prefix: string) => {
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      if (entry.isDirectory()) walk(join(current, entry.name), `${prefix}${entry.name}/`);
      else out.push(`${prefix}${entry.name}`);
    }
  };
  walk(dir, '');
  return out.sort();
}

export function readJson(path: string): any {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** Every file under `dir` as text, joined: used by canary scans. */
export function allArtifactText(dir: string): string {
  return filesIn(dir).map((f) => readFileSync(join(dir, f), 'utf8')).join('\n');
}

// ---- fake ZAP API -------------------------------------------------------------------------------

export type ZapFake = {
  apiUrl: string;
  requests: { path: string; query: URLSearchParams; key: string | undefined }[];
  close(): Promise<void>;
};

export type ZapBehavior = {
  apiKey?: string;
  version?: string;
  closed?: boolean;
  /** Alerts held for the target origin before the scan. */
  existingAlerts?: number;
  /** Alerts returned by the alerts view. */
  alerts?: unknown[];
  spiderStatus?: string;
  spiderResults?: string[];
  /** Count reported after paging started (to simulate a change while paging). */
  countAfterPaging?: number;
};

export async function startZap(b: ZapBehavior = {}): Promise<ZapFake> {
  const key = b.apiKey ?? CANARY_API_KEY;
  const alerts = b.alerts ?? [];
  const requests: ZapFake['requests'] = [];
  let spidered = false;
  let paged = false;
  let reset = false;
  const send = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  const handler = (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    const header = req.headers['x-zap-api-key'];
    requests.push({ path: url.pathname, query: url.searchParams, key: typeof header === 'string' ? header : undefined });
    if (b.closed) {
      req.socket.destroy();
      return;
    }
    if (header !== key) return send(res, 403, { code: 'bad_api_key', message: 'Bad API key' });
    switch (url.pathname) {
      case '/JSON/core/view/version/':
        return send(res, 200, { version: b.version ?? '2.15.0' });
      case '/JSON/core/action/newSession/':
        reset = true;
        return send(res, 200, { Result: 'OK' });
      case '/JSON/alert/view/numberOfAlerts/': {
        // Before the spider runs the session holds `existingAlerts`; afterwards it holds the scan's alerts.
        const count = !spidered ? (reset ? 0 : (b.existingAlerts ?? 0)) : paged && b.countAfterPaging !== undefined ? b.countAfterPaging : alerts.length;
        return send(res, 200, { numberOfAlerts: String(count) });
      }
      case '/JSON/context/action/newContext/':
        return send(res, 200, { contextId: '1' });
      case '/JSON/context/action/includeInContext/':
      case '/JSON/context/action/setContextInScope/':
      case '/JSON/spider/action/stop/':
        return send(res, 200, { Result: 'OK' });
      case '/JSON/spider/action/scan/':
        spidered = true;
        return send(res, 200, { scan: '0' });
      case '/JSON/spider/view/status/':
        return send(res, 200, { status: b.spiderStatus ?? '100' });
      case '/JSON/spider/view/results/':
        return send(res, 200, { results: b.spiderResults ?? [`${ORIGIN}/`] });
      case '/JSON/pscan/view/recordsToScan/':
        return send(res, 200, { recordsToScan: '0' });
      case '/JSON/alert/view/alerts/': {
        paged = true;
        const start = Number(url.searchParams.get('start') ?? '0');
        const count = Number(url.searchParams.get('count') ?? '500');
        return send(res, 200, { alerts: alerts.slice(start, start + count) });
      }
      default:
        return send(res, 404, { code: 'url_not_found' });
    }
  };
  const server: Server = createServer(handler);
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
  const { port } = server.address() as AddressInfo;
  return {
    apiUrl: `http://127.0.0.1:${port}`,
    requests,
    close: () =>
      new Promise<void>((done) => {
        server.closeAllConnections();
        server.close(() => done());
      }),
  };
}

export function zapAlert(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    pluginId: '10202',
    alertRef: '10202-1',
    alert: 'Absence of Anti-CSRF Tokens',
    name: 'Absence of Anti-CSRF Tokens',
    risk: 'Medium',
    confidence: 'Low',
    description: 'No anti-CSRF tokens were found.',
    url: `${ORIGIN}/login`,
    method: 'POST',
    param: '',
    attack: '',
    evidence: '<form action="/login">',
    other: '',
    inputVector: '',
    messageId: '17',
    reference: 'https://owasp.org/www-community/attacks/csrf',
    ...over,
  };
}

export function liveEnv(zap: ZapFake, key = CANARY_API_KEY): Record<string, string> {
  return { SCANBRIDGE_ZAP_API_URL: zap.apiUrl, SCANBRIDGE_ZAP_API_KEY: key };
}

export function semgrepResult(over: { id?: string; path?: string; line?: number; severity?: string; message?: string } = {}) {
  const line = over.line ?? 2;
  return {
    check_id: over.id ?? 'rules.sql-injection',
    path: over.path ?? 'src/app.js',
    start: { line, col: 1, offset: -1 },
    end: { line, col: 20, offset: -1 },
    extra: { message: over.message ?? 'Possible SQL injection', severity: over.severity ?? 'ERROR', lines: 'requires login', metavars: { $X: { abstract_content: 'x' } } },
  };
}

export function semgrepOutput(o: { results?: unknown[]; errors?: unknown[]; scanned?: string[]; version?: string } = {}): string {
  return JSON.stringify({
    results: o.results ?? [],
    errors: o.errors ?? [],
    paths: { scanned: o.scanned ?? ['src/app.js'] },
    version: o.version ?? '1.2.3',
  });
}
