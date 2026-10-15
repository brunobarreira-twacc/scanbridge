import assert from 'node:assert/strict';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { semgrepAdapter } from '../../../src/adapters/semgrep/index.js';
import { zapAdapter } from '../../../src/adapters/zap/index.js';
import { NodeRunner } from '../../../src/adapters/io/index.js';
import type { ScanOutput, ToolCatalog } from '../../../src/contracts/adapter.js';
import { SensitiveString } from '../../../src/contracts/sensitive.js';
import { main, type CliPorts } from '../../../src/cli/main.js';
import { Capture, envOf } from '../../unit/cli/fakes.js';
import {
  CANARY_API_KEY,
  CANARY_ENV_VALUE,
  ORIGIN,
  SOURCE_LINES,
  allArtifactText,
  codes,
  configYaml,
  envelope,
  filesIn,
  installFakeSemgrep,
  makeRepo,
  readJson,
  runCli,
  scanDirectory,
  semgrepOutput,
  semgrepResult,
  startZap,
  zapAlert,
  liveEnv,
  type Repo,
} from './harness.js';

// Synthetic canary secrets, one per built-in value pattern. None is a working credential.
const PATTERN_CANARIES: Record<string, string> = {
  assignment: 'canary-assignment-value-7781',
  bearer: 'canarybearertoken7781abcd',
  'private-key': 'CANARYPRIVATEKEYBODY7781',
  github: `ghp_${'a1B2c3D4e5'.repeat(4)}`,
  githubPat: `github_pat_${'A1b2C3d4E5'.repeat(3)}`,
  gitlab: `glpat-${'a1b2c3d4e5'.repeat(2)}`,
  aws: 'AKIA1234567890ABCDEF',
  slack: 'xoxb-1234567890-canary7781',
  google: `AIza${'a1B2c3D4e5'.repeat(3)}XyZ12`,
  stripe: `sk_live_${'a1B2c3D4e5f6g7h8'}`,
  npm: `npm_${'a1B2c3D4e5'.repeat(3)}a1B2c3`,
};

const CANARY_LINES = [
  `password = "${PATTERN_CANARIES.assignment}"`,
  `Authorization: Bearer ${PATTERN_CANARIES.bearer}`,
  '-----BEGIN RSA PRIVATE KEY-----',
  PATTERN_CANARIES['private-key'] as string,
  '-----END RSA PRIVATE KEY-----',
  `token ${PATTERN_CANARIES.github}`,
  `pat ${PATTERN_CANARIES.githubPat}`,
  `gl ${PATTERN_CANARIES.gitlab}`,
  `aws ${PATTERN_CANARIES.aws}`,
  `slack ${PATTERN_CANARIES.slack}`,
  `google ${PATTERN_CANARIES.google}`,
  `stripe ${PATTERN_CANARIES.stripe}`,
  `npm ${PATTERN_CANARIES.npm}`,
  `configured ${CANARY_ENV_VALUE}`,
];

function assertNoCanary(label: string, text: string): void {
  for (const [name, secret] of Object.entries({ ...PATTERN_CANARIES, env: CANARY_ENV_VALUE, key: CANARY_API_KEY })) assert.ok(!text.includes(secret), `${label} contains the ${name} canary`);
}

describe('secret canary', () => {
  it('Semgrep: source snippets, producer lines and a configured env value never reach any output', async () => {
    const source = `${CANARY_LINES.join('\n')}\n`;
    // Lines 3-5 hold one private-key block, so they are reported as one multi-line range.
    const results = CANARY_LINES.flatMap((_, i) => (i === 3 || i === 4 ? [] : [semgrepResult({ id: `rules.c${i}`, line: i + 1, path: 'src/secrets.js' })]));
    (results[2] as ReturnType<typeof semgrepResult>).end.line = 5;
    // The producer output carries the same secrets in `lines` and in the message.
    for (const result of results) {
      result.extra.lines = CANARY_LINES.join(' ');
      result.extra.message = `found password=${PATTERN_CANARIES.assignment}`;
    }
    const repo = makeRepo({ 'src/secrets.js': source }, configYaml({ envVars: ['SCANBRIDGE_CANARY_ENV'] }));
    installFakeSemgrep(repo, { stdout: semgrepOutput({ results, scanned: ['src/secrets.js'] }), stderr: `stderr password=${PATTERN_CANARIES.assignment}` });
    const run = await runCli(repo, ['scan', '--adapter', 'semgrep', '--target', '.', '--output', 'out'], { SCANBRIDGE_CANARY_ENV: CANARY_ENV_VALUE });
    assert.equal(run.status, 0, run.stderr);
    const dir = scanDirectory(repo) as string;
    assertNoCanary('artifacts', allArtifactText(dir));
    assertNoCanary('stdout', run.stdout);
    assertNoCanary('stderr', run.stderr);
    assert.ok(readJson(join(dir, 'normalized.json')).findings.length > 0);
  });

  it('Semgrep failure: the stderr tail is redacted in diagnostics', async () => {
    const repo = makeRepo({ 'src/app.js': SOURCE_LINES });
    installFakeSemgrep(repo, { exitCode: 2, stderr: `password=${PATTERN_CANARIES.assignment} ${PATTERN_CANARIES.github} Bearer ${PATTERN_CANARIES.bearer}` });
    const run = await runCli(repo, ['scan', '--adapter', 'semgrep', '--target', '.', '--output', 'out']);
    assert.equal(run.status, 3);
    assertNoCanary('stdout', run.stdout);
    assertNoCanary('artifacts', allArtifactText(scanDirectory(repo) as string));
  });

  it('ZAP live: alert text with secrets and the API key never reach any output', async () => {
    const evidence = CANARY_LINES.join(' ');
    const alerts = [zapAlert({ evidence, other: evidence, attack: `password=${PATTERN_CANARIES.assignment}`, description: evidence })];
    const zap = await startZap({ alerts });
    try {
      const repo = makeRepo({}, configYaml({ envVars: ['SCANBRIDGE_CANARY_ENV'] }));
      const run = await runCli(repo, ['scan', '--adapter', 'zap', '--target-url', ORIGIN, '--output', 'out'], {
        ...liveEnv(zap),
        SCANBRIDGE_CANARY_ENV: CANARY_ENV_VALUE,
      });
      assert.equal(run.status, 0, run.stderr);
      const dir = scanDirectory(repo) as string;
      assertNoCanary('artifacts', allArtifactText(dir));
      assertNoCanary('stdout', run.stdout);
      assertNoCanary('stderr', run.stderr);
      assert.equal(readJson(join(dir, 'normalized.json')).findings[0].redactions_applied, true);
    } finally {
      await zap.close();
    }
  });

  it('ZAP failures never echo the API key', async () => {
    const zap = await startZap({ closed: true });
    try {
      const repo = makeRepo();
      const run = await runCli(repo, ['scan', '--adapter', 'zap', '--target-url', ORIGIN, '--output', 'out'], liveEnv(zap));
      assert.equal(run.status, 2);
      assertNoCanary('stdout', run.stdout);
      assertNoCanary('stderr', run.stderr);
      assertNoCanary('artifacts', allArtifactText(scanDirectory(repo) as string));
    } finally {
      await zap.close();
    }
  });

  it('offline ZAP: a report with secrets is stored redacted only', async () => {
    const evidence = CANARY_LINES.join(' ');
    const repo = makeRepo({}, configYaml({ envVars: ['SCANBRIDGE_CANARY_ENV'] }));
    writeFileSync(join(repo.root, 'alerts.json'), JSON.stringify({ alerts: [zapAlert({ evidence, other: evidence })] }));
    const run = await runCli(repo, ['scan', '--adapter', 'zap', '--from-report', 'alerts.json', '--target-url', ORIGIN, '--output', 'out'], {
      SCANBRIDGE_CANARY_ENV: CANARY_ENV_VALUE,
    });
    assert.equal(run.status, 0, run.stderr);
    assertNoCanary('artifacts', allArtifactText(scanDirectory(repo) as string));
    assertNoCanary('stdout', run.stdout);
  });

  it('a payload that cannot be redacted safely fails closed: redaction_failed, no raw, no normalized', async () => {
    const depth = 200_000;
    const repo = makeRepo();
    writeFileSync(join(repo.root, 'alerts.json'), `{"alerts":${'['.repeat(depth)}${']'.repeat(depth)}}`);
    const run = await runCli(repo, ['scan', '--adapter', 'zap', '--from-report', 'alerts.json', '--target-url', ORIGIN, '--output', 'out']);
    assert.equal(run.status, 3, run.stdout.slice(0, 400));
    const env = envelope(run);
    assert.ok(codes(env).includes('redaction_failed'));
    assert.deepEqual(filesIn(scanDirectory(repo) as string), ['scan-result.json']);
  });
});

describe('determinism and exclusivity', () => {
  it('normalized.json is byte-identical across two Semgrep runs on identical input', async () => {
    const repo = makeRepo({ 'src/app.js': SOURCE_LINES });
    installFakeSemgrep(repo, { stdout: semgrepOutput({ results: [semgrepResult({ id: 'rules.b', line: 5 }), semgrepResult({ id: 'rules.a', line: 3 })] }) });
    const args = ['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'out'];
    const first = await runCli(repo, args);
    const second = await runCli(repo, args);
    assert.equal(first.status, 0, first.stderr);
    assert.equal(second.status, 0, second.stderr);
    const files = filesOf(repo, 'normalized.json');
    assert.equal(files.length, 2);
    assert.equal(files[0], files[1]);
    assert.ok((files[0] as string).endsWith('}\n'));
  });

  it('normalized.json is byte-identical across two offline ZAP runs', async () => {
    const repo = makeRepo();
    const alerts = [zapAlert({ pluginId: '2' }), zapAlert({ pluginId: '1' }), zapAlert({ pluginId: '2' })];
    writeFileSync(join(repo.root, 'alerts.json'), JSON.stringify({ alerts }));
    const args = ['scan', '--adapter', 'zap', '--from-report', 'alerts.json', '--target-url', ORIGIN, '--output', 'out'];
    await runCli(repo, args);
    await runCli(repo, args);
    const files = filesOf(repo, 'normalized.json');
    assert.equal(files.length, 2);
    assert.equal(files[0], files[1]);
  });

  it('a second scan with the identical scan_id is refused and the first stays untouched', async () => {
    const repo = makeRepo({ 'src/app.js': SOURCE_LINES });
    const ports = fakeCatalogPorts(async () => okOutput(semgrepOutput()));
    const run = () => {
      const stdout = new Capture();
      const stderr = new Capture();
      return main(['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'out'], {
        cwd: repo.root,
        env: envOf({}),
        clock: { now: () => new Date(Date.UTC(2026, 9, 13, 14, 25, 1, 123)), sleep: async () => {} },
        ports,
        stdout,
        stderr,
      }).then((exitCode) => ({ exitCode, stdout: stdout.text }));
    };
    const first = await run();
    assert.equal(first.exitCode, 0);
    const dir = scanDirectory(repo) as string;
    const before = readFileSync(join(dir, 'scan-result.json'), 'utf8');
    const second = await run();
    assert.equal(second.exitCode, 3);
    const env = JSON.parse(second.stdout);
    assert.deepEqual(env.artifacts, { directory: null, raw: null, normalized: null });
    assert.equal(readFileSync(join(dir, 'scan-result.json'), 'utf8'), before);
    assert.equal(before, first.stdout);
  });
});

function filesOf(repo: Repo, name: string): string[] {
  const out = join(repo.root, 'out');
  return filesIn(out)
    .filter((f) => f.endsWith(`/${name}`))
    .map((f) => readFileSync(join(out, f), 'utf8'));
}

// ---- fake catalogs ------------------------------------------------------------------------------

type Recorded = { semgrepProbe: unknown[]; zapProbe: unknown[]; semgrepScan: unknown[]; zapScan: unknown[] };

function okOutput(stdout: string): ScanOutput {
  return { outcome: 'ok', raw: new TextEncoder().encode(stdout), diagnostics: [], coverageLoss: [], reasons: [] };
}

function fakeCatalogPorts(
  scan: () => Promise<ScanOutput>,
  recorded: Recorded = { semgrepProbe: [], zapProbe: [], semgrepScan: [], zapScan: [] },
): CliPorts & { recorded: Recorded } {
  const catalog: ToolCatalog = {
    semgrep: {
      ...semgrepAdapter,
      probe: async (c) => {
        recorded.semgrepProbe.push(c);
        return { status: 'ready', version: '1.2.3', diagnostics: [] };
      },
      scan: async (c) => {
        recorded.semgrepScan.push(c);
        return scan();
      },
    },
    zap: {
      ...zapAdapter,
      probe: async (c) => {
        recorded.zapProbe.push(c);
        return { status: 'ready', version: '2.15.0', diagnostics: [] };
      },
      scan: async (c) => {
        recorded.zapScan.push(c);
        return scan();
      },
    },
  };
  return { catalog, runner: new NodeRunner(), http: { request: async () => ({ kind: 'closed' }) }, recorded };
}

async function inProcess(repo: Repo, argv: string[], ports: CliPorts, env: Record<string, string> = {}) {
  const stdout = new Capture();
  const stderr = new Capture();
  const asked: string[] = [];
  const exitCode = await main(argv, {
    cwd: repo.root,
    env: { get: (name) => (asked.push(name), env[name]) },
    clock: { now: () => new Date(Date.UTC(2026, 9, 13, 14, 25, 1, 123)), sleep: async () => {} },
    ports,
    stdout,
    stderr,
  });
  return { exitCode, stdout: stdout.text, stderr: stderr.text, asked };
}

describe('contexts and ports', () => {
  it('offline ZAP calls neither probe nor scan and never reads the API URL or key variables', async () => {
    const throwing: ToolCatalog = {
      semgrep: semgrepAdapter,
      zap: {
        ...zapAdapter,
        probe: async () => {
          throw new Error('probe must not be called');
        },
        scan: async () => {
          throw new Error('scan must not be called');
        },
      },
    };
    const repo = makeRepo();
    writeFileSync(join(repo.root, 'alerts.json'), JSON.stringify({ alerts: [zapAlert()] }));
    const ports: CliPorts = { catalog: throwing, runner: new NodeRunner(), http: { request: async () => ({ kind: 'closed' }) } };
    const result = await inProcess(repo, ['scan', '--adapter', 'zap', '--from-report', 'alerts.json', '--output', 'out'], ports, {
      SCANBRIDGE_ZAP_TARGET_URL: ORIGIN,
    });
    assert.equal(result.exitCode, 0, result.stdout);
    assert.equal(JSON.parse(result.stdout).status, 'unverified');
    assert.ok(!result.asked.includes('SCANBRIDGE_ZAP_API_URL'));
    assert.ok(!result.asked.includes('SCANBRIDGE_ZAP_API_KEY'));
  });

  it('probe contexts hold no dummy target, scan id or key value', async () => {
    const repo = makeRepo({ 'src/app.js': SOURCE_LINES });
    const ports = fakeCatalogPorts(async () => okOutput(semgrepOutput()));
    const semgrep = await inProcess(repo, ['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'out'], ports);
    assert.equal(semgrep.exitCode, 0, semgrep.stdout);
    assert.deepEqual(ports.recorded.semgrepProbe, [{ producer: 'semgrep' }]);

    const zapPorts = fakeCatalogPorts(async () => okOutput(JSON.stringify({ alerts: [zapAlert()] })));
    const zap = await inProcess(
      repo,
      ['scan', '--adapter', 'zap', '--target-url', ORIGIN, '--output', 'out2'],
      zapPorts,
      { SCANBRIDGE_ZAP_API_URL: 'http://127.0.0.1:9', SCANBRIDGE_ZAP_API_KEY: CANARY_API_KEY },
    );
    assert.equal(zap.exitCode, 0, zap.stdout);
    const probe = zapPorts.recorded.zapProbe[0] as { producer: string; apiUrl: string; apiKey: SensitiveString };
    assert.deepEqual(Object.keys(probe).sort(), ['apiKey', 'apiUrl', 'producer']);
    assert.ok(probe.apiKey instanceof SensitiveString);
    assert.equal(String(probe.apiKey), '[REDACTED]');
    assert.ok(!JSON.stringify(probe).includes(CANARY_API_KEY));
    const scanContext = zapPorts.recorded.zapScan[0] as Record<string, unknown>;
    assert.equal(scanContext.targetOrigin, ORIGIN);
    assert.match(String(scanContext.scanId), /^\d{8}T\d{6}\.\d{3}Z-[0-9a-f]{8}$/);
    assert.ok(!JSON.stringify(scanContext).includes(CANARY_API_KEY));
    assertNoCanary('stdout', zap.stdout);
  });

  it('a scan timeout reported by the adapter is failed, exit 3, no raw', async () => {
    const repo = makeRepo({ 'src/app.js': SOURCE_LINES });
    const ports = fakeCatalogPorts(async () => ({
      outcome: 'failed',
      raw: null,
      diagnostics: [{ code: 'tool_timeout', level: 'error', tool: 'semgrep', message: 'semgrep exceeded the scan timeout' }],
      coverageLoss: [],
      reasons: [],
    }));
    const result = await inProcess(repo, ['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'out'], ports);
    assert.equal(result.exitCode, 3);
    const env = JSON.parse(result.stdout);
    assert.equal(env.status, 'failed');
    assert.deepEqual(env.diagnostics.map((d: { code: string }) => d.code), ['tool_timeout']);
    assert.deepEqual(filesIn(scanDirectory(repo) as string), ['scan-result.json']);
  });

  it('an adapter-reported unavailable scan is exit 2', async () => {
    const repo = makeRepo({ 'src/app.js': SOURCE_LINES });
    const ports = fakeCatalogPorts(async () => ({
      outcome: 'unavailable',
      raw: null,
      diagnostics: [{ code: 'tool_unavailable', level: 'error', tool: 'semgrep', message: 'semgrep could not be started' }],
      coverageLoss: [],
      reasons: [],
    }));
    const result = await inProcess(repo, ['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'out'], ports);
    assert.equal(result.exitCode, 2);
    assert.equal(JSON.parse(result.stdout).status, 'failed');
  });

  it('an adapter that throws is contained: failed, exit 3, scan-result.json written, no thrown text leaked', async () => {
    const repo = makeRepo({ 'src/app.js': SOURCE_LINES });
    const ports = fakeCatalogPorts(async () => {
      throw new Error(`leak ${PATTERN_CANARIES.assignment}`);
    });
    const result = await inProcess(repo, ['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'out'], ports);
    assert.equal(result.exitCode, 3);
    assertNoCanary('stdout', result.stdout);
    assert.ok(existsSync(join(scanDirectory(repo) as string, 'scan-result.json')));
  });

  it('an unwired build reports the tool unavailable before creating anything', async () => {
    const repo = makeRepo({ 'src/app.js': SOURCE_LINES });
    const stdout = new Capture();
    const exitCode = await main(['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'out'], {
      cwd: repo.root,
      env: envOf({}),
      clock: { now: () => new Date(0), sleep: async () => {} },
      stdout,
      stderr: new Capture(),
    });
    assert.equal(exitCode, 2);
    assert.deepEqual(JSON.parse(stdout.text).artifacts, { directory: null, raw: null, normalized: null });
    assert.equal(existsSync(join(repo.root, 'out')), false);
  });
});
