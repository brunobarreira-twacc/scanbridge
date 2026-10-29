import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { main } from '../../../src/cli/main.js';
import { BASE_ENV, scratchRepo } from '../../unit/config/helpers.js';
import { cliDeps, fakePorts, unavailableProbe } from '../../unit/cli/fakes.js';
import { document, zapDocument } from '../../unit/comparison/fixtures.js';

const DOCTOR_CONFIG = `version: 1
tools:
  semgrep:
    enabled: true
    config:
      rules: [rules/security.yaml]
  zap:
    enabled: true
    config:
      api_url_env: SCANBRIDGE_ZAP_API_URL
      api_key_env: SCANBRIDGE_ZAP_API_KEY
      target_url_env: SCANBRIDGE_ZAP_TARGET_URL
      allowed_target_origins: ["http://127.0.0.1:8080"]
  sonarqube:
    enabled: false
    config:
      api_url_env: SONARQUBE_URL
      api_key_env: SONARQUBE_TOKEN
      project_key_env: SONARQUBE_PROJECT
`;

const scratchDirs: string[] = [];
after(() => {
  for (const dir of scratchDirs) rmSync(dir, { recursive: true, force: true });
});

function workdir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'scanbridge-cli-shell-'));
  scratchDirs.push(dir);
  return dir;
}

/** Stdout must be exactly one JSON document; stderr must hold logs, never a JSON result. */
function assertShape(stdout: string, stderr: string): unknown {
  assert.ok(stdout.endsWith('\n'), 'stdout ends with a newline');
  const parsed: unknown = JSON.parse(stdout);
  if (stderr !== '') assert.throws(() => JSON.parse(stderr), 'stderr is not a JSON result');
  return parsed;
}

describe('doctor through main', () => {
  it('reports ready tools with exit 0', async () => {
    const { root, configPath } = scratchRepo(DOCTOR_CONFIG);
    const run = cliDeps({ cwd: root, env: envWith(BASE_ENV), ports: fakePorts() });
    const exitCode = await main(['doctor', '--config', configPath], run.deps);

    assert.equal(exitCode, 0);
    const report = assertShape(run.stdout.text, run.stderr.text) as { ok: boolean; command: string; tools: { status: string }[] };
    assert.equal(report.command, 'doctor');
    assert.equal(report.ok, true);
    assert.deepEqual(report.tools.map((tool) => tool.status), ['ready', 'ready', 'skipped']);
  });

  it('exits 2 when a tool is unavailable', async () => {
    const { root, configPath } = scratchRepo(DOCTOR_CONFIG);
    const ports = fakePorts({ semgrep: async () => unavailableProbe('semgrep') });
    const run = cliDeps({ cwd: root, env: envWith(BASE_ENV), ports });
    const exitCode = await main(['doctor', '--config', configPath], run.deps);

    assert.equal(exitCode, 2);
    const report = assertShape(run.stdout.text, run.stderr.text) as { ok: boolean; tools: { status: string }[] };
    assert.equal(report.ok, false);
    assert.equal(report.tools[0]?.status, 'unavailable');
  });

  it('exits 1 with an invalid_configuration envelope for a bad config', async () => {
    const { root, configPath } = scratchRepo('version: 2\n');
    const run = cliDeps({ cwd: root, env: envWith(BASE_ENV), ports: fakePorts() });
    const exitCode = await main(['doctor', '--config', configPath], run.deps);

    assert.equal(exitCode, 1);
    assert.deepEqual(assertShape(run.stdout.text, run.stderr.text), {
      schema_version: '1',
      status: 'error',
      error: { code: 'invalid_configuration', message: 'configuration is invalid' },
    });
  });

  it('marks a disabled tool as skipped and does not probe it', async () => {
    const config = DOCTOR_CONFIG.replace('enabled: true\n    config:\n      rules', 'enabled: false\n    config:\n      rules');
    const { root, configPath } = scratchRepo(config);
    const ports = fakePorts();
    const run = cliDeps({ cwd: root, env: envWith(BASE_ENV), ports });
    const exitCode = await main(['doctor', '--config', configPath], run.deps);

    assert.equal(exitCode, 0);
    const report = assertShape(run.stdout.text, run.stderr.text) as { tools: { name: string; status: string }[] };
    assert.equal(report.tools.find((tool) => tool.name === 'semgrep')?.status, 'skipped');
    assert.equal(ports.calls.semgrep.length, 0);
  });
});

describe('compare through main', () => {
  it('compares two valid reports with exit 0', async () => {
    const { base, head } = writeReports(workdir(), { base: document(), head: document({ producer_version: '1.51.0' }) });
    const run = cliDeps({ cwd: base.dir });
    const exitCode = await main(['compare', '--base-report', base.file, '--head-report', head.file], run.deps);

    assert.equal(exitCode, 0);
    const result = assertShape(run.stdout.text, run.stderr.text) as { command: string; authoritative: boolean };
    assert.equal(result.command, 'compare');
    assert.equal(result.authoritative, false, 'a producer version mismatch is non-authoritative');
    assert.equal(run.stderr.text, '');
  });

  it('reports malformed JSON as invalid_report with exit 5', async () => {
    const dir = workdir();
    const good = writeReports(dir, { base: document(), head: document() });
    const bad = join(dir, 'bad.json');
    writeFileSync(bad, '{"schema_version": ');
    const run = cliDeps({ cwd: dir });
    const exitCode = await main(['compare', '--base-report', bad, '--head-report', good.head.file], run.deps);

    assert.equal(exitCode, 5);
    assert.deepEqual(assertShape(run.stdout.text, run.stderr.text), {
      schema_version: '1',
      status: 'error',
      error: { code: 'invalid_report', message: 'base report is not valid JSON' },
    });
  });

  it('reports a schema-invalid document as invalid_report with exit 5', async () => {
    const dir = workdir();
    const { base, head } = writeReports(dir, { base: document(), head: { ...document(), schema_version: '2' } });
    const run = cliDeps({ cwd: dir });
    const exitCode = await main(['compare', '--base-report', base.file, '--head-report', head.file], run.deps);

    assert.equal(exitCode, 5);
    const envelope = assertShape(run.stdout.text, run.stderr.text) as { error: { code: string; message: string } };
    assert.equal(envelope.error.code, 'invalid_report');
    assert.equal(envelope.error.message, 'head report failed schema validation');
  });

  it('refuses reports from different producers with incompatible_reports and exit 5', async () => {
    const dir = workdir();
    const { base, head } = writeReports(dir, { base: document(), head: zapDocument() });
    const run = cliDeps({ cwd: dir });
    const exitCode = await main(['compare', '--base-report', base.file, '--head-report', head.file], run.deps);

    assert.equal(exitCode, 5);
    const envelope = assertShape(run.stdout.text, run.stderr.text) as { error: { code: string } };
    assert.equal(envelope.error.code, 'incompatible_reports');
  });

  it('refuses a partial input with exit 4 unless --allow-partial is given', async () => {
    const dir = workdir();
    const partial = document({ completeness: 'partial', authoritative: false, non_authoritative_reasons: ['partial_scan'] });
    const { base, head } = writeReports(dir, { base: partial, head: document() });

    const refused = cliDeps({ cwd: dir });
    assert.equal(await main(['compare', '--base-report', base.file, '--head-report', head.file], refused.deps), 4);
    const envelope = assertShape(refused.stdout.text, refused.stderr.text) as { error: { code: string } };
    assert.equal(envelope.error.code, 'partial_input_refused');

    const allowed = cliDeps({ cwd: dir });
    const exitCode = await main(
      ['compare', '--base-report', base.file, '--head-report', head.file, '--allow-partial'],
      allowed.deps,
    );
    assert.equal(exitCode, 0);
    const result = assertShape(allowed.stdout.text, allowed.stderr.text) as { non_authoritative_reasons: string[] };
    assert.ok(result.non_authoritative_reasons.includes('partial_input_allowed'));
  });
});

function envWith(values: Record<string, string>) {
  return { get: (name: string) => values[name] };
}

function writeReports(
  dir: string,
  docs: { base: unknown; head: unknown },
): { base: { dir: string; file: string }; head: { dir: string; file: string } } {
  const base = join(dir, 'base.json');
  const head = join(dir, 'head.json');
  writeFileSync(base, JSON.stringify(docs.base));
  writeFileSync(head, JSON.stringify(docs.head));
  return { base: { dir, file: base }, head: { dir, file: head } };
}
