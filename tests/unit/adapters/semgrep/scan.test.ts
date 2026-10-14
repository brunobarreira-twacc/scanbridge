import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { SemgrepScanContext } from '../../../../src/contracts/adapter.js';
import { RAW_JSON_MAX_BYTES, TEXT_FIELD_MAX } from '../../../../src/contracts/limits.js';
import { scan } from '../../../../src/adapters/semgrep/scan.js';
import { FakeRunner, bytes, depsWith } from './fake-deps.js';

function ctx(over: Partial<SemgrepScanContext> = {}): SemgrepScanContext {
  return {
    producer: 'semgrep',
    rootAbs: '/repo',
    targetRel: 'src',
    rules: { mode: 'local', ruleFiles: ['rules/a.yaml', 'rules/b.yaml'] },
    ruleTimeoutSeconds: 5,
    timeoutSeconds: 600,
    excludeRelToTarget: null,
    ...over,
  };
}

const LOCAL_ARGV = [
  'scan',
  '--json',
  '--metrics=off',
  '--disable-version-check',
  '--disable-nosem',
  '--timeout',
  '5',
  '--config',
  'rules/a.yaml',
  '--config',
  'rules/b.yaml',
  'src',
];

test('local rules: exact argv, cwd, process timeout and stdout cap', async () => {
  const runner = new FakeRunner({ stdout: bytes('{}') });
  await scan(ctx(), depsWith(runner));
  assert.deepEqual(runner.calls, [
    { cmd: 'semgrep', args: LOCAL_ARGV, cwd: '/repo', timeoutMs: 600_000, maxStdoutBytes: RAW_JSON_MAX_BYTES },
  ]);
});

test('local rules: exclusion goes before the target', async () => {
  const runner = new FakeRunner({ stdout: bytes('{}') });
  await scan(ctx({ excludeRelToTarget: 'out/base' }), depsWith(runner));
  assert.deepEqual(runner.calls[0]?.args, [...LOCAL_ARGV.slice(0, -1), '--exclude', 'out/base', 'src']);
});

test('registry rules: --config per id, no --metrics=off, registry_rules reason and non_deterministic_rules diagnostic', async () => {
  const runner = new FakeRunner({ stdout: bytes('{}') });
  const out = await scan(
    ctx({ rules: { mode: 'registry', ids: ['p/python', 'p/owasp'] }, excludeRelToTarget: 'out' }),
    depsWith(runner),
  );
  assert.deepEqual(runner.calls[0]?.args, [
    'scan',
    '--json',
    '--disable-version-check',
    '--disable-nosem',
    '--timeout',
    '5',
    '--config',
    'p/python',
    '--config',
    'p/owasp',
    '--exclude',
    'out',
    'src',
  ]);
  assert.deepEqual(out.reasons, ['registry_rules']);
  assert.deepEqual(out.diagnostics.map((d) => d.code), ['non_deterministic_rules']);
});

test('auto rules: --config auto, no --metrics=off, auto_rules reason', async () => {
  const runner = new FakeRunner({ stdout: bytes('{}') });
  const out = await scan(ctx({ rules: { mode: 'auto' } }), depsWith(runner));
  assert.deepEqual(runner.calls[0]?.args, [
    'scan',
    '--json',
    '--disable-version-check',
    '--disable-nosem',
    '--timeout',
    '5',
    '--config',
    'auto',
    'src',
  ]);
  assert.deepEqual(out.reasons, ['auto_rules']);
  assert.deepEqual(out.diagnostics.map((d) => d.code), ['non_deterministic_rules']);
});

test('argv never carries --error, --verbose or --strict', async () => {
  const runner = new FakeRunner({ stdout: bytes('{}') });
  await scan(ctx(), depsWith(runner));
  for (const forbidden of ['--error', '--verbose', '--strict']) {
    assert.equal(runner.calls[0]?.args.includes(forbidden), false, forbidden);
  }
});

test('exit 0 is ok with the raw stdout and no coverage loss', async () => {
  const stdout = bytes('{"results":[]}');
  const out = await scan(ctx(), depsWith(new FakeRunner({ stdout })));
  assert.equal(out.outcome, 'ok');
  assert.deepEqual(out.raw, stdout);
  assert.deepEqual(out.diagnostics, []);
  assert.deepEqual(out.coverageLoss, []);
  assert.deepEqual(out.reasons, []);
});

test('any non-zero exit is failed with a bounded stderr tail as detail [verify V1]', async () => {
  // Exit 7 is deliberately not special-cased: V1 stays open.
  const stderrTail = 'x'.repeat(TEXT_FIELD_MAX + 100) + 'END';
  const out = await scan(ctx(), depsWith(new FakeRunner({ exitCode: 7, stderrTail })));
  assert.equal(out.outcome, 'failed');
  assert.equal(out.raw, null);
  assert.equal(out.diagnostics.length, 1);
  const [failure] = out.diagnostics;
  assert.equal(failure?.code, 'tool_execution_failed');
  assert.equal([...(failure?.detail ?? '')].length, TEXT_FIELD_MAX);
  assert.ok(failure?.detail?.endsWith('END'));
});

test('a signal exit (no exit code) is failed with tool_execution_failed', async () => {
  const out = await scan(ctx(), depsWith(new FakeRunner({ exitCode: null, signal: 'SIGKILL' })));
  assert.equal(out.outcome, 'failed');
  assert.deepEqual(out.diagnostics.map((d) => d.code), ['tool_execution_failed']);
  assert.equal('detail' in (out.diagnostics[0] ?? {}), false);
});

test('timeout is failed with tool_timeout', async () => {
  const out = await scan(ctx(), depsWith(new FakeRunner({ timedOut: true, exitCode: null })));
  assert.equal(out.outcome, 'failed');
  assert.deepEqual(out.diagnostics.map((d) => d.code), ['tool_timeout']);
});

test('stdout over the cap is failed with resource_limit_exceeded', async () => {
  const out = await scan(ctx(), depsWith(new FakeRunner({ stdoutTruncated: true })));
  assert.equal(out.outcome, 'failed');
  assert.deepEqual(out.diagnostics.map((d) => d.code), ['resource_limit_exceeded']);
});

test('spawn failure is unavailable with tool_unavailable', async () => {
  const out = await scan(ctx(), depsWith(new FakeRunner({ spawnFailed: true, exitCode: null })));
  assert.equal(out.outcome, 'unavailable');
  assert.equal(out.raw, null);
  assert.deepEqual(out.diagnostics.map((d) => d.code), ['tool_unavailable']);
});

test('registry reasons and diagnostics are returned even when the scan fails', async () => {
  const out = await scan(ctx({ rules: { mode: 'auto' } }), depsWith(new FakeRunner({ exitCode: 2 })));
  assert.equal(out.outcome, 'failed');
  assert.deepEqual(out.reasons, ['auto_rules']);
  assert.deepEqual(out.diagnostics.map((d) => d.code), ['non_deterministic_rules', 'tool_execution_failed']);
});
