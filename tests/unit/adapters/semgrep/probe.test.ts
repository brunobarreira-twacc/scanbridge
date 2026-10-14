import assert from 'node:assert/strict';
import { test } from 'node:test';
import { probe } from '../../../../src/adapters/semgrep/probe.js';
import { FakeRunner, bytes, depsWith } from './fake-deps.js';

test('probe runs semgrep --version and parses the first version-looking token', async () => {
  const runner = new FakeRunner({ stdout: bytes('semgrep 1.97.0 (python 3.12)\n') });
  const result = await probe({ producer: 'semgrep' }, depsWith(runner));
  assert.deepEqual(runner.calls.map((c) => [c.cmd, c.args]), [['semgrep', ['--version']]]);
  assert.deepEqual(result, { status: 'ready', version: '1.97.0', diagnostics: [] });
});

test('probe returns ready with a null version when no version token is printed', async () => {
  const runner = new FakeRunner({ stdout: bytes('unknown build\n') });
  const result = await probe({ producer: 'semgrep' }, depsWith(runner));
  assert.deepEqual(result, { status: 'ready', version: null, diagnostics: [] });
});

test('probe reports a missing binary as unavailable with tool_unavailable', async () => {
  const runner = new FakeRunner({ spawnFailed: true, exitCode: null });
  const result = await probe({ producer: 'semgrep' }, depsWith(runner));
  assert.equal(result.status, 'unavailable');
  assert.equal(result.version, null);
  assert.deepEqual(result.diagnostics.map((d) => d.code), ['tool_unavailable']);
});

test('probe treats a non-zero exit or a timeout as unavailable', async () => {
  for (const result of [{ exitCode: 2 }, { timedOut: true, exitCode: null }]) {
    const out = await probe({ producer: 'semgrep' }, depsWith(new FakeRunner(result)));
    assert.equal(out.status, 'unavailable');
    assert.deepEqual(out.diagnostics.map((d) => d.code), ['tool_unavailable']);
  }
});
