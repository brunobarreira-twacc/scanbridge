import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { NodeRunner } from '../../../src/adapters/io/runner.js';
import type { Runner } from '../../../src/contracts/ports.js';

// Test-only: `node` stands in for the production allowlist (`semgrep`, `git`).
const NODE = 'node' as Parameters<Runner['run']>[0];
const runner = new NodeRunner([NODE], 200);
const cwd = realpathSync(mkdtempSync(join(tmpdir(), 'runner-')));
const base = { cwd, timeoutMs: 10_000, maxStdoutBytes: 1_000_000 };
const text = (b: Uint8Array) => Buffer.from(b).toString('utf8');

describe('NodeRunner', () => {
  it('returns stdout of a successful child', async () => {
    const r = await runner.run(NODE, ['-e', 'process.stdout.write("hello")'], base);
    assert.equal(text(r.stdout), 'hello');
    assert.equal(r.exitCode, 0);
    assert.equal(r.signal, null);
    assert.equal(r.timedOut, false);
    assert.equal(r.spawnFailed, false);
    assert.equal(r.stdoutTruncated, false);
  });

  it('reports a non-zero exit code', async () => {
    const r = await runner.run(NODE, ['-e', 'process.exit(3)'], base);
    assert.equal(r.exitCode, 3);
    assert.equal(r.timedOut, false);
  });

  it('passes arguments as argv without a shell', async () => {
    const r = await runner.run(NODE, ['-e', 'process.stdout.write(process.argv[1])', '$(echo injected)'], base);
    assert.equal(text(r.stdout), '$(echo injected)');
  });

  it('runs in the given cwd and passes the environment through', async () => {
    process.env.SCANBRIDGE_IO_TEST = 'passed-through';
    try {
      const r = await runner.run(NODE, ['-e', 'process.stdout.write(process.cwd() + "|" + process.env.SCANBRIDGE_IO_TEST)'], base);
      assert.equal(text(r.stdout), `${cwd}|passed-through`);
    } finally {
      delete process.env.SCANBRIDGE_IO_TEST;
    }
  });

  it('kills a sleeping child on timeout and sets timedOut', async () => {
    const started = Date.now();
    const r = await runner.run(NODE, ['-e', 'setInterval(() => {}, 1000)'], { ...base, timeoutMs: 100 });
    assert.equal(r.timedOut, true);
    assert.equal(r.signal, 'SIGTERM');
    assert.ok(Date.now() - started < 5_000);
  });

  it('escalates to SIGKILL when the child ignores SIGTERM', async () => {
    const script = "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000); process.stdout.write('ready');";
    const r = await runner.run(NODE, ['-e', script], { ...base, timeoutMs: 100 });
    assert.equal(r.timedOut, true);
    assert.equal(r.signal, 'SIGKILL');
  });

  it('keeps exactly maxStdoutBytes and sets stdoutTruncated when more arrives', async () => {
    const r = await runner.run(NODE, ['-e', "process.stdout.write('x'.repeat(100000))"], {
      ...base,
      maxStdoutBytes: 1000,
    });
    assert.equal(r.stdout.byteLength, 1000);
    assert.equal(r.stdoutTruncated, true);
  });

  it('does not set stdoutTruncated when output is one byte under the cap', async () => {
    const r = await runner.run(NODE, ['-e', "process.stdout.write('x'.repeat(999))"], { ...base, maxStdoutBytes: 1000 });
    assert.equal(r.stdout.byteLength, 999);
    assert.equal(r.stdoutTruncated, false);
  });

  it('does not set stdoutTruncated when output fits exactly', async () => {
    const r = await runner.run(NODE, ['-e', "process.stdout.write('x'.repeat(1000))"], { ...base, maxStdoutBytes: 1000 });
    assert.equal(r.stdout.byteLength, 1000);
    assert.equal(r.stdoutTruncated, false);
  });

  it('keeps only the last 2 KiB of stderr', async () => {
    const r = await runner.run(NODE, ['-e', "process.stderr.write('a'.repeat(5000) + 'END')"], base);
    assert.equal(r.stderrTail.length, 2048);
    assert.ok(r.stderrTail.endsWith('END'));
    assert.equal(r.stderrTail, 'a'.repeat(2045) + 'END');
  });

  it('reports spawnFailed when the binary is missing', async () => {
    const missing = new NodeRunner(['scanbridge-no-such-binary']);
    const r = await missing.run('scanbridge-no-such-binary' as Parameters<Runner['run']>[0], [], base);
    assert.equal(r.spawnFailed, true);
    assert.equal(r.exitCode, null);
    assert.equal(r.stdout.byteLength, 0);
  });

  it('refuses a command outside the allowlist without spawning it', async () => {
    const r = await runner.run('git', ['--version'], base);
    assert.equal(r.spawnFailed, true);
    assert.equal(r.stdout.byteLength, 0);
  });

  it('production allowlist is semgrep and git only', async () => {
    const production = new NodeRunner();
    const r = await production.run(NODE, ['-e', 'process.exit(0)'], base);
    assert.equal(r.spawnFailed, true);
  });
});
