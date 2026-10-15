import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { after, describe, it } from 'node:test';
import { document } from '../../unit/comparison/fixtures.js';

// The compiled entry: dist/tests/contract/cli-shell -> dist/src/cli/main.js.
const BIN = resolve(dirname(fileURLToPath(import.meta.url)), '../../../src/cli/main.js');

const dir = mkdtempSync(join(tmpdir(), 'scanbridge-cli-bin-'));
after(() => rmSync(dir, { recursive: true, force: true }));

function run(args: string[]) {
  const result = spawnSync(process.execPath, [BIN, ...args], {
    cwd: dir,
    encoding: 'utf8',
    env: { PATH: process.env.PATH ?? '' },
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

describe('built bin', () => {
  it('compares two reports: one JSON document on stdout, nothing on stderr, exit 0', () => {
    writeFileSync(join(dir, 'base.json'), JSON.stringify(document()));
    writeFileSync(join(dir, 'head.json'), JSON.stringify(document()));

    const result = run(['compare', '--base-report', 'base.json', '--head-report', 'head.json']);

    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).command, 'compare');
    assert.equal(result.stderr, '');
  });

  it('prints a usage error envelope with exit 1 for an unknown flag', () => {
    const result = run(['scan', '--adapter', 'semgrep', '--output', 'out', '--bogus']);

    assert.equal(result.status, 1);
    assert.deepEqual(JSON.parse(result.stdout), {
      schema_version: '1',
      status: 'error',
      error: { code: 'usage_error', message: 'invalid arguments' },
    });
  });
});
