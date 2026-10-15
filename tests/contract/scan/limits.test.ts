import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import * as limits from '../../../src/contracts/limits.js';
import { NORMALIZED_JSON_MAX_BYTES, RAW_JSON_MAX_BYTES } from '../../../src/contracts/limits.js';
import { normalizedTooLarge, rawTooLarge } from '../../../src/cli/scan/limits.js';
import { codes, envelope, filesIn, installFakeSemgrep, makeRepo, runCli, scanDirectory, SOURCE_LINES } from './harness.js';

// dist/tests/contract/scan -> repository root
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');

describe('V9 size limits', () => {
  it('raw size: one below and exactly at the limit are accepted, one above is not', () => {
    assert.equal(rawTooLarge(RAW_JSON_MAX_BYTES - 1), false);
    assert.equal(rawTooLarge(RAW_JSON_MAX_BYTES), false);
    assert.equal(rawTooLarge(RAW_JSON_MAX_BYTES + 1), true);
  });

  it('normalized size: one below and exactly at the limit are accepted, one above is not', () => {
    assert.equal(normalizedTooLarge(NORMALIZED_JSON_MAX_BYTES - 1), false);
    assert.equal(normalizedTooLarge(NORMALIZED_JSON_MAX_BYTES), false);
    assert.equal(normalizedTooLarge(NORMALIZED_JSON_MAX_BYTES + 1), true);
  });

  async function generated(results: number) {
    const repo = makeRepo({ 'src/app.js': SOURCE_LINES });
    installFakeSemgrep(repo, { stdoutGenerator: { results, path: 'src/app.js', messageLength: 4000 } });
    const run = await runCli(repo, ['scan', '--adapter', 'semgrep', '--target', 'src', '--output', 'out']);
    return { repo, run };
  }

  it('a normalized.json below the limit is written', async () => {
    const { repo, run } = await generated(2000);
    assert.equal(run.status, 0, JSON.stringify(envelope(run).diagnostics).slice(0, 600));
    const dir = scanDirectory(repo) as string;
    assert.ok(statSync(join(dir, 'normalized.json')).size < NORMALIZED_JSON_MAX_BYTES);
  });

  it('a normalized.json above the limit fails the scan: exit 3, raw kept, no normalized', async () => {
    const { repo, run } = await generated(7000);
    assert.equal(run.status, 3, run.stdout.slice(0, 300));
    const env = envelope(run);
    assert.equal(env.status, 'failed');
    assert.ok(codes(env).includes('resource_limit_exceeded'));
    assert.deepEqual(filesIn(scanDirectory(repo) as string), ['raw/semgrep.json', 'scan-result.json']);
    assert.deepEqual(env.artifacts.raw, ['raw/semgrep.json']);
    assert.equal(env.artifacts.normalized, null);
  });
});

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : path.endsWith('.ts') ? [path] : [];
  });
}

/** Source text without comments, strings, template literals and regex literals (best effort). */
function codeOnly(text: string): string {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:\\])\/\/.*$/gm, '$1 ')
    .replace(/'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*"|`(?:[^`\\]|\\.)*`/g, "''")
    .replace(/(?<=[=(,:!&|?]\s*)\/(?![/*])(?:[^/\\\n[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+\/[a-z]*/g, '/re/');
}

describe('V9 limits live only in src/contracts/limits.ts', () => {
  const values = new Map<number, string>();
  for (const [name, value] of Object.entries(limits)) {
    if (typeof value === 'number' && value >= 100) values.set(value, name);
  }

  it('no source file outside limits.ts repeats a limit value as a numeric literal', () => {
    // Arithmetic on KiB units for byte buffers that are not specified limits.
    const allowed = new Map<string, number[]>([
      ['src/adapters/io/runner.ts', [1024]],
      ['src/adapters/zap/probe.ts', [1024]],
      // HTTP status range check (`< 300`), not a timeout.
      ['src/adapters/zap/scan.ts', [300]],
    ]);
    const found: string[] = [];
    for (const file of walk(join(ROOT, 'src'))) {
      const rel = relative(ROOT, file).split('\\').join('/');
      if (rel === 'src/contracts/limits.ts') continue;
      const code = codeOnly(readFileSync(file, 'utf8'));
      for (const match of code.matchAll(/(?<![\w.])\d[\d_]*(?![\w.])/g)) {
        const value = Number(match[0].replace(/_/g, ''));
        const name = values.get(value);
        if (name !== undefined && !(allowed.get(rel) ?? []).includes(value)) found.push(`${rel}: ${match[0]} (= ${name})`);
      }
    }
    assert.deepEqual(found, []);
  });

  it('the scanner itself catches a duplicated literal', () => {
    const sample = codeOnly('const a = 50 * 1024 * 1024; // 4000 in a comment\nconst s = "4000";\nconst b = 4_000;');
    const hits = [...sample.matchAll(/(?<![\w.])\d[\d_]*(?![\w.])/g)].map((m) => Number(m[0].replace(/_/g, '')));
    assert.deepEqual(hits, [50, 1024, 1024, 4000]);
    assert.equal(values.get(4000), 'TEXT_FIELD_MAX');
  });
});

describe('V5 fixture provenance', () => {
  for (const tool of ['semgrep', 'zap'] as const) {
    const base = join(ROOT, 'tests', 'fixtures', tool);
    const cases = existsSync(base) ? readdirSync(base).filter((n) => statSync(join(base, n)).isDirectory()) : [];
    it(`${tool}: fixture cases exist`, () => {
      assert.ok(cases.length > 0);
    });
    for (const name of cases) {
      it(`${tool}/${name} has PROVENANCE.md with a producer version line`, () => {
        const file = join(base, name, 'PROVENANCE.md');
        assert.ok(existsSync(file), 'PROVENANCE.md is missing');
        const text = readFileSync(file, 'utf8');
        const line = text.split('\n').find((l) => l.startsWith('Producer version:'));
        assert.ok(line !== undefined, 'missing "Producer version:" line');
        const value = line.slice('Producer version:'.length).trim();
        assert.ok(value !== '', 'empty producer version');
        if (/^unknown/i.test(value)) {
          assert.match(value, /^unknown — verify against real (Semgrep|ZAP)$/i);
          assert.ok(new RegExp(`verify against real ${tool}`, 'i').test(text), `missing "verify against real ${tool}" marker`);
        }
      });
    }
  }
});
