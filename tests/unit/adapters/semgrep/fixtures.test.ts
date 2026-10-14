import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { NormalizeContext } from '../../../../src/contracts/adapter.js';
import type { SourceText } from '../../../../src/contracts/ports.js';
import { normalize } from '../../../../src/adapters/semgrep/normalize.js';
import { parse, sourceRefs } from '../../../../src/adapters/semgrep/parse.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..', 'tests', 'fixtures', 'semgrep');

// Each case: raw.json (producer stdout), expected.json, optional context.json and sources.json.
// Candidates in expected.json are projections: only the listed keys are compared.
type Expected = {
  completeness: string;
  unusableCount: number;
  diagnostics: string[];
  coverageLoss: string[];
  producerVersion?: string | null;
  candidates?: Record<string, unknown>[];
};

const DEFAULT_CONTEXT: NormalizeContext = {
  mode: 'live',
  targetRel: 'src',
  targetOrigin: null,
  producerVersion: null,
  redactionTouched: new Set(),
  coverageLoss: [],
  scanDiagnostics: [],
  scanReasons: [],
};

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

function loadContext(dir: string): NormalizeContext {
  const path = join(dir, 'context.json');
  if (!existsSync(path)) return DEFAULT_CONTEXT;
  const raw = readJson<Partial<Omit<NormalizeContext, 'redactionTouched'>> & { redactionTouched?: string[] }>(path);
  return { ...DEFAULT_CONTEXT, ...raw, redactionTouched: new Set(raw.redactionTouched ?? []) };
}

function pick(value: Record<string, unknown>, keys: string[]): Record<string, unknown> {
  return Object.fromEntries(keys.map((k) => [k, value[k]]));
}

for (const name of readdirSync(FIXTURES).sort()) {
  const dir = join(FIXTURES, name);
  test(`fixture ${name}`, () => {
    const parsed = parse(readFileSync(join(dir, 'raw.json')));
    assert.equal(parsed.ok, true, 'fixture parses');
    if (!parsed.ok) return;

    const expected = readJson<Expected>(join(dir, 'expected.json'));
    const sourceFile = join(dir, 'sources.json');
    const sourceMap = existsSync(sourceFile) ? readJson<Record<string, SourceText>>(sourceFile) : {};
    const sources = new Map<string, SourceText>();
    for (const ref of sourceRefs(parsed.doc)) {
      const text = sourceMap[ref.key];
      if (text) sources.set(ref.key, text);
    }

    const out = normalize(parsed.doc, loadContext(dir), sources);

    assert.equal(out.completeness, expected.completeness, 'completeness');
    assert.equal(out.unusableCount, expected.unusableCount, 'unusableCount');
    assert.deepEqual(out.diagnostics.map((d) => d.code), expected.diagnostics, 'diagnostics');
    assert.deepEqual(out.coverageLoss.map((d) => d.code), expected.coverageLoss, 'coverageLoss');
    if (expected.producerVersion !== undefined) {
      assert.equal(out.producerVersion, expected.producerVersion, 'producerVersion');
    }
    if (expected.candidates !== undefined) {
      assert.equal(out.candidates.length, expected.candidates.length, 'candidate count');
      expected.candidates.forEach((want, i) => {
        const got = out.candidates[i];
        assert.ok(got, `candidate ${i}`);
        assert.deepEqual(
          pick(got as unknown as Record<string, unknown>, Object.keys(want)),
          want,
          `candidate ${i}`,
        );
      });
    }
  });
}
