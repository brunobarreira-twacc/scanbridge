import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { normalize } from '../../../../src/adapters/zap/normalize.js';
import { parse } from '../../../../src/adapters/zap/parse.js';
import { assertMatches, LIVE_CONTEXT, NO_SOURCES, project } from './helpers.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..', 'tests', 'fixtures', 'zap');

// Each case: raw.json (producer bytes) and expected.json. Candidates are projections: only the listed keys are compared.
type Expected = {
  parse: 'ok' | 'invalid_json' | 'unsupported_shape';
  completeness?: string;
  unusableCount?: number;
  diagnostics?: string[];
  coverageLoss?: string[];
  reasons?: string[];
  severityMappingVersion?: string;
  candidates?: Record<string, unknown>[];
};

for (const name of readdirSync(FIXTURES).sort()) {
  const dir = join(FIXTURES, name);
  test(`fixture ${name}`, () => {
    assert.ok(existsSync(join(dir, 'PROVENANCE.md')), 'every fixture carries PROVENANCE.md');
    const provenance = readFileSync(join(dir, 'PROVENANCE.md'), 'utf8');
    assert.ok(provenance.includes('Producer version: unknown — verify against real ZAP'), 'V5 line present');

    const expected = JSON.parse(readFileSync(join(dir, 'expected.json'), 'utf8')) as Expected;
    const result = parse(readFileSync(join(dir, 'raw.json')));
    if (expected.parse !== 'ok') {
      assert.deepEqual(result, { ok: false, reason: expected.parse });
      return;
    }
    assert.ok(result.ok, 'fixture parses');

    const out = normalize(result.doc, LIVE_CONTEXT, NO_SOURCES);
    assert.equal(out.completeness, expected.completeness);
    assert.equal(out.unusableCount, expected.unusableCount);
    assert.deepEqual(
      out.diagnostics.map((d) => d.code),
      expected.diagnostics,
    );
    assert.deepEqual(
      out.coverageLoss.map((d) => d.code),
      expected.coverageLoss,
    );
    assert.deepEqual(out.reasons, expected.reasons);
    assert.equal(out.severityMappingVersion, expected.severityMappingVersion);

    assert.equal(out.candidates.length, expected.candidates?.length, 'candidate count');
    out.candidates.forEach((candidate, i) => assertMatches(project(candidate), expected.candidates?.[i], `candidates[${i}]`));
  });
}
