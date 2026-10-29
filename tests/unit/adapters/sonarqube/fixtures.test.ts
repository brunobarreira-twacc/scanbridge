import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { NormalizeContext } from '../../../../src/contracts/adapter.js';
import type { JsonValue } from '../../../../src/contracts/enums.js';
import { normalize } from '../../../../src/adapters/sonarqube/normalize.js';
import { parse } from '../../../../src/adapters/sonarqube/parse.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..', 'tests', 'fixtures', 'sonarqube');

const CTX: NormalizeContext = {
  mode: 'live',
  targetRel: '',
  targetOrigin: null,
  producerVersion: null,
  redactionTouched: new Set(),
  coverageLoss: [],
  scanDiagnostics: [],
  scanReasons: [],
};

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

/** Every key in `expected` must match `actual`; absent keys are ignored. */
function assertMatches(actual: unknown, expected: unknown, at = '$'): void {
  if (typeof expected === 'object' && expected !== null && !Array.isArray(expected)) {
    assert.ok(typeof actual === 'object' && actual !== null, `${at} should be an object`);
    const a = actual as Record<string, unknown>;
    for (const key of Object.keys(expected as Record<string, unknown>)) {
      assertMatches(a[key], (expected as Record<string, unknown>)[key], `${at}.${key}`);
    }
    return;
  }
  assert.deepEqual(actual, expected, at);
}

function project(c: ReturnType<typeof normalize>['candidates'][number]): Record<string, unknown> {
  return {
    ruleId: c.ruleId,
    producerReference: c.producerReference,
    producerFingerprint: c.producerFingerprint,
    title: c.title,
    description: c.description,
    confidence: c.confidence,
    severityOriginal: c.severityOriginal,
    severity: c.severity,
    redactionsApplied: c.redactionsApplied,
    sourcePath: c.location.source?.path,
    startLine: c.location.source?.startLine,
  };
}

for (const name of readdirSync(FIXTURES).sort()) {
  const dir = join(FIXTURES, name);
  test(`fixture ${name}`, () => {
    assert.ok(existsSync(join(dir, 'PROVENANCE.md')), 'every fixture carries PROVENANCE.md');
    const provenance = readFileSync(join(dir, 'PROVENANCE.md'), 'utf8');
    assert.ok(provenance.includes('Producer version: unknown — verify against real SonarQube'), 'V5 line present');

    const expected = JSON.parse(readFileSync(join(dir, 'expected.json'), 'utf8')) as Expected;
    const result = parse(readFileSync(join(dir, 'raw.json')));

    if (expected.parse !== 'ok') {
      assert.deepEqual(result, { ok: false, reason: expected.parse });
      return;
    }
    assert.ok(result.ok, 'fixture parses');

    const out = normalize(result.doc as JsonValue, CTX, new Map());
    assert.equal(out.completeness, expected.completeness, 'completeness');
    assert.equal(out.unusableCount, expected.unusableCount, 'unusableCount');
    assert.deepEqual(out.diagnostics.map((d) => d.code), expected.diagnostics, 'diagnostics');
    assert.deepEqual(out.coverageLoss.map((d) => d.code), expected.coverageLoss, 'coverageLoss');
    assert.deepEqual(out.reasons, expected.reasons, 'reasons');
    assert.equal(out.severityMappingVersion, expected.severityMappingVersion, 'severityMappingVersion');
    assert.equal(out.candidates.length, expected.candidates?.length, 'candidate count');
    out.candidates.forEach((c, i) => assertMatches(project(c), expected.candidates?.[i], `candidates[${i}]`));
  });
}
