import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { RawDiagnostic } from '../../../src/contracts/adapter.js';
import type { Completeness, ScanReason } from '../../../src/contracts/enums.js';
import { classify, type ClassifyInput } from '../../../src/core/findings/index.js';

const coverage: RawDiagnostic = { code: 'partial_coverage', level: 'warn', message: 'lost some' };

function input(
  overrides: {
    completeness?: Completeness;
    unusableCount?: number;
    normalizeCoverage?: RawDiagnostic[];
    normalizeReasons?: ScanReason[];
    scanCoverage?: RawDiagnostic[];
    scanReasons?: ScanReason[];
    findingCoverage?: RawDiagnostic[];
    findingReasons?: ScanReason[];
    findingCount?: number;
  } = {},
): ClassifyInput {
  return {
    normalize: {
      completeness: overrides.completeness ?? 'complete',
      unusableCount: overrides.unusableCount ?? 0,
      coverageLoss: overrides.normalizeCoverage ?? [],
      reasons: overrides.normalizeReasons ?? [],
    },
    scan: { coverageLoss: overrides.scanCoverage ?? [], reasons: overrides.scanReasons ?? [] },
    findings: { coverageLoss: overrides.findingCoverage ?? [], reasons: overrides.findingReasons ?? [] },
    findingCount: overrides.findingCount ?? 1,
  };
}

test('complete with findings and no reasons is authoritative', () => {
  assert.deepEqual(classify(input()), {
    completeness: 'complete',
    authoritative: true,
    non_authoritative_reasons: [],
    diagnostics: [],
  });
});

test('complete with no findings is still complete', () => {
  const result = classify(input({ findingCount: 0 }));
  assert.equal(result.completeness, 'complete');
  assert.equal(result.authoritative, true);
});

test('unverified stays unverified and is not authoritative', () => {
  const result = classify(input({ completeness: 'unverified' }));
  assert.equal(result.completeness, 'unverified');
  assert.equal(result.authoritative, false);
  assert.deepEqual(result.non_authoritative_reasons, []);
});

test('offline_report carried from the normalizer makes an unverified result non-authoritative with the reason', () => {
  const result = classify(input({ completeness: 'unverified', normalizeReasons: ['offline_report'] }));
  assert.deepEqual(result.non_authoritative_reasons, ['offline_report']);
});

test('unverified with coverage loss becomes partial', () => {
  const result = classify(input({ completeness: 'unverified', scanCoverage: [coverage] }));
  assert.equal(result.completeness, 'partial');
  assert.deepEqual(result.non_authoritative_reasons, ['partial_scan']);
});

test('coverage loss from the normalizer, the scan or the findings build each make the scan partial', () => {
  assert.equal(classify(input({ normalizeCoverage: [coverage] })).completeness, 'partial');
  assert.equal(classify(input({ scanCoverage: [coverage] })).completeness, 'partial');
  assert.equal(classify(input({ findingCoverage: [coverage] })).completeness, 'partial');
});

test('a partial normalizer result with no coverage loss stays partial', () => {
  assert.equal(classify(input({ completeness: 'partial' })).completeness, 'partial');
});

test('unusable entries with findings left: partial, with a malformed_report diagnostic carrying the count', () => {
  const result = classify(input({ unusableCount: 2, findingCount: 3 }));
  assert.equal(result.completeness, 'partial');
  assert.equal(result.authoritative, false);
  assert.deepEqual(result.diagnostics, [
    { code: 'malformed_report', level: 'warn', message: '2 entries lack required identity values and were excluded' },
  ]);
});

test('unusable entries with no findings left: failed', () => {
  const result = classify(input({ unusableCount: 2, findingCount: 0 }));
  assert.equal(result.completeness, 'failed');
  assert.equal(result.authoritative, false);
  assert.equal(result.diagnostics[0]?.code, 'malformed_report');
});

test('empty findings with no unusable entries and no failure stay complete (no false failure)', () => {
  assert.equal(classify(input({ findingCount: 0, unusableCount: 0 })).completeness, 'complete');
});

test('normalizer failure is failed regardless of findings', () => {
  assert.equal(classify(input({ completeness: 'failed' })).completeness, 'failed');
});

test('registry or auto rules make a complete result non-authoritative with the reason', () => {
  const result = classify(input({ scanReasons: ['registry_rules'] }));
  assert.equal(result.completeness, 'complete');
  assert.equal(result.authoritative, false);
  assert.deepEqual(result.non_authoritative_reasons, ['registry_rules']);
});

test('fingerprint_degraded and unmapped_severity from the findings make the result non-authoritative', () => {
  const result = classify(input({ findingReasons: ['unmapped_severity', 'fingerprint_degraded'] }));
  assert.equal(result.authoritative, false);
  assert.deepEqual(result.non_authoritative_reasons, ['fingerprint_degraded', 'unmapped_severity']);
});

test('reasons are unioned, sorted and deduplicated', () => {
  const result = classify(
    input({ normalizeReasons: ['registry_rules', 'auto_rules'], scanReasons: ['registry_rules'], findingReasons: ['fingerprint_degraded'] }),
  );
  assert.deepEqual(result.non_authoritative_reasons, ['auto_rules', 'fingerprint_degraded', 'registry_rules']);
});
