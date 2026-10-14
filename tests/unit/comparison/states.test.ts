import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compareDocuments } from '../../../src/core/comparison/index.js';
import { finding, document, fp, text } from './fixtures.js';

function compareOk(base: Parameters<typeof compareDocuments>[0], head: Parameters<typeof compareDocuments>[1]) {
  const outcome = compareDocuments(base, head, { allowPartial: false });
  assert.equal(outcome.ok, true);
  if (!outcome.ok) throw new Error('unreachable');
  return outcome.result;
}

test('identical findings are unchanged and comparable', () => {
  const result = compareOk(
    document({ findings: [finding(1)] }),
    document({ findings: [finding(1)] }),
  );
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0]?.state, 'unchanged');
  assert.deepEqual(result.findings[0]?.severity_comparison, 'comparable');
  assert.deepEqual(result.findings[0]?.changed_fields, []);
  assert.equal(result.summary.unchanged, 1);
});

test('head-only finding with complete base is new, with base null', () => {
  const result = compareOk(document(), document({ findings: [finding(1)] }));
  const [entry] = result.findings;
  assert.equal(entry?.state, 'new');
  assert.equal(entry?.base, null);
  assert.notEqual(entry?.head, null);
  assert.equal(entry?.severity_comparison, 'incomparable');
  assert.deepEqual(entry?.changed_fields, []);
  assert.equal(result.summary.new, 1);
});

test('base-only finding with complete head is resolved, with head null', () => {
  const result = compareOk(document({ findings: [finding(1)] }), document());
  const [entry] = result.findings;
  assert.equal(entry?.state, 'resolved');
  assert.equal(entry?.head, null);
  assert.notEqual(entry?.base, null);
  assert.equal(entry?.severity_comparison, 'incomparable');
  assert.equal(result.summary.resolved, 1);
});

test('a non-severity field change is changed with its sorted field list', () => {
  const result = compareOk(
    document({ findings: [finding(1, { confidence: text('Low'), title: text('Old title') })] }),
    document({ findings: [finding(1, { confidence: text('High'), title: text('New title') })] }),
  );
  const [entry] = result.findings;
  assert.equal(entry?.state, 'changed');
  assert.deepEqual(entry?.changed_fields, ['confidence', 'title']);
  assert.equal(result.summary.changed, 1);
});

test('severity increase is severity_increased and keeps other changed fields', () => {
  const result = compareOk(
    document({ findings: [finding(1, { severity: 'medium', severity_original: 'WARNING', title: text('Old') })] }),
    document({ findings: [finding(1, { severity: 'high', severity_original: 'ERROR', title: text('New') })] }),
  );
  const [entry] = result.findings;
  assert.equal(entry?.state, 'severity_increased');
  assert.equal(entry?.severity_comparison, 'comparable');
  assert.deepEqual(entry?.changed_fields, ['severity_original', 'title']);
  assert.equal(result.summary.severity_increased, 1);
  assert.equal(result.summary.severity_comparison_incomparable, 0);
});

test('severity decrease is severity_decreased', () => {
  const result = compareOk(
    document({ findings: [finding(1, { severity: 'critical', severity_original: 'CRITICAL' })] }),
    document({ findings: [finding(1, { severity: 'low', severity_original: 'INFO' })] }),
  );
  const [entry] = result.findings;
  assert.equal(entry?.state, 'severity_decreased');
  assert.deepEqual(entry?.changed_fields, ['severity_original']);
  assert.equal(result.summary.severity_decreased, 1);
});

test('same rank with differing severity_original is changed, not a severity state', () => {
  const result = compareOk(
    document({ findings: [finding(1, { severity: 'high', severity_original: 'ERROR' })] }),
    document({ findings: [finding(1, { severity: 'high', severity_original: 'HIGH' })] }),
  );
  const [entry] = result.findings;
  assert.equal(entry?.state, 'changed');
  assert.equal(entry?.severity_comparison, 'comparable');
  assert.deepEqual(entry?.changed_fields, ['severity_original']);
});

test('one-sided entries never carry changed fields', () => {
  const result = compareOk(
    document({ findings: [finding(1)] }),
    document({ findings: [finding(2, { title: text('Other') })] }),
  );
  for (const entry of result.findings) {
    assert.deepEqual(entry.changed_fields, []);
    assert.equal(entry.severity_comparison, 'incomparable');
  }
});

test('entries are sorted by fingerprint and summary counts each state', () => {
  const result = compareOk(
    document({ findings: [finding(3), finding(1, { confidence: text('Low') })] }),
    document({ findings: [finding(1, { confidence: text('High') }), finding(2)] }),
  );
  assert.deepEqual(
    result.findings.map((entry) => entry.fingerprint),
    [fp(1), fp(2), fp(3)],
  );
  assert.deepEqual(
    result.findings.map((entry) => entry.state),
    ['changed', 'new', 'resolved'],
  );
  assert.deepEqual(result.summary, {
    new: 1,
    resolved: 1,
    unchanged: 0,
    changed: 1,
    severity_increased: 0,
    severity_decreased: 0,
    incomparable: 0,
    severity_comparison_incomparable: 2,
  });
});

test('differing fingerprint versions give one incomparable one-sided entry per finding per side', () => {
  const result = compareOk(
    document({ fingerprint_version: 'v1', findings: [finding(1), finding(2)] }),
    document({ fingerprint_version: 'v2', findings: [finding(1)] }),
  );
  assert.equal(result.findings.length, 3);
  for (const entry of result.findings) {
    assert.equal(entry.state, 'incomparable');
    assert.equal(entry.severity_comparison, 'incomparable');
    assert.deepEqual(entry.changed_fields, []);
    assert.ok(entry.base === null || entry.head === null, 'no matching across versions');
  }
  assert.deepEqual(
    result.findings.map((entry) => [entry.fingerprint, entry.base !== null]),
    [
      [fp(1), true],
      [fp(1), false],
      [fp(2), true],
    ],
  );
  assert.equal(result.summary.incomparable, 3);
  assert.deepEqual(result.non_authoritative_reasons, ['fingerprint_version_mismatch']);
});
