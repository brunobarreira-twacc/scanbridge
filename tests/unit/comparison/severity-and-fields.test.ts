import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compareDocuments } from '../../../src/core/comparison/index.js';
import type { CompareFinding, NormalizedDocument } from '../../../src/schemas/index.js';
import { document, finding, occurrence, text } from './fixtures.js';

function entryFor(base: NormalizedDocument, head: NormalizedDocument): CompareFinding {
  const outcome = compareDocuments(base, head, { allowPartial: false });
  assert.equal(outcome.ok, true);
  if (!outcome.ok) throw new Error('unreachable');
  const [entry] = outcome.result.findings;
  assert.ok(entry, 'expected one entry');
  return entry;
}

/** Both sides hold fingerprint 1; `base` and `head` override the finding under test. */
function pair(
  base: Parameters<typeof finding>[1],
  head: Parameters<typeof finding>[1],
): [NormalizedDocument, NormalizedDocument] {
  return [document({ findings: [finding(1, base)] }), document({ findings: [finding(1, head)] })];
}

test('severity comparison is comparable when both are known, complete and share a mapping version', () => {
  const entry = entryFor(...pair({ severity: 'low' }, { severity: 'low' }));
  assert.equal(entry.severity_comparison, 'comparable');
});

test('unknown severity on one side makes the comparison incomparable', () => {
  const entry = entryFor(
    ...pair({ severity: 'unknown', severity_original: 'Foo' }, { severity: 'high', severity_original: 'HIGH' }),
  );
  assert.equal(entry.severity_comparison, 'incomparable');
  assert.equal(entry.state, 'changed');
  assert.deepEqual(entry.changed_fields, ['severity_original']);
});

test('unknown severity on both sides is incomparable and never a severity state', () => {
  const entry = entryFor(...pair({ severity: 'unknown' }, { severity: 'unknown' }));
  assert.equal(entry.severity_comparison, 'incomparable');
  assert.equal(entry.state, 'unchanged');
});

test('severity_complete false on either side makes the comparison incomparable', () => {
  const entry = entryFor(
    ...pair({ severity: 'low', severity_complete: false }, { severity: 'high', severity_original: 'ERROR' }),
  );
  assert.equal(entry.severity_comparison, 'incomparable');
  assert.notEqual(entry.state, 'severity_increased');
});

test('severity mapping version mismatch makes the comparison incomparable and adds the reason', () => {
  const base = document({ severity_mapping_version: 'semgrep-1', findings: [finding(1, { severity: 'low' })] });
  const head = document({
    severity_mapping_version: 'semgrep-2',
    findings: [finding(1, { severity: 'high', severity_original: 'WARNING' })],
  });
  const outcome = compareDocuments(base, head, { allowPartial: false });
  if (!outcome.ok) throw new Error('unexpected refusal');
  const [entry] = outcome.result.findings;
  assert.equal(entry?.severity_comparison, 'incomparable');
  assert.equal(entry?.state, 'changed');
  assert.deepEqual(entry?.changed_fields, ['severity_original']);
  assert.ok(outcome.result.non_authoritative_reasons.includes('severity_mapping_version_mismatch'));
  assert.equal(outcome.result.summary.severity_comparison_incomparable, 1);
});

test('changed_fields names confidence when the producer text changes', () => {
  const entry = entryFor(...pair({ confidence: text('Low') }, { confidence: text('High') }));
  assert.deepEqual(entry.changed_fields, ['confidence']);
});

test('changed_fields names confidence when it appears or disappears', () => {
  const entry = entryFor(...pair({ confidence: null }, { confidence: text('Low') }));
  assert.deepEqual(entry.changed_fields, ['confidence']);
});

test('changed_fields names title', () => {
  const entry = entryFor(...pair({ title: text('A') }, { title: text('B') }));
  assert.deepEqual(entry.changed_fields, ['title']);
});

test('changed_fields names occurrence_count (count changes with identical occurrences)', () => {
  const entry = entryFor(...pair({ occurrence_count: 1 }, { occurrence_count: 2 }));
  assert.deepEqual(entry.changed_fields, ['occurrence_count']);
});

test('changed_fields names occurrence_severities from the sorted multiset of occurrence severity_original', () => {
  // Same count and same finding-level severity_original, different per-occurrence originals.
  const entry = entryFor(
    ...pair(
      { occurrences: [occurrence({ severity_original: 'WARN' }), occurrence({ severity_original: 'ERROR' })] },
      { occurrences: [occurrence({ severity_original: 'ERROR' }), occurrence({ severity_original: 'ERROR' })] },
    ),
  );
  assert.deepEqual(entry.changed_fields, ['occurrence_severities']);
});

test('occurrence_severities order does not matter (multiset compare)', () => {
  const entry = entryFor(
    ...pair(
      { occurrences: [occurrence({ severity_original: 'WARN' }), occurrence({ severity_original: 'ERROR' })] },
      { occurrences: [occurrence({ severity_original: 'ERROR' }), occurrence({ severity_original: 'WARN' })] },
    ),
  );
  assert.equal(entry.state, 'unchanged');
  assert.deepEqual(entry.changed_fields, []);
});

test('changed_fields names severity_original', () => {
  const entry = entryFor(...pair({ severity_original: 'ERROR' }, { severity_original: 'error' }));
  assert.deepEqual(entry.changed_fields, ['severity_original']);
});

test('evidence compares the sorted text values across occurrences', () => {
  const entry = entryFor(
    ...pair(
      { occurrences: [occurrence({ evidence: { snippet: text('a') } }), occurrence({ evidence: { snippet: text('b') } })] },
      { occurrences: [occurrence({ evidence: { snippet: text('b') } }), occurrence({ evidence: { snippet: text('a') } })] },
    ),
  );
  assert.equal(entry.state, 'unchanged');
  assert.deepEqual(entry.changed_fields, []);
});

test('evidence changes are detected in attack and evidence fields too', () => {
  const entry = entryFor(
    ...pair(
      { occurrences: [occurrence({ evidence: { attack: text('x'), evidence: text('y') } })] },
      { occurrences: [occurrence({ evidence: { attack: text('x'), evidence: text('z') } })] },
    ),
  );
  assert.deepEqual(entry.changed_fields, ['evidence']);
});

test('evidence ignores message_id, locations and line numbers', () => {
  const entry = entryFor(
    ...pair(
      {
        occurrences: [
          occurrence({
            source_location: { path: 'a.ts', start_line: 1, start_col: 1, end_line: 1, end_col: 5 },
            evidence: { snippet: text('same'), message_id: '1' },
          }),
        ],
      },
      {
        occurrences: [
          occurrence({
            source_location: { path: 'a.ts', start_line: 40, start_col: 2, end_line: 41, end_col: 9 },
            evidence: { snippet: text('same'), message_id: '99' },
          }),
        ],
      },
    ),
  );
  assert.equal(entry.state, 'unchanged');
  assert.deepEqual(entry.changed_fields, []);
});

test('description, references, category, producer_fingerprint and redactions_applied are not compared', () => {
  const entry = entryFor(
    ...pair(
      { description: text('one'), references: ['a'], category: 'x', producer_fingerprint: 'p1', redactions_applied: false },
      { description: text('two'), references: ['b'], category: 'y', producer_fingerprint: 'p2', redactions_applied: true },
    ),
  );
  assert.equal(entry.state, 'unchanged');
  assert.deepEqual(entry.changed_fields, []);
});

test('fingerprint_quality is not compared', () => {
  const entry = entryFor(...pair({ fingerprint_quality: 'exact' }, { fingerprint_quality: 'degraded' }));
  assert.equal(entry.state, 'unchanged');
  assert.equal(entry.base?.fingerprint_quality, 'exact');
  assert.equal(entry.head?.fingerprint_quality, 'degraded');
});
