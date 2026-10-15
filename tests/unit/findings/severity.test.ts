import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Candidate } from '../../../src/contracts/adapter.js';
import type { Severity } from '../../../src/contracts/enums.js';
import { buildSemgrep, semgrepCandidate } from './helpers.js';

/** Same fingerprint (same rule, path and snippet), different line and severity. */
const at = (line: number, severity: Severity, severityOriginal: string): Candidate =>
  semgrepCandidate({
    severity,
    severityOriginal,
    location: { source: { path: 'src/db.ts', startLine: line, startCol: 1, endLine: line, endCol: 9 } },
  });

test('mixed known severities: the highest rank wins, with its own original and complete true', () => {
  const [finding] = buildSemgrep([at(1, 'medium', 'WARNING'), at(2, 'high', 'ERROR'), at(3, 'low', 'INFO')]).findings;
  assert.equal(finding?.severity, 'high');
  assert.equal(finding?.severity_original, 'ERROR');
  assert.equal(finding?.severity_complete, true);
  assert.deepEqual(
    finding?.occurrences.map((o) => o.severity),
    ['medium', 'high', 'low'],
    'each occurrence keeps its own severity',
  );
});

test('partly unknown: the known maximum still wins, severity_complete is false and unmapped_severity is reported', () => {
  const result = buildSemgrep([at(1, 'high', 'ERROR'), at(2, 'unknown', 'Strange')]);
  const [finding] = result.findings;
  assert.equal(finding?.severity, 'high');
  assert.equal(finding?.severity_original, 'ERROR');
  assert.equal(finding?.severity_complete, false);
  assert.deepEqual(result.reasons, ['unmapped_severity']);
});

test('all unknown: severity is unknown and severity_original comes from the first canonical occurrence', () => {
  const [finding] = buildSemgrep([at(9, 'unknown', 'Late'), at(4, 'unknown', 'Early')]).findings;
  assert.equal(finding?.severity, 'unknown');
  assert.equal(finding?.severity_original, 'Early');
  assert.equal(finding?.severity_complete, false);
});

test('tie-break: among equal known severities, the first in canonical order supplies severity_original', () => {
  const [finding] = buildSemgrep([at(8, 'high', 'LATE_HIGH'), at(2, 'high', 'EARLY_HIGH')]).findings;
  assert.equal(finding?.severity, 'high');
  assert.equal(finding?.severity_original, 'EARLY_HIGH');
  assert.equal(finding?.severity_complete, true);
});

test('no unknown occurrences: no unmapped_severity reason', () => {
  const result = buildSemgrep([at(1, 'info', 'INFO')]);
  assert.deepEqual(result.reasons, []);
  assert.equal(result.findings[0]?.severity_complete, true);
});
