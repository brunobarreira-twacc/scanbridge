import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Candidate } from '../../../src/contracts/adapter.js';
import {
  FINDINGS_MAX,
  OCCURRENCES_PER_FINDING_MAX,
  PATH_MAX,
  RULE_ID_MAX,
} from '../../../src/contracts/limits.js';
import {
  canonicalizeSnippet,
  fingerprintFromMaterial,
  semgrepDegraded,
  semgrepExact,
} from '../../../src/core/fingerprints/index.js';
import { buildSemgrep, semgrepCandidate, shuffled } from './helpers.js';

const SNIPPET = 'db.query("SELECT * FROM t WHERE id=" + id)';
const exactFingerprint = (ruleId: string, path: string, snippet: string) =>
  fingerprintFromMaterial(semgrepExact(ruleId, path, canonicalizeSnippet(snippet)));
const degradedFingerprint = (ruleId: string, path: string, line = 42, col = 3) =>
  fingerprintFromMaterial(semgrepDegraded(ruleId, path, line, col, line, col + 55));

test('exact fingerprint uses the canonical snippet and is not degraded', () => {
  const [finding] = buildSemgrep([semgrepCandidate()]).findings;
  assert.ok(finding);
  assert.equal(finding.fingerprint, exactFingerprint('rules.sql-injection', 'src/db.ts', SNIPPET));
  assert.equal(finding.fingerprint_quality, 'exact');
  assert.equal(finding.producer_reference, null);
});

test('identical snippets at different lines group into one finding', () => {
  const a = semgrepCandidate({ location: { source: { path: 'src/db.ts', startLine: 10, startCol: 1, endLine: 10, endCol: 9 } } });
  const b = semgrepCandidate({ location: { source: { path: 'src/db.ts', startLine: 5, startCol: 1, endLine: 5, endCol: 9 } } });
  const result = buildSemgrep([a, b]);
  assert.equal(result.findings.length, 1);
  const [finding] = result.findings;
  assert.equal(finding?.occurrence_count, 2);
  assert.deepEqual(
    finding?.occurrences.map((o) => o.source_location?.start_line),
    [5, 10],
    'occurrences are in canonical location order',
  );
});

test('snippet failure gives a degraded location fingerprint and a fingerprint_degraded diagnostic', () => {
  const candidate = semgrepCandidate({ snippet: { ok: false, reason: 'invalid_utf8' } });
  const result = buildSemgrep([candidate]);
  const [finding] = result.findings;
  assert.equal(finding?.fingerprint, degradedFingerprint('rules.sql-injection', 'src/db.ts'));
  assert.equal(finding?.fingerprint_quality, 'degraded');
  assert.deepEqual(result.reasons, ['fingerprint_degraded']);
  assert.deepEqual(
    result.diagnostics.map((d) => d.code),
    ['fingerprint_degraded'],
  );
});

test('a missing snippet is treated as unreadable', () => {
  const candidate = semgrepCandidate();
  delete candidate.snippet;
  const [finding] = buildSemgrep([candidate]).findings;
  assert.equal(finding?.fingerprint_quality, 'degraded');
});

test('every snippet failure reason degrades the same way', () => {
  for (const reason of ['outside_target', 'symlink', 'too_large', 'invalid_utf8', 'missing', 'changed', 'unreadable'] as const) {
    const [finding] = buildSemgrep([semgrepCandidate({ snippet: { ok: false, reason } })]).findings;
    assert.equal(finding?.fingerprint_quality, 'degraded', reason);
  }
});

test('oversized path keeps the finding with a placeholder path and an oversized warning', () => {
  const longPath = `${'p'.repeat(PATH_MAX)}.ts`;
  const candidate = semgrepCandidate({ location: { source: { path: longPath, startLine: 1, startCol: 1, endLine: 1, endCol: 5 } } });
  const result = buildSemgrep([candidate]);
  const [finding] = result.findings;
  assert.ok(finding);
  const placeholder = finding.occurrences[0]?.source_location?.path ?? '';
  assert.match(placeholder, /^\[oversized:[0-9a-f]{64}\]$/);
  assert.equal(finding.fingerprint, fingerprintFromMaterial(semgrepDegraded('rules.sql-injection', placeholder, 1, 1, 1, 5)));
  assert.equal(finding.fingerprint_quality, 'degraded');
  assert.deepEqual(result.reasons, ['fingerprint_degraded']);
  assert.deepEqual(
    result.diagnostics.map((d) => d.code),
    ['resource_limit_exceeded'],
  );
});

test('control characters in the path give an invalid placeholder and a malformed_report warning', () => {
  const candidate = semgrepCandidate({ location: { source: { path: 'src/\u0007db.ts', startLine: 1, startCol: 1, endLine: 1, endCol: 5 } } });
  const result = buildSemgrep([candidate]);
  const [finding] = result.findings;
  assert.match(finding?.occurrences[0]?.source_location?.path ?? '', /^\[invalid:[0-9a-f]{64}\]$/);
  assert.equal(finding?.fingerprint_quality, 'degraded');
  assert.deepEqual(
    result.diagnostics.map((d) => d.code),
    ['malformed_report'],
  );
});

test('oversized rule id gives a placeholder rule id, a degraded fingerprint and a warning', () => {
  const candidate = semgrepCandidate({ ruleId: 'r'.repeat(RULE_ID_MAX + 1) });
  const [finding] = buildSemgrep([candidate]).findings;
  assert.match(finding?.rule_id ?? '', /^\[oversized:[0-9a-f]{64}\]$/);
  assert.equal(finding?.fingerprint_quality, 'degraded');
});

test('identical fingerprints group, and redactions_applied is true if any occurrence had them', () => {
  const plain = semgrepCandidate();
  const redacted = semgrepCandidate({ redactionsApplied: true, location: { source: { path: 'src/db.ts', startLine: 99, startCol: 1, endLine: 99, endCol: 4 } } });
  const [finding] = buildSemgrep([plain, redacted]).findings;
  assert.equal(finding?.occurrence_count, 2);
  assert.equal(finding?.redactions_applied, true);
});

for (const count of [99, OCCURRENCES_PER_FINDING_MAX, OCCURRENCES_PER_FINDING_MAX + 1]) {
  test(`occurrence cap with ${count} occurrences of one fingerprint`, () => {
    const candidates: Candidate[] = Array.from({ length: count }, (_, i) =>
      semgrepCandidate({ location: { source: { path: 'src/db.ts', startLine: i + 1, startCol: 1, endLine: i + 1, endCol: 9 } } }),
    );
    const result = buildSemgrep(candidates);
    const [finding] = result.findings;
    assert.equal(finding?.occurrence_count, count, 'occurrence_count is the total');
    assert.equal(finding?.occurrences.length, Math.min(count, OCCURRENCES_PER_FINDING_MAX));
    const partial = result.coverageLoss.filter((d) => d.code === 'partial_coverage');
    assert.equal(partial.length, count > OCCURRENCES_PER_FINDING_MAX ? 1 : 0);
  });
}

// [verify] V9: the finding cap value is FINDINGS_MAX in src/contracts/limits.ts; the test only uses the constant.
test('finding cap keeps the first FINDINGS_MAX findings by fingerprint and reports partial coverage', () => {
  const total = FINDINGS_MAX + 1;
  const candidates = Array.from({ length: total }, (_, i) => semgrepCandidate({ snippet: { ok: true, text: `unique snippet ${i}` } }));
  const result = buildSemgrep(candidates);
  assert.equal(result.findings.length, FINDINGS_MAX);
  const fingerprints = result.findings.map((f) => f.fingerprint);
  assert.deepEqual(fingerprints, [...fingerprints].sort());
  assert.equal(result.coverageLoss.filter((d) => d.code === 'partial_coverage').length, 1);
});

test('shuffled candidates produce identical output (determinism)', () => {
  const base = [
    semgrepCandidate({ location: { source: { path: 'src/a.ts', startLine: 3, startCol: 1, endLine: 3, endCol: 9 } } }),
    semgrepCandidate({ location: { source: { path: 'src/a.ts', startLine: 1, startCol: 1, endLine: 1, endCol: 9 } }, severityOriginal: 'WARNING', severity: 'medium' }),
    semgrepCandidate({ snippet: { ok: false, reason: 'missing' }, ruleId: 'rules.other' }),
  ];
  const expected = JSON.stringify(buildSemgrep(base));
  for (const seed of [1, 7, 42]) {
    assert.equal(JSON.stringify(buildSemgrep(shuffled(base, seed))), expected);
  }
});

test('a candidate from the other producer is rejected', () => {
  assert.throws(() => buildSemgrep([{ ...semgrepCandidate(), producer: 'zap' }]), TypeError);
});
