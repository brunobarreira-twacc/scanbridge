import assert from 'node:assert/strict';
import { test } from 'node:test';
import { REFERENCE_MAX, REFERENCES_PER_FINDING_MAX } from '../../../src/contracts/limits.js';
import { buildSemgrep, semgrepCandidate } from './helpers.js';

const REDACTED = 'https://example.com/docs?key=[REDACTED]';

test('redaction-token strings pass through unchanged', () => {
  const [finding] = buildSemgrep([semgrepCandidate({ references: [REDACTED] })]).findings;
  assert.deepEqual(finding?.references, [REDACTED]);
});

test('control characters in references are replaced with U+FFFD', () => {
  const [finding] = buildSemgrep([semgrepCandidate({ references: ['https://a.example/\u0007x\ty'] })]).findings;
  assert.deepEqual(finding?.references, ['https://a.example/�x\ty']);
});

test('references over the limit are omitted, never truncated; a reference at the limit is kept', () => {
  const atLimit = 'a'.repeat(REFERENCE_MAX);
  const overLimit = 'b'.repeat(REFERENCE_MAX + 1);
  const result = buildSemgrep([semgrepCandidate({ references: [atLimit, overLimit] })]);
  const [finding] = result.findings;
  assert.deepEqual(finding?.references, [atLimit]);
  const warnings = result.diagnostics.filter((d) => d.code === 'resource_limit_exceeded');
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]?.message ?? '', new RegExp(`^1 references longer than ${REFERENCE_MAX} code points and 0 references beyond`));
});

test('references are sorted by code point, deduplicated across occurrences and stay strings', () => {
  const a = semgrepCandidate({ references: ['https://b.example', 'https://a.example'] });
  const b = semgrepCandidate({ references: ['https://a.example', 'https://c.example'], location: { source: { path: 'src/db.ts', startLine: 7, startCol: 1, endLine: 7, endCol: 9 } } });
  const [finding] = buildSemgrep([a, b]).findings;
  assert.deepEqual(finding?.references, ['https://a.example', 'https://b.example', 'https://c.example']);
  for (const reference of finding?.references ?? []) assert.equal(typeof reference, 'string');
});

// [verify] V9: the per-finding cap is REFERENCES_PER_FINDING_MAX in src/contracts/limits.ts; the test only uses the constant.
test('at most REFERENCES_PER_FINDING_MAX references are kept, with one warning recording the counts', () => {
  const extra = 5;
  const references = Array.from({ length: REFERENCES_PER_FINDING_MAX + extra }, (_, i) => `https://ref.example/${String(i).padStart(3, '0')}`);
  const result = buildSemgrep([semgrepCandidate({ references })]);
  const [finding] = result.findings;
  assert.equal(finding?.references?.length, REFERENCES_PER_FINDING_MAX);
  assert.equal(finding?.references?.[0], 'https://ref.example/000', 'first in sorted order are kept');
  const warnings = result.diagnostics.filter((d) => d.code === 'resource_limit_exceeded');
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0]?.message, `0 references longer than ${REFERENCE_MAX} code points and ${extra} references beyond ${REFERENCES_PER_FINDING_MAX} per finding were omitted`);
});

test('reference omission adds no coverage loss and no completeness change', () => {
  const result = buildSemgrep([semgrepCandidate({ references: ['b'.repeat(REFERENCE_MAX + 1)] })]);
  assert.deepEqual(result.coverageLoss, []);
  assert.deepEqual(result.reasons, []);
});
