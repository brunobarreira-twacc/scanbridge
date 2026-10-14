import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compareDocuments } from '../../../src/core/comparison/index.js';
import type { NormalizedDocument } from '../../../src/schemas/index.js';
import { directoryTarget, document, finding, gitTarget, zapDocument } from './fixtures.js';

/** The base input has the finding; the head input lacks it. Returns the entry's state. */
function resolvedState(head: NormalizedDocument, base: NormalizedDocument = document({ findings: [finding(1)] })) {
  const outcome = compareDocuments(base, head, { allowPartial: true });
  assert.equal(outcome.ok, true);
  if (!outcome.ok) throw new Error('unreachable');
  return outcome.result.findings[0]?.state;
}

/** The head input has the finding; the base input lacks it. Returns the entry's state. */
function newState(base: NormalizedDocument, head: NormalizedDocument = document({ findings: [finding(1)] })) {
  const outcome = compareDocuments(base, head, { allowPartial: true });
  assert.equal(outcome.ok, true);
  if (!outcome.ok) throw new Error('unreachable');
  return outcome.result.findings[0]?.state;
}

test('absence from a complete head input is resolved', () => {
  assert.equal(resolvedState(document()), 'resolved');
});

test('absence in a partial head input is incomparable', () => {
  assert.equal(resolvedState(document({ completeness: 'partial', authoritative: false })), 'incomparable');
});

test('absence in an unverified head input is incomparable', () => {
  assert.equal(resolvedState(document({ completeness: 'unverified', authoritative: false })), 'incomparable');
});

test('absence in a partial base input is incomparable (head-only finding)', () => {
  assert.equal(
    newState(document({ completeness: 'partial', authoritative: false })),
    'incomparable',
  );
});

test('absence in an unverified base input is incomparable (head-only finding)', () => {
  assert.equal(
    newState(document({ completeness: 'unverified', authoritative: false })),
    'incomparable',
  );
});

test('a complete base input with a head-only finding is new', () => {
  assert.equal(newState(document()), 'new');
});

test('a failed input is treated as untrusted for absence (spec gap, see handoff)', () => {
  assert.equal(resolvedState(document({ completeness: 'failed', authoritative: false })), 'incomparable');
});

test('rules_digest mismatch makes both one-sided directions incomparable', () => {
  const rulesChanged = { rules_digest: 'f'.repeat(64) };
  assert.equal(resolvedState(document(rulesChanged)), 'incomparable');
  assert.equal(newState(document(), document({ ...rulesChanged, findings: [finding(1)] })), 'incomparable');
});

test('redaction_policy_version mismatch makes one-sided entries incomparable', () => {
  assert.equal(
    resolvedState(document({ redaction_policy_version: '2' }), document({ findings: [finding(1)] })),
    'incomparable',
  );
});

test('target subject mismatch (relative_path) makes one-sided entries incomparable', () => {
  const base = document({ findings: [finding(1)], target: gitTarget({ relative_path: 'a' }) });
  const head = document({ target: gitTarget({ relative_path: 'b' }) });
  const outcome = compareDocuments(base, head, { allowPartial: false });
  if (!outcome.ok) throw new Error('unexpected refusal');
  assert.equal(outcome.result.findings[0]?.state, 'incomparable');
  assert.ok(outcome.result.non_authoritative_reasons.includes('target_identity_incomparable'));
});

test('target subject mismatch (kind) makes one-sided entries incomparable', () => {
  const base = document({ findings: [finding(1)], target: gitTarget() });
  const head = document({ target: directoryTarget() });
  const outcome = compareDocuments(base, head, { allowPartial: false });
  if (!outcome.ok) throw new Error('unexpected refusal');
  assert.equal(outcome.result.findings[0]?.state, 'incomparable');
});

test('fingerprint_degraded on either input makes one-sided entries incomparable', () => {
  const degradedHead = document({
    non_authoritative_reasons: ['fingerprint_degraded'],
    authoritative: false,
  });
  assert.equal(resolvedState(degradedHead), 'incomparable');

  // Base lacks the finding; the default head has it.
  const degradedBase = document({
    non_authoritative_reasons: ['fingerprint_degraded'],
    authoritative: false,
  });
  assert.equal(newState(degradedBase), 'incomparable');
});

test('producer version mismatch does not affect absence', () => {
  assert.equal(
    resolvedState(document({ producer_version: '1.51.0' }), document({ findings: [finding(1)] })),
    'resolved',
  );
});

test('null producer version does not affect absence', () => {
  assert.equal(resolvedState(document({ producer_version: null })), 'resolved');
});

test('severity_mapping_version mismatch does not affect absence', () => {
  assert.equal(
    resolvedState(document({ severity_mapping_version: 'semgrep-2' })),
    'resolved',
  );
});

test('a null digest alone does not affect absence but adds target_identity_incomparable', () => {
  const base = document({ findings: [finding(1)], target: gitTarget({ content_digest: null }) });
  const head = document({ target: gitTarget({ content_digest: null }) });
  const outcome = compareDocuments(base, head, { allowPartial: false });
  if (!outcome.ok) throw new Error('unexpected refusal');
  assert.equal(outcome.result.findings[0]?.state, 'resolved');
  assert.deepEqual(outcome.result.non_authoritative_reasons, ['target_identity_incomparable']);
});

test('unmapped_severity on an input does not affect absence', () => {
  assert.equal(
    resolvedState(document({ non_authoritative_reasons: ['unmapped_severity'], authoritative: false })),
    'resolved',
  );
});

test('partial_input_allowed does not affect absence when the lacking input is complete', () => {
  const base = document({ findings: [finding(1)], completeness: 'partial', authoritative: false });
  const head = document();
  const outcome = compareDocuments(base, head, { allowPartial: true });
  if (!outcome.ok) throw new Error('unexpected refusal');
  assert.equal(outcome.result.findings[0]?.state, 'resolved');
  assert.ok(outcome.result.non_authoritative_reasons.includes('partial_input_allowed'));
});

test('ZAP live documents with a null rules digest keep absence claims trusted', () => {
  assert.equal(resolvedState(zapDocument(), zapDocument({ findings: [finding(1)] })), 'resolved');
});
