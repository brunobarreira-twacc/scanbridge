import assert from 'node:assert/strict';
import { test } from 'node:test';
import { compareDocuments, type CompareOutcome } from '../../../src/core/comparison/index.js';
import { CompareResultSchema, type CompareResult, type NormalizedDocument } from '../../../src/schemas/index.js';
import {
  DIGEST_CONFIG,
  directoryTarget,
  document,
  finding,
  gitTarget,
  httpOriginTarget,
  zapDocument,
  DIGEST_CONTENT_OTHER,
} from './fixtures.js';

function run(base: NormalizedDocument, head: NormalizedDocument, allowPartial = false): CompareResult {
  const outcome: CompareOutcome = compareDocuments(base, head, { allowPartial });
  assert.equal(outcome.ok, true, outcome.ok ? '' : `refused: ${outcome.error}`);
  if (!outcome.ok) throw new Error('unreachable');
  return outcome.result;
}

// ---- Refusals -------------------------------------------------------------

test('different producers are refused as incompatible_reports', () => {
  const outcome = compareDocuments(document(), zapDocument(), { allowPartial: false });
  assert.deepEqual(outcome, { ok: false, error: 'incompatible_reports' });
});

test('incompatible_reports takes precedence over partial_input_refused', () => {
  const outcome = compareDocuments(document({ completeness: 'partial', authoritative: false }), zapDocument(), {
    allowPartial: false,
  });
  assert.deepEqual(outcome, { ok: false, error: 'incompatible_reports' });
});

test('a partial base without allowPartial is refused', () => {
  const outcome = compareDocuments(document({ completeness: 'partial', authoritative: false }), document(), {
    allowPartial: false,
  });
  assert.deepEqual(outcome, { ok: false, error: 'partial_input_refused' });
});

test('a partial head without allowPartial is refused', () => {
  const outcome = compareDocuments(document(), document({ completeness: 'partial', authoritative: false }), {
    allowPartial: false,
  });
  assert.deepEqual(outcome, { ok: false, error: 'partial_input_refused' });
});

test('an unverified input never needs the flag', () => {
  const outcome = compareDocuments(document({ completeness: 'unverified', authoritative: false }), document(), {
    allowPartial: false,
  });
  assert.equal(outcome.ok, true);
});

test('allowPartial lets a partial input through and adds partial_input_allowed', () => {
  const result = run(document({ completeness: 'partial', authoritative: false }), document(), true);
  assert.ok(result.non_authoritative_reasons.includes('partial_input_allowed'));
  assert.ok(result.non_authoritative_reasons.includes('base_input_non_authoritative'));
  assert.equal(result.authoritative, false);
});

test('allowPartial with no partial input adds no partial_input_allowed', () => {
  const result = run(document(), document(), true);
  assert.equal(result.non_authoritative_reasons.includes('partial_input_allowed'), false);
  assert.equal(result.authoritative, true);
});

// ---- Authority and compare-level reasons ----------------------------------

test('identical complete inputs are authoritative with no reasons', () => {
  const result = run(document(), document());
  assert.equal(result.authoritative, true);
  assert.deepEqual(result.non_authoritative_reasons, []);
});

test('a non-authoritative input adds its side reason and makes the comparison non-authoritative', () => {
  const result = run(document({ non_authoritative_reasons: ['registry_rules'], authoritative: false }), document());
  assert.deepEqual(result.non_authoritative_reasons, ['base_input_non_authoritative']);
  assert.equal(result.authoritative, false);
  assert.deepEqual(result.base.non_authoritative_reasons, ['registry_rules']);
});

test('producer version mismatch', () => {
  const result = run(document(), document({ producer_version: '1.51.0' }));
  assert.deepEqual(result.non_authoritative_reasons, ['producer_version_mismatch']);
});

test('null producer version on either side is producer_version_incomparable', () => {
  assert.deepEqual(run(document({ producer_version: null }), document()).non_authoritative_reasons, [
    'producer_version_incomparable',
  ]);
  assert.deepEqual(run(document(), document({ producer_version: null })).non_authoritative_reasons, [
    'producer_version_incomparable',
  ]);
});

test('rules_digest mismatch adds rules_mismatch', () => {
  const result = run(document(), document({ rules_digest: 'f'.repeat(64) }));
  assert.deepEqual(result.non_authoritative_reasons, ['rules_mismatch']);
});

test('redaction_policy_version mismatch adds redaction_policy_mismatch', () => {
  const result = run(document(), document({ redaction_policy_version: '2' }));
  assert.deepEqual(result.non_authoritative_reasons, ['redaction_policy_mismatch']);
});

test('fingerprint_version mismatch adds fingerprint_version_mismatch', () => {
  const result = run(document(), document({ fingerprint_version: 'v2' }));
  assert.deepEqual(result.non_authoritative_reasons, ['fingerprint_version_mismatch']);
});

test('severity_mapping_version mismatch adds severity_mapping_version_mismatch', () => {
  const result = run(document(), document({ severity_mapping_version: 'semgrep-2' }));
  assert.deepEqual(result.non_authoritative_reasons, ['severity_mapping_version_mismatch']);
});

test('configuration_digest difference is metadata only', () => {
  const result = run(document(), document({ configuration_digest: 'f'.repeat(64) }));
  assert.equal(result.metadata.configuration_digest_equal, false);
  assert.equal(result.authoritative, true);
  assert.deepEqual(result.non_authoritative_reasons, []);
  assert.equal(run(document(), document({ configuration_digest: DIGEST_CONFIG })).metadata.configuration_digest_equal, true);
});

test('reasons come out in the closed spec order', () => {
  const result = run(
    document({ non_authoritative_reasons: ['unmapped_severity'], authoritative: false, producer_version: null }),
    document({ rules_digest: 'f'.repeat(64), redaction_policy_version: '2', fingerprint_version: 'v2' }),
  );
  assert.deepEqual(result.non_authoritative_reasons, [
    'fingerprint_version_mismatch',
    'redaction_policy_mismatch',
    'rules_mismatch',
    'producer_version_incomparable',
    'base_input_non_authoritative',
  ]);
});

// ---- Target comparability matrix ------------------------------------------

test('git: same relative_path and both digests present is comparable; revisions are informational', () => {
  const result = run(
    document({ target: gitTarget({ revision: 'before' }) }),
    document({ target: gitTarget({ revision: 'after', dirty: true }) }),
  );
  assert.equal(result.non_authoritative_reasons.includes('target_identity_incomparable'), false);
  assert.equal(result.authoritative, true);
});

test('git: a null digest on either side adds only target_identity_incomparable', () => {
  const result = run(document(), document({ target: gitTarget({ content_digest: null }) }));
  assert.deepEqual(result.non_authoritative_reasons, ['target_identity_incomparable']);
});

test('git: different relative_path is a subject mismatch and target_identity_incomparable', () => {
  const result = run(document(), document({ target: gitTarget({ relative_path: 'other' }) }));
  assert.deepEqual(result.non_authoritative_reasons, ['target_identity_incomparable']);
});

test('directory: same relative_path and both digests present is comparable', () => {
  const result = run(
    document({ target: directoryTarget() }),
    document({ target: directoryTarget({ content_digest: DIGEST_CONTENT_OTHER }) }),
  );
  assert.equal(result.authoritative, true);
});

test('directory: null digest adds target_identity_incomparable; different path does too', () => {
  assert.deepEqual(
    run(document({ target: directoryTarget() }), document({ target: directoryTarget({ content_digest: null }) }))
      .non_authoritative_reasons,
    ['target_identity_incomparable'],
  );
  assert.deepEqual(
    run(document({ target: directoryTarget() }), document({ target: directoryTarget({ relative_path: 'x' }) }))
      .non_authoritative_reasons,
    ['target_identity_incomparable'],
  );
});

test('mismatched kinds (git vs directory) are target_identity_incomparable', () => {
  const result = run(document({ target: gitTarget() }), document({ target: directoryTarget() }));
  assert.deepEqual(result.non_authoritative_reasons, ['target_identity_incomparable']);
});

test('http_origin: same origin is comparable; different origin is not', () => {
  assert.equal(run(zapDocument(), zapDocument()).authoritative, true);
  assert.deepEqual(
    run(zapDocument(), zapDocument({ target: httpOriginTarget({ origin: 'http://127.0.0.1:9090' }) })).non_authoritative_reasons,
    ['target_identity_incomparable'],
  );
});

test('two complete live ZAP documents with asserted revisions are authoritative and echo the revisions', () => {
  const result = run(
    zapDocument({ target: httpOriginTarget({ asserted_revision: 'build-41' }) }),
    zapDocument({ target: httpOriginTarget({ asserted_revision: 'build-42' }) }),
  );
  assert.equal(result.authoritative, true);
  assert.deepEqual(result.non_authoritative_reasons, []);
  assert.deepEqual(result.base.asserted_revision, { value: 'build-41', asserted: true });
  assert.deepEqual(result.head.asserted_revision, { value: 'build-42', asserted: true });
});

test('asserted revisions are not required and missing ones echo as null', () => {
  const result = run(zapDocument(), zapDocument({ target: httpOriginTarget({ asserted_revision: 'b' }) }));
  assert.equal(result.authoritative, true);
  assert.equal(result.base.asserted_revision, null);
  assert.deepEqual(result.head.asserted_revision, { value: 'b', asserted: true });
});

test('an offline (unverified) ZAP document is never authoritative', () => {
  const offline = zapDocument({
    completeness: 'unverified',
    authoritative: false,
    non_authoritative_reasons: ['offline_report'],
  });
  const result = run(offline, zapDocument());
  assert.equal(result.authoritative, false);
  assert.ok(result.non_authoritative_reasons.includes('base_input_non_authoritative'));
  assert.deepEqual(result.base.non_authoritative_reasons, ['offline_report']);
});

// ---- Output contract -------------------------------------------------------

test('every output validates against the T02 CompareResult schema', () => {
  const scenarios: Array<[NormalizedDocument, NormalizedDocument, boolean]> = [
    [document(), document(), false],
    [document({ findings: [finding(1)] }), document({ findings: [finding(2)] }), false],
    [document({ fingerprint_version: 'v1', findings: [finding(1)] }), document({ fingerprint_version: 'v2', findings: [finding(1)] }), false],
    [document({ completeness: 'partial', authoritative: false, findings: [finding(1)] }), document({ findings: [] }), true],
    [zapDocument({ target: httpOriginTarget({ asserted_revision: 'r' }) }), zapDocument(), false],
  ];
  for (const [base, head, allowPartial] of scenarios) {
    const result = run(base, head, allowPartial);
    assert.doesNotThrow(() => CompareResultSchema.parse(result));
  }
});

test('the same inputs give identical output, regardless of input finding order', () => {
  const baseFindings = [finding(3), finding(1, { confidence: { text: 'Low', truncated: false, original_length: 3 } })];
  const headFindings = [finding(1, { confidence: { text: 'High', truncated: false, original_length: 4 } }), finding(2)];

  const first = run(document({ findings: baseFindings }), document({ findings: headFindings }));
  const second = run(document({ findings: baseFindings }), document({ findings: headFindings }));
  const reversed = run(document({ findings: [...baseFindings].reverse() }), document({ findings: [...headFindings].reverse() }));

  assert.deepEqual(first, second);
  assert.deepEqual(first, reversed);
});
