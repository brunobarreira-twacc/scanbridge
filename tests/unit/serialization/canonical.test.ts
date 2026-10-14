import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { serializeCanonical } from '../../../src/core/serialization/index.js';

const hex = (c: string) => c.repeat(64);
const text = (t: string) => ({ text: t, truncated: false, original_length: [...t].length });
const fingerprint = (c: string) => `v1:${hex(c)}`;

const sourceOccurrence = (line: number, path = 'src/a.ts') => ({
  severity: 'high',
  severity_original: 'ERROR',
  source_location: { path, start_line: line, start_col: 1, end_line: line, end_col: 9 },
  evidence: { snippet: text(`line ${line}`) },
});

const runtimeOccurrence = (attack: string) => ({
  severity: 'medium',
  severity_original: 'Medium',
  runtime_location: { url: 'https://example.test/a', method: 'GET', param: 'q' },
  evidence: { attack: text(attack), evidence: text('e'), message_id: '7' },
});

const finding = (c: string, occurrences: unknown[]) => ({
  fingerprint: fingerprint(c),
  fingerprint_quality: 'exact',
  rule_id: `rule.${c}`,
  producer_reference: null,
  title: text(`Title ${c}`),
  severity: 'high',
  severity_original: 'ERROR',
  severity_complete: true,
  confidence: null,
  references: ['https://b.example', 'https://a.example', 'https://a.example'],
  status: 'open',
  occurrence_count: occurrences.length,
  occurrences,
});

const document = (findings: unknown[], summary: Record<string, number>) => ({
  schema_version: '1',
  content_trust: 'untrusted_producer_content',
  producer: 'semgrep',
  producer_version: '1.2.3',
  target: { kind: 'git', relative_path: '.', revision: 'abc', dirty: false, content_digest: hex('d') },
  completeness: 'complete',
  authoritative: true,
  non_authoritative_reasons: ['registry_rules', 'auto_rules', 'registry_rules'],
  fingerprint_version: 'v1',
  severity_mapping_version: 'semgrep-1',
  redaction_policy_version: 'zap-1+0123456789ab',
  rules_digest: null,
  configuration_digest: hex('c'),
  raw_sha256_before_redaction: hex('1'),
  raw_sha256_after_redaction: hex('2'),
  redaction_summary: summary,
  findings,
});

/** Same logical value with every object's keys reversed and every array reversed. */
function scramble(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(scramble).reverse();
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).reverse().map(([k, v]) => [k, scramble(v)]));
  }
  return value;
}

const sample = () =>
  document(
    [
      finding('b', [sourceOccurrence(9), sourceOccurrence(2)]),
      finding('a', [runtimeOccurrence('zeta'), runtimeOccurrence('alpha')]),
    ],
    { 'zz-rule': 1, 'aa-rule': 2 },
  );

describe('serializeCanonical', () => {
  it('gives identical bytes for different key and array input orders', () => {
    const a = serializeCanonical('NormalizedDocument', sample());
    const b = serializeCanonical('NormalizedDocument', scramble(sample()));
    assert.equal(a, b);
  });

  it('writes LF only with exactly one trailing newline', () => {
    const out = serializeCanonical('NormalizedDocument', sample());
    assert.equal(out.includes('\r'), false);
    assert.ok(out.endsWith('}\n'));
    assert.equal(out.endsWith('\n\n'), false);
  });

  it('uses 2-space indentation', () => {
    const out = serializeCanonical('TextField', text('x'));
    assert.equal(out, '{\n  "text": "x",\n  "truncated": false,\n  "original_length": 1\n}\n');
  });

  it('emits keys in declared order, not insertion order', () => {
    const out = serializeCanonical('NormalizedDocument', sample());
    const keys = [...out.matchAll(/^ {2}"([a-z_]+)":/gm)].map((m) => m[1]);
    assert.deepEqual(keys.slice(0, 4), ['schema_version', 'content_trust', 'producer', 'producer_version']);
    assert.equal(keys.at(-1), 'findings');
  });

  it('sorts findings by fingerprint and occurrences by canonical location', () => {
    const parsed = JSON.parse(serializeCanonical('NormalizedDocument', sample()));
    assert.deepEqual(
      parsed.findings.map((f: { fingerprint: string }) => f.fingerprint),
      [fingerprint('a'), fingerprint('b')],
    );
    const sourceFinding = parsed.findings[1];
    assert.deepEqual(
      sourceFinding.occurrences.map((o: { source_location: { start_line: number } }) => o.source_location.start_line),
      [2, 9],
    );
  });

  it('orders runtime occurrences by attack text, using the TextField text', () => {
    const parsed = JSON.parse(serializeCanonical('NormalizedDocument', sample()));
    const runtimeFinding = parsed.findings[0];
    assert.deepEqual(
      runtimeFinding.occurrences.map((o: { evidence: { attack: { text: string } } }) => o.evidence.attack.text),
      ['alpha', 'zeta'],
    );
  });

  it('sorts and deduplicates reason and reference lists by code point', () => {
    const parsed = JSON.parse(serializeCanonical('NormalizedDocument', sample()));
    assert.deepEqual(parsed.non_authoritative_reasons, ['auto_rules', 'registry_rules']);
    assert.deepEqual(parsed.findings[0].references, [
      'https://a.example',
      'https://b.example',
    ]);
  });

  it('sorts redaction counts by rule id', () => {
    const out = serializeCanonical('NormalizedDocument', sample());
    assert.ok(out.indexOf('"aa-rule"') < out.indexOf('"zz-rule"'));
  });

  it('keeps duplicate entries in a sorted multiset', () => {
    const out = serializeCanonical('FindingReference', {
      rule_id: 'r',
      producer_reference: null,
      title: text('t'),
      fingerprint_quality: 'exact',
      severity: 'high',
      severity_original: 'ERROR',
      severity_complete: true,
      confidence: null,
      occurrence_count: 3,
      occurrence_severities: ['WARNING', 'ERROR', 'WARNING'],
    });
    assert.deepEqual(JSON.parse(out).occurrence_severities, ['ERROR', 'WARNING', 'WARNING']);
  });

  it('keeps array order for arrays declared ordered', () => {
    const out = serializeCanonical('Artifacts', {
      directory: '/out/s',
      raw: ['raw/z.json', 'raw/a.json'],
      normalized: null,
    });
    assert.deepEqual(JSON.parse(out).raw, ['raw/z.json', 'raw/a.json']);
  });

  it('rejects fields that are not declared for the type', () => {
    assert.throws(
      () => serializeCanonical('TextField', { text: 'x', truncated: false, original_length: 1, extra: true }),
      /field "extra" is not declared/,
    );
  });

  it('rejects unknown object types', () => {
    assert.throws(() => serializeCanonical('NoSuchType', {}), /unknown object type/);
    assert.throws(() => serializeCanonical('constructor', {}), /unknown object type/);
  });

  it('rejects non-integer numbers', () => {
    assert.throws(
      () => serializeCanonical('TextField', { text: 'x', truncated: false, original_length: 1.5 }),
      /safe integer/,
    );
  });

  it('rejects negative redaction counts', () => {
    assert.throws(() => serializeCanonical('NormalizedDocument', { ...sample(), redaction_summary: { r: -1 } }), /non-negative/);
  });

  it('writes null for nullable fields and omits absent optional ones', () => {
    const parsed = JSON.parse(serializeCanonical('GitTarget', {
      kind: 'git',
      relative_path: '.',
      revision: null,
      dirty: null,
      content_digest: null,
    }));
    assert.deepEqual(parsed, { kind: 'git', relative_path: '.', revision: null, dirty: null, content_digest: null });
  });
});
