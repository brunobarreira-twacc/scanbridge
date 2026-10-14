import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { NormalizeContext } from '../../../../src/contracts/adapter.js';
import type { JsonValue } from '../../../../src/contracts/enums.js';
import type { SourceText } from '../../../../src/contracts/ports.js';
import { normalize } from '../../../../src/adapters/semgrep/normalize.js';

function context(over: Partial<NormalizeContext> = {}): NormalizeContext {
  return {
    mode: 'live',
    targetRel: 'src',
    targetOrigin: null,
    producerVersion: null,
    redactionTouched: new Set(),
    coverageLoss: [],
    scanDiagnostics: [],
    scanReasons: [],
    ...over,
  };
}

function json(value: unknown): JsonValue {
  return JSON.parse(JSON.stringify(value)) as JsonValue;
}

function result(extra: Record<string, unknown> = {}, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    check_id: 'rules.sql',
    path: 'src/a.py',
    start: { line: 3, col: 1, offset: -1 },
    end: { line: 3, col: 9, offset: -1 },
    extra: { severity: 'ERROR', message: 'bad query', ...extra },
    ...over,
  };
}

function doc(results: unknown[], over: Record<string, unknown> = {}): JsonValue {
  return json({ results, errors: [], paths: { scanned: ['src/a.py'] }, ...over });
}

const NO_SOURCES: ReadonlyMap<string, SourceText> = new Map();

test('maps each semgrep-1 severity exactly and case-sensitively', () => {
  const table: [string, string][] = [
    ['CRITICAL', 'critical'],
    ['HIGH', 'high'],
    ['ERROR', 'high'],
    ['MEDIUM', 'medium'],
    ['WARNING', 'medium'],
    ['LOW', 'low'],
    ['INFO', 'info'],
    ['EXPERIMENT', 'info'],
    ['INVENTORY', 'info'],
    ['error', 'unknown'],
    ['constructor', 'unknown'],
  ];
  for (const [original, expected] of table) {
    const out = normalize(doc([result({ severity: original })]), context(), NO_SOURCES);
    assert.equal(out.candidates[0]?.severity, expected, original);
    assert.equal(out.candidates[0]?.severityOriginal, original);
    assert.equal(out.severityMappingVersion, 'semgrep-1');
  }
});

test('an unmapped severity gives unknown and one unmapped_severity diagnostic', () => {
  const out = normalize(doc([result({ severity: 'BLOCKER' }), result({ severity: 'INFO' })]), context(), NO_SOURCES);
  assert.deepEqual(out.diagnostics.map((d) => d.code), ['unmapped_severity']);
  assert.equal(out.candidates[0]?.severity, 'unknown');
  assert.equal(out.completeness, 'complete');
});

test('maps identity, text and location fields from a result', () => {
  const out = normalize(
    doc([
      result({ fingerprint: 'fp-1', message: 'msg', lines: 'db.query(x)', metavars: { $X: 'secret' } }, {
        start: { line: 4, col: 2, offset: 40 },
        end: { line: 4, col: 20, offset: 58 },
      }),
    ]),
    context(),
    NO_SOURCES,
  );
  const [candidate] = out.candidates;
  assert.ok(candidate);
  assert.equal(candidate.producer, 'semgrep');
  assert.equal(candidate.ruleId, 'rules.sql');
  assert.equal(candidate.title, 'rules.sql');
  assert.equal(candidate.producerReference, null);
  assert.equal(candidate.producerFingerprint, 'fp-1');
  assert.equal(candidate.description, 'msg');
  assert.deepEqual(candidate.location, {
    source: { path: 'src/a.py', startLine: 4, startCol: 2, endLine: 4, endCol: 20 },
  });
  assert.deepEqual(candidate.evidence, { producer_lines: 'db.query(x)' });
  assert.equal(JSON.stringify(candidate).includes('metavars'), false);
});

test('strips a leading ./ from the path and keeps the root-relative form', () => {
  const out = normalize(doc([result({}, { path: './src/a.py' })]), context(), NO_SOURCES);
  assert.equal(out.candidates[0]?.location.source?.path, 'src/a.py');
});

test('metadata is read only when it has the expected types', () => {
  const withMeta = normalize(
    doc([result({ metadata: { confidence: 'HIGH', category: 'security', references: ['https://a', 'https://b'] } })]),
    context(),
    NO_SOURCES,
  );
  assert.equal(withMeta.candidates[0]?.confidence, 'HIGH');
  assert.equal(withMeta.candidates[0]?.category, 'security');
  assert.deepEqual(withMeta.candidates[0]?.references, ['https://a', 'https://b']);

  const badMeta = normalize(
    doc([result({ metadata: { confidence: 3, category: ['x'], references: ['https://a', 4] } })]),
    context(),
    NO_SOURCES,
  );
  assert.equal(badMeta.candidates[0]?.confidence, null);
  assert.equal(badMeta.candidates[0]?.category, null);
  assert.deepEqual(badMeta.candidates[0]?.references, []);
});

test('non-string message and fingerprint become null', () => {
  const out = normalize(doc([result({ message: 7, fingerprint: { a: 1 } })]), context(), NO_SOURCES);
  assert.equal(out.candidates[0]?.description, null);
  assert.equal(out.candidates[0]?.producerFingerprint, null);
});

test('snippets come from the sources map; a missing source leaves the snippet absent', () => {
  const sources = new Map<string, SourceText>([
    ['src/a.py:3:3', { ok: true, text: 'db.query(x)', redacted: false }],
    ['src/b.py:1:1', { ok: false, reason: 'too_large' }],
  ]);
  const out = normalize(
    doc([result(), result({}, { path: 'src/b.py', start: { line: 1, col: 1 }, end: { line: 1, col: 1 } }), result({}, { path: 'src/c.py' })]),
    context(),
    sources,
  );
  assert.deepEqual(out.candidates[0]?.snippet, { ok: true, text: 'db.query(x)' });
  assert.deepEqual(out.candidates[1]?.snippet, { ok: false, reason: 'too_large' });
  assert.equal('snippet' in (out.candidates[2] ?? {}), false);
});

test('redactionsApplied follows the pointer prefix for that index and a redacted source', () => {
  const sources = new Map<string, SourceText>([['src/a.py:3:3', { ok: true, text: 'x', redacted: true }]]);
  const touched = new Set(['/results/1/extra/lines', '/results/10/extra/message']);
  const out = normalize(doc([result({}, { path: 'src/z.py' }), result({}, { path: 'src/y.py' }), result()]), context({ redactionTouched: touched }), sources);
  assert.equal(out.candidates[0]?.redactionsApplied, false);
  assert.equal(out.candidates[1]?.redactionsApplied, true);
  assert.equal(out.candidates[2]?.redactionsApplied, true);
});

test('version is the document version, else the context version, else null', () => {
  assert.equal(normalize(doc([], { version: '1.2.3' }), context({ producerVersion: '9.9.9' }), NO_SOURCES).producerVersion, '1.2.3');
  assert.equal(normalize(doc([]), context({ producerVersion: '9.9.9' }), NO_SOURCES).producerVersion, '9.9.9');
  assert.equal(normalize(doc([]), context(), NO_SOURCES).producerVersion, null);
});

test('unusable entries are counted, dropped and make the scan partial while usable entries remain', () => {
  const out = normalize(
    doc([
      result(),
      { path: 'src/a.py', start: { line: 1, col: 1 }, end: { line: 1, col: 1 } },
      result({}, { check_id: 3 }),
      result({}, { start: { line: 1.5, col: 1 } }),
      'junk',
    ]),
    context(),
    NO_SOURCES,
  );
  assert.equal(out.candidates.length, 1);
  assert.equal(out.unusableCount, 4);
  assert.deepEqual(out.diagnostics.map((d) => d.code), ['malformed_report']);
  assert.equal(out.completeness, 'partial');
});

test('no usable entries with unusable entries present gives failed', () => {
  const out = normalize(doc([{ path: 'src/a.py' }, 'junk']), context(), NO_SOURCES);
  assert.equal(out.candidates.length, 0);
  assert.equal(out.unusableCount, 2);
  assert.equal(out.completeness, 'failed');
});

test('a missing paths.scanned is treated as no files scanned', () => {
  const out = normalize(json({ results: [], errors: [], paths: {} }), context(), NO_SOURCES);
  assert.equal(out.completeness, 'partial');
  assert.deepEqual(out.diagnostics.map((d) => d.code), ['no_files_scanned']);
});

test('an empty scan with files scanned and no errors is complete', () => {
  const out = normalize(doc([]), context(), NO_SOURCES);
  assert.equal(out.completeness, 'complete');
  assert.deepEqual(out.coverageLoss, []);
  assert.deepEqual(out.reasons, []);
});

test('an unsupported document gives failed without candidates', () => {
  const out = normalize(json([]), context({ producerVersion: '1.0.0' }), NO_SOURCES);
  assert.equal(out.completeness, 'failed');
  assert.equal(out.candidates.length, 0);
  assert.equal(out.producerVersion, '1.0.0');
});
