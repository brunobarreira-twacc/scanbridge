import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { normalize } from '../../../../src/adapters/sonarqube/normalize.js';
import { parse, sourceRefs } from '../../../../src/adapters/sonarqube/parse.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..');
const PURE_FILES = ['parse.ts', 'normalize.ts', 'severity.ts', 'document.ts'];
const FORBIDDEN = /from ['"](node:)?(fs|fs\/promises|net|http|https|dns|tls|child_process|dgram)['"]|\bfetch\s*\(/;

const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);

test('invalid JSON is rejected as invalid_json', () => {
  assert.deepEqual(parse(bytes('{"issues":[')), { ok: false, reason: 'invalid_json' });
});

test('bytes that are not valid UTF-8 are rejected as invalid_json', () => {
  assert.deepEqual(parse(new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x7d])), { ok: false, reason: 'invalid_json' });
});

for (const [label, text] of [
  ['an array', '[]'],
  ['a scalar', '"issues"'],
  ['null', 'null'],
  ['an empty object', '{}'],
  ['issues that is not an array', '{"issues":{},"total":0,"projectKey":"p"}'],
  ['missing total', '{"issues":[],"projectKey":"p"}'],
  ['missing projectKey', '{"issues":[],"total":0}'],
] as const) {
  test(`${label} is rejected as unsupported_shape`, () => {
    assert.deepEqual(parse(bytes(text)), { ok: false, reason: 'unsupported_shape' });
  });
}

test('valid shape is accepted, entries left for normalize to judge', () => {
  const result = parse(bytes('{"issues":[{"key":"X"},null],"total":2,"projectKey":"p"}'));
  assert.ok(result.ok);
  assert.equal((result.doc as { projectKey: string }).projectKey, 'p');
});

test('sourceRefs is always empty, whatever the document', () => {
  assert.deepEqual(sourceRefs({ issues: [], total: 0, projectKey: 'p' }), []);
  assert.deepEqual(sourceRefs({}), []);
  assert.deepEqual(sourceRefs(null), []);
});

test('SonarQube parse, normalize, severity, and document sources import no filesystem or network module', () => {
  for (const file of PURE_FILES) {
    const source = readFileSync(join(ROOT, 'src', 'adapters', 'sonarqube', file), 'utf8');
    assert.doesNotMatch(source, FORBIDDEN, file);
  }
});

test('parse and normalize run with fetch unavailable', () => {
  const globals = globalThis as { fetch?: unknown };
  const original = globals.fetch;
  let calls = 0;
  globals.fetch = () => {
    calls++;
    throw new Error('network access attempted');
  };
  try {
    const raw = bytes('{"issues":[{"key":"K1","rule":"java:S2259","component":"p:src/A.java","type":"BUG","message":"NPE","impacts":[{"softwareQuality":"RELIABILITY","severity":"HIGH"}]}],"total":1,"projectKey":"p"}');
    const result = parse(raw);
    assert.ok(result.ok);
    const ctx = {
      mode: 'live' as const,
      targetRel: '',
      targetOrigin: null,
      producerVersion: null,
      redactionTouched: new Set<string>(),
      coverageLoss: [],
      scanDiagnostics: [],
      scanReasons: [],
    };
    const out = normalize(result.doc, ctx, new Map());
    assert.equal(out.candidates.length, 1);
    assert.deepEqual(sourceRefs(result.doc), []);
  } finally {
    globals.fetch = original;
  }
  assert.equal(calls, 0);
});
