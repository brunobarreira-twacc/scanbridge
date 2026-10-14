import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import type { JsonValue } from '../../../../src/contracts/enums.js';
import { parse, sourceRefs } from '../../../../src/adapters/semgrep/parse.js';
import { bytes } from './fake-deps.js';

const emptyDoc = { results: [], errors: [], paths: { scanned: ['a.py'] } };

test('parse rejects bytes that are not UTF-8 JSON as invalid_json', () => {
  assert.deepEqual(parse(bytes('{not json')), { ok: false, reason: 'invalid_json' });
  assert.deepEqual(parse(new Uint8Array([0xff, 0xfe, 0x7b])), { ok: false, reason: 'invalid_json' });
});

test('parse rejects other JSON shapes as unsupported_shape', () => {
  const shapes: unknown[] = [
    [],
    null,
    { errors: [], paths: { scanned: [] } },
    { results: {}, errors: [], paths: { scanned: [] } },
    { results: [], errors: 'none', paths: { scanned: [] } },
    { results: [], errors: [], paths: [] },
    { results: [], errors: [], paths: { scanned: 'a.py' } },
  ];
  for (const shape of shapes) {
    assert.deepEqual(parse(bytes(JSON.stringify(shape))), { ok: false, reason: 'unsupported_shape' }, JSON.stringify(shape));
  }
});

test('parse accepts a document whose paths.scanned is absent', () => {
  const result = parse(bytes(JSON.stringify({ results: [], errors: [], paths: {} })));
  assert.equal(result.ok, true);
});

test('parse returns the decoded document', () => {
  assert.deepEqual(parse(bytes(JSON.stringify(emptyDoc))), { ok: true, doc: emptyDoc });
});

test('sourceRefs returns one ref per usable result with a <path>:<start>:<end> key', () => {
  const doc = {
    results: [
      { check_id: 'r', path: 'src/a.py', start: { line: 3, col: 1, offset: -1 }, end: { line: 5, col: 2, offset: -1 } },
      { check_id: 'r', path: './src/b.py', start: { line: 9, col: 1 }, end: { line: 9, col: 4 } },
      { path: 'src/c.py', start: { line: 1, col: 1 }, end: { line: 1, col: 2 } },
      'not an entry',
    ],
    errors: [],
    paths: { scanned: [] },
  } as unknown as JsonValue;
  assert.deepEqual(sourceRefs(doc), [
    { key: 'src/a.py:3:5', path: 'src/a.py', startLine: 3, endLine: 5 },
    { key: 'src/b.py:9:9', path: 'src/b.py', startLine: 9, endLine: 9 },
  ]);
});

test('sourceRefs returns no refs for an unsupported document', () => {
  assert.deepEqual(sourceRefs([] as unknown as JsonValue), []);
});

test('parse, sourceRefs and normalize sources stay free of filesystem, process, clock and network access', () => {
  const srcDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..', 'src', 'adapters', 'semgrep');
  const pure = ['document.ts', 'errors.ts', 'severity.ts', 'parse.ts', 'normalize.ts'];
  const forbidden = [/from\s+['"](?:node:)?(?:fs|child_process|http|https|net)(?:\/promises)?['"]/, /process\./, /Date\b/, /\bfetch\s*\(/];
  for (const file of pure) {
    const text = readFileSync(join(srcDir, file), 'utf8');
    for (const re of forbidden) assert.equal(re.test(text), false, `${file} matches ${re.source}`);
  }
});
