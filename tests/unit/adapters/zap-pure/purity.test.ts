import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { normalize } from '../../../../src/adapters/zap/normalize.js';
import { parse, sourceRefs } from '../../../../src/adapters/zap/parse.js';
import { LIVE_CONTEXT, NO_SOURCES } from './helpers.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', '..');
const PURE_FILES = ['parse.ts', 'normalize.ts', 'severity.ts'];
const FORBIDDEN = /from ['"](node:)?(fs|fs\/promises|net|http|https|dns|tls|child_process|dgram)['"]|\bfetch\s*\(/;

test('ZAP parse, normalize and severity sources import no filesystem or network module and call no fetch', () => {
  for (const file of PURE_FILES) {
    const source = readFileSync(join(ROOT, 'src', 'adapters', 'zap', file), 'utf8');
    assert.doesNotMatch(source, FORBIDDEN, file);
  }
});

test('parse, normalize and sourceRefs run with fetch unavailable', () => {
  const globals = globalThis as { fetch?: unknown };
  const original = globals.fetch;
  let calls = 0;
  globals.fetch = () => {
    calls++;
    throw new Error('network access attempted');
  };
  try {
    const result = parse(new TextEncoder().encode('{"alerts":[{"pluginId":"10038","url":"http://127.0.0.1:8080/","risk":"Low"}]}'));
    assert.ok(result.ok);
    assert.equal(normalize(result.doc, LIVE_CONTEXT, NO_SOURCES).candidates.length, 1);
    assert.deepEqual(sourceRefs(result.doc), []);
  } finally {
    globals.fetch = original;
  }
  assert.equal(calls, 0);
});
