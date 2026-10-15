import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parse, sourceRefs } from '../../../../src/adapters/zap/parse.js';

const bytes = (text: string): Uint8Array => new TextEncoder().encode(text);

test('invalid JSON is rejected as invalid_json', () => {
  assert.deepEqual(parse(bytes('{"alerts":[')), { ok: false, reason: 'invalid_json' });
});

test('bytes that are not valid UTF-8 are rejected as invalid_json', () => {
  assert.deepEqual(parse(new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x7d])), { ok: false, reason: 'invalid_json' });
});

for (const [label, text] of [
  ['an array', '[]'],
  ['a scalar', '"alerts"'],
  ['null', 'null'],
  ['an empty object', '{}'],
  ['alerts that is not an array', '{"alerts":{}}'],
  ['an extra top-level key', '{"alerts":[],"site":[]}'],
  ['a Traditional JSON report', '{"@programName":"ZAP","site":[{"alerts":[]}]}'],
] as const) {
  test(`${label} is rejected as unsupported_shape`, () => {
    assert.deepEqual(parse(bytes(text)), { ok: false, reason: 'unsupported_shape' });
  });
}

test('exactly {"alerts":[...]} is accepted, with entries left for normalize to judge', () => {
  const result = parse(bytes('{"alerts":[{"pluginId":"10202"},"not checked here"]}'));
  assert.ok(result.ok);
  assert.deepEqual(result.doc, { alerts: [{ pluginId: '10202' }, 'not checked here'] });
});

test('sourceRefs is always empty, whatever the document', () => {
  assert.deepEqual(sourceRefs({ alerts: [{ pluginId: '10202', url: 'http://127.0.0.1:8080/' }] }), []);
  assert.deepEqual(sourceRefs({}), []);
});
