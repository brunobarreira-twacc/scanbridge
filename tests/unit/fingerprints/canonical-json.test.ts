import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalJson } from '../../../src/core/fingerprints/canonical-json.js';
import { sha256Hex } from '../../../src/core/fingerprints/hash.js';

test('RFC 8785 string escaping', () => {
  assert.equal(canonicalJson('plain'), '"plain"');
  assert.equal(canonicalJson('"quote" and \\ backslash'), '"\\"quote\\" and \\\\ backslash"');
  assert.equal(canonicalJson('\b\f\n\r\t'), '"\\b\\f\\n\\r\\t"');
  assert.equal(canonicalJson('\u0001\u001f'), '"\\u0001\\u001f"');
  assert.equal(canonicalJson('\u007f\u0080'), '"\u007f\u0080"');
  assert.equal(canonicalJson('é'), '"é"');
});

test('RFC 8785 member sorting uses UTF-16 code units', () => {
  // Vector from RFC 8785 section 3.2.3, with the members in sorted order.
  const input = {
    '€': 'Euro Sign',
    '\r': 'Carriage Return',
    'דּ': 'Hebrew Letter Dalet With Dagesh',
    '1': 'One',
    '😀': 'Emoji: Grinning Face',
    '\u0080': 'Control',
    'ö': 'Latin Small Letter O With Diaeresis',
  };
  assert.equal(
    canonicalJson(input),
    '{"\\r":"Carriage Return","1":"One","\u0080":"Control",' +
      '"ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign",' +
      '"😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
  );
});

test('object keys are sorted at every depth and the input order is ignored', () => {
  assert.equal(canonicalJson({ b: 1, a: { d: [], c: null } }), '{"a":{"c":null,"d":[]},"b":1}');
  assert.equal(canonicalJson({ a: 1, b: 2 }), canonicalJson({ b: 2, a: 1 }));
});

test('integers serialize without fraction or exponent', () => {
  assert.equal(canonicalJson(0), '0');
  assert.equal(canonicalJson(-0), '0');
  assert.equal(canonicalJson(42), '42');
  assert.equal(canonicalJson(-7), '-7');
  assert.equal(canonicalJson(9007199254740991), '9007199254740991');
});

test('booleans, null and arrays keep their order', () => {
  assert.equal(canonicalJson([true, false, null, ['x', 2]]), '[true,false,null,["x",2]]');
  assert.equal(canonicalJson([]), '[]');
  assert.equal(canonicalJson({}), '{}');
});

test('floats and non-finite numbers are rejected', () => {
  for (const value of [1.5, 0.1, Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
    assert.throws(() => canonicalJson(value), TypeError, String(value));
  }
  assert.throws(() => canonicalJson(['ok', { x: 2.5 }]), TypeError);
});

test('unsupported values are rejected', () => {
  assert.throws(() => canonicalJson(undefined as never), TypeError);
  assert.throws(() => canonicalJson(Symbol('s') as never), TypeError);
});

test('sha256Hex matches the FIPS 180 vector for "abc", for strings and bytes', () => {
  const expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
  assert.equal(sha256Hex('abc'), expected);
  assert.equal(sha256Hex(new TextEncoder().encode('abc')), expected);
});
