import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { serializeRaw, sha256Utf8 } from '../../../src/core/serialization/index.js';

describe('serializeRaw', () => {
  it('keeps parsed key and array order exactly', () => {
    const parsed = JSON.parse('{"zeta":[3,1,2],"alpha":{"second":true,"first":null}}');
    assert.equal(
      serializeRaw(parsed),
      '{\n  "zeta": [\n    3,\n    1,\n    2\n  ],\n  "alpha": {\n    "second": true,\n    "first": null\n  }\n}\n',
    );
  });

  it('writes LF with exactly one trailing newline', () => {
    const out = serializeRaw({ a: 'x' });
    assert.equal(out.includes('\r'), false);
    assert.ok(out.endsWith('}\n'));
    assert.equal(out.endsWith('\n\n'), false);
  });

  it('keeps non-ASCII text as UTF-8 characters', () => {
    assert.equal(serializeRaw({ s: 'é' }), '{\n  "s": "é"\n}\n');
  });

  it('rejects values that are not JSON', () => {
    assert.throws(() => serializeRaw({ a: undefined }), /not a JSON value/);
    assert.throws(() => serializeRaw([1, undefined]), /not a JSON value/);
    assert.throws(() => serializeRaw({ n: Number.NaN }), /non-finite/);
    assert.throws(() => serializeRaw(1n), /not a JSON value/);
  });

  it('rejects sparse arrays instead of writing null', () => {
    const sparse: unknown[] = [];
    sparse[1] = 'x';
    assert.throws(() => serializeRaw(sparse), /not a JSON value/);
  });
});

describe('sha256Utf8', () => {
  it('hashes the exact UTF-8 bytes', () => {
    // SHA-256 of "abc" (FIPS 180-2 test vector).
    assert.equal(sha256Utf8('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('differs for any byte change, including the trailing newline', () => {
    assert.notEqual(sha256Utf8(serializeRaw({ a: 1 })), sha256Utf8(serializeRaw({ a: 1 }).trimEnd()));
  });
});
