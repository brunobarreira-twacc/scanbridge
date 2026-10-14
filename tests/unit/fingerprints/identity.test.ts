import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  METHOD_MAX,
  PARAM_MAX,
  PATH_MAX,
  PRODUCER_REFERENCE_MAX,
  RULE_ID_MAX,
  URL_MAX,
} from '../../../src/contracts/limits.js';
import { sha256Hex } from '../../../src/core/fingerprints/hash.js';
import { guardIdentity, hasProhibitedControl, type IdentityKind } from '../../../src/core/fingerprints/identity.js';

const LIMITS: [IdentityKind, number][] = [
  ['rule_id', RULE_ID_MAX],
  ['producer_reference', PRODUCER_REFERENCE_MAX],
  ['path', PATH_MAX],
  ['url', URL_MAX],
  ['method', METHOD_MAX],
  ['param', PARAM_MAX],
];

// Code points, not UTF-16 units: each emoji is one code point and two units.
const repeat = (ch: string, n: number) => ch.repeat(n);

test('hasProhibitedControl flags C0 controls and DEL only', () => {
  assert.equal(hasProhibitedControl('plain text ~ é 😀'), false);
  assert.equal(hasProhibitedControl(' '), false);
  assert.equal(hasProhibitedControl('\u0000'), true);
  assert.equal(hasProhibitedControl('\t'), true);
  assert.equal(hasProhibitedControl('\n'), true);
  assert.equal(hasProhibitedControl('\u001f'), true);
  assert.equal(hasProhibitedControl('\u007f'), true);
  assert.equal(hasProhibitedControl('\u0080'), false);
});

for (const [kind, limit] of LIMITS) {
  test(`${kind}: one below, exactly at and one above the limit`, () => {
    // Uppercase letters are unchanged by the method uppercasing step.
    const below = repeat('A', limit - 1);
    const at = repeat('A', limit);
    const above = repeat('A', limit + 1);
    assert.deepEqual(guardIdentity(below, kind), { value: below, degraded: false });
    assert.deepEqual(guardIdentity(at, kind), { value: at, degraded: false });
    const guarded = guardIdentity(above, kind);
    assert.equal(guarded.degraded, true);
    assert.equal(guarded.reason, 'oversized');
    assert.equal(guarded.value, `[oversized:${sha256Hex(above)}]`);
  });

  test(`${kind}: limit counts code points, not UTF-16 units`, () => {
    const atEmoji = repeat('😀', limit);
    assert.deepEqual(guardIdentity(atEmoji, kind), { value: atEmoji, degraded: false });
    const aboveEmoji = repeat('😀', limit + 1);
    assert.equal(guardIdentity(aboveEmoji, kind).reason, 'oversized');
  });

  test(`${kind}: a control character yields an invalid placeholder`, () => {
    for (const control of ['\u0000', '\u0009', '\u001b', '\u007f']) {
      const original = `ab${control}cd`;
      const guarded = guardIdentity(original, kind);
      // The placeholder hashes the value after the method uppercasing step.
      const hashed = kind === 'method' ? original.toUpperCase() : original;
      assert.deepEqual(guarded, {
        value: `[invalid:${sha256Hex(hashed)}]`,
        degraded: true,
        reason: 'invalid',
      });
    }
  });

  test(`${kind}: control characters win over size`, () => {
    const original = `x\u0001${repeat('a', limit + 10)}`;
    assert.equal(guardIdentity(original, kind).reason, 'invalid');
  });

  test(`${kind}: two different over-limit values give different placeholders`, () => {
    const first = guardIdentity(repeat('a', limit + 1), kind).value;
    const second = guardIdentity(repeat('b', limit + 1), kind).value;
    assert.notEqual(first, second);
  });

  test(`${kind}: identical over-limit values give identical placeholders`, () => {
    const first = guardIdentity(repeat('q', limit + 5), kind).value;
    const second = guardIdentity(repeat('q', limit + 5), kind).value;
    assert.equal(first, second);
  });
}

test('placeholders use the lowercase hex SHA-256 of the original', () => {
  assert.match(guardIdentity('a'.repeat(2000), 'path').value, /^\[oversized:[0-9a-f]{64}\]$/);
  assert.match(guardIdentity('\u0000', 'param').value, /^\[invalid:[0-9a-f]{64}\]$/);
});

test('method is uppercased before the checks', () => {
  assert.deepEqual(guardIdentity('get', 'method'), { value: 'GET', degraded: false });
  assert.deepEqual(guardIdentity('pOsT', 'method'), { value: 'POST', degraded: false });
});

test('method control characters are checked after uppercasing', () => {
  const guarded = guardIdentity('ge\u0000t', 'method');
  assert.equal(guarded.reason, 'invalid');
  assert.equal(guarded.value, `[invalid:${sha256Hex('GE\u0000T')}]`);
});

test('values are never truncated or repaired', () => {
  const value = 'Ünïcödé path with spaces/and%20escapes';
  assert.deepEqual(guardIdentity(value, 'path'), { value, degraded: false });
});
