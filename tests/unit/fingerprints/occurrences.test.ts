import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  compareCodePoints,
  compareOccurrences,
  type OccurrenceOrderInput,
} from '../../../src/core/fingerprints/occurrences.js';

const src = (path: string, sl: number, sc: number, el: number, ec: number): OccurrenceOrderInput => ({
  source_location: { path, start_line: sl, start_col: sc, end_line: el, end_col: ec },
});

const run = (
  url: string,
  method: string,
  param: string,
  evidence: OccurrenceOrderInput['evidence'] = null,
): OccurrenceOrderInput => ({ runtime_location: { url, method, param }, evidence });

const zapEvidence = (attack: string | null, text: string | null, messageId: string | null) => ({
  attack,
  evidence: text === null ? null : { text },
  message_id: messageId,
});

/** Checks reflexivity, antisymmetry and transitivity over all triples. */
function assertTotalPreorder(items: OccurrenceOrderInput[]): void {
  const sign = (n: number) => Math.sign(n);
  for (const a of items) {
    assert.equal(compareOccurrences(a, a), 0);
    for (const b of items) {
      // Sum, not negation: -0 and 0 are not equal under assert.equal.
      assert.equal(sign(compareOccurrences(a, b)) + sign(compareOccurrences(b, a)), 0);
      for (const c of items) {
        if (compareOccurrences(a, b) <= 0 && compareOccurrences(b, c) <= 0) {
          assert.ok(compareOccurrences(a, c) <= 0, 'transitivity');
        }
      }
    }
  }
}

test('source-location occurrences order by path, then line and column', () => {
  const items = [
    src('b.ts', 1, 1, 1, 2),
    src('a.ts', 10, 1, 10, 2),
    src('a.ts', 2, 5, 2, 9),
    src('a.ts', 2, 5, 2, 8),
    src('a.ts', 2, 4, 3, 1),
    src('a.ts', 2, 4, 2, 9),
  ];
  const sorted = [...items].sort(compareOccurrences);
  assert.deepEqual(
    sorted.map((o) => {
      const s = o.source_location!;
      return [s.path, s.start_line, s.start_col, s.end_line, s.end_col];
    }),
    [
      ['a.ts', 2, 4, 2, 9],
      ['a.ts', 2, 4, 3, 1],
      ['a.ts', 2, 5, 2, 8],
      ['a.ts', 2, 5, 2, 9],
      ['a.ts', 10, 1, 10, 2],
      ['b.ts', 1, 1, 1, 2],
    ],
  );
  assertTotalPreorder(items);
});

test('runtime occurrences order by url, method, param, then null-first evidence fields', () => {
  const items = [
    run('http://h/b', 'GET', '', zapEvidence(null, 'x', '1')),
    run('http://h/a', 'POST', 'q', zapEvidence(null, 'x', '1')),
    run('http://h/a', 'GET', 'z', zapEvidence(null, 'x', '1')),
    run('http://h/a', 'GET', 'a', zapEvidence(null, 'x', '1')),
    run('http://h/a', 'GET', 'a', zapEvidence('atk', 'x', '1')),
    run('http://h/a', 'GET', 'a', zapEvidence(null, 'y', '1')),
    run('http://h/a', 'GET', 'a', zapEvidence(null, 'y', null)),
    run('http://h/a', 'GET', 'a', zapEvidence(null, 'y', '2')),
    run('http://h/a', 'GET', 'a', null),
  ];
  const sorted = [...items].sort(compareOccurrences);
  assert.deepEqual(
    sorted.map((o) => o.runtime_location?.url + ' ' + o.runtime_location?.method + ' ' + o.runtime_location?.param),
    [
      'http://h/a GET a',
      'http://h/a GET a',
      'http://h/a GET a',
      'http://h/a GET a',
      'http://h/a GET a',
      'http://h/a GET a',
      'http://h/a GET z',
      'http://h/a POST q',
      'http://h/b GET ',
    ],
  );
  // Within the (GET, a) group: no evidence, then attack null by text and message_id, then attack "atk".
  assert.deepEqual(
    sorted.slice(0, 6).map((o) => JSON.stringify(o.evidence ?? null)),
    [
      'null',
      JSON.stringify(zapEvidence(null, 'x', '1')),
      JSON.stringify(zapEvidence(null, 'y', null)),
      JSON.stringify(zapEvidence(null, 'y', '1')),
      JSON.stringify(zapEvidence(null, 'y', '2')),
      JSON.stringify(zapEvidence('atk', 'x', '1')),
    ],
  );
  assertTotalPreorder(items);
});

test('null attack and null evidence come before any string', () => {
  const withNull = run('http://h/a', 'GET', '', zapEvidence(null, null, null));
  const withString = run('http://h/a', 'GET', '', zapEvidence('', '', ''));
  assert.ok(compareOccurrences(withNull, withString) < 0);
  assert.ok(compareOccurrences(withString, withNull) > 0);
});

test('runtime strings compare by code point, not UTF-16 code unit', () => {
  // U+FF5E sorts before U+1F600 by code point, but after it by UTF-16 code unit.
  assert.ok(compareCodePoints('～', '\u{1F600}') < 0);
  assert.ok(compareOccurrences(run('http://h/～', 'GET', ''), run('http://h/\u{1F600}', 'GET', '')) < 0);
});

test('mixed shapes: source before runtime before neither, and the order is total', () => {
  const items: OccurrenceOrderInput[] = [
    {},
    run('http://h/a', 'GET', ''),
    src('a.ts', 1, 1, 1, 1),
    { source_location: null, runtime_location: null },
    run('http://h/a', 'GET', '', zapEvidence('x', 'y', 'z')),
    src('a.ts', 1, 1, 1, 2),
  ];
  const sorted = [...items].sort(compareOccurrences);
  assert.ok(sorted[0]?.source_location);
  assert.ok(sorted[1]?.source_location);
  assert.ok(sorted[2]?.runtime_location);
  assert.ok(sorted[3]?.runtime_location);
  assertTotalPreorder(items);
});

test('compareCodePoints orders prefixes first and is code-point based', () => {
  assert.ok(compareCodePoints('a', 'ab') < 0);
  assert.ok(compareCodePoints('ab', 'a') > 0);
  assert.equal(compareCodePoints('same', 'same'), 0);
  assert.ok(compareCodePoints('\u{10000}', '￿') > 0);
});
