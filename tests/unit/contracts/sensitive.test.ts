import assert from 'node:assert/strict';
import { inspect } from 'node:util';
import { mock, test } from 'node:test';
import { SensitiveString } from '../../../src/contracts/sensitive.js';

const CANARY = 'canary-key-9f3a7c1e';

test('implicit conversions never reveal the value', () => {
  const s = new SensitiveString(CANARY);
  const outputs = [
    String(s),
    `${s}`,
    s + '',
    JSON.stringify(s),
    JSON.stringify({ key: s, nested: [s] }),
    inspect(s),
    inspect({ key: s }, { depth: 5 }),
    s.toString(),
  ];
  for (const o of outputs) {
    assert.equal(o.includes(CANARY), false, o);
    assert.match(o, /\[REDACTED\]/);
  }
});

test('console.log capture never reveals the value', () => {
  const s = new SensitiveString(CANARY);
  const log = mock.method(console, 'log', () => {});
  const stdout = mock.method(process.stdout, 'write', () => true);
  try {
    console.log(s);
    console.log({ s });
    console.log('%s %o', s, s);
  } finally {
    const calls = [...log.mock.calls, ...stdout.mock.calls].map((c) => c.arguments.map((a) => inspect(a)).join(' '));
    log.mock.restore();
    stdout.mock.restore();
    for (const c of calls) assert.equal(c.includes(CANARY), false);
    assert.ok(calls.length >= 3);
  }
});

test('reveal() returns the value', () => {
  assert.equal(new SensitiveString(CANARY).reveal(), CANARY);
});

test('no own enumerable property exposes the value', () => {
  const s = new SensitiveString(CANARY);
  assert.deepEqual(Object.keys(s), []);
  assert.equal(JSON.stringify(Object.getOwnPropertyNames(s)).includes(CANARY), false);
  assert.equal(JSON.stringify(Object.entries(s)).includes(CANARY), false);
});
