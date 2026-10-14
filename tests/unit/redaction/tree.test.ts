import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RedactionError, buildPolicy, redactTree } from '../../../src/core/redaction/index.js';

const policy = buildPolicy({ headers: ['X-Custom-Auth'], json_keys: ['sessionId'], env_vars: [] }, {});

test('built-in header keys are redacted case-insensitively', () => {
  const input = { Authorization: 'a', cookie: 'b', 'SET-COOKIE': 'c', 'x-api-key': 'd', keep: 'e' };
  const { value, summary, touched } = redactTree(input, policy);
  assert.deepEqual(value, {
    Authorization: '[REDACTED:header]',
    cookie: '[REDACTED:header]',
    'SET-COOKIE': '[REDACTED:header]',
    'x-api-key': '[REDACTED:header]',
    keep: 'e',
  });
  assert.deepEqual(summary, { header: 4 });
  assert.deepEqual(touched, ['/Authorization', '/cookie', '/SET-COOKIE', '/x-api-key']);
});

test('configured header names match case-insensitively as keys', () => {
  const { value } = redactTree({ 'x-custom-auth': 'secret-ish' }, policy);
  assert.deepEqual(value, { 'x-custom-auth': '[REDACTED:header]' });
});

test('configured and built-in header names match as {name, value} header pairs', () => {
  const input = {
    headers: [
      { name: 'x-custom-auth', value: 'v1' },
      { name: 'Cookie', value: 'v2' },
      { name: 'Accept', value: 'keep' },
    ],
  };
  const { value, summary, touched } = redactTree(input, policy);
  assert.deepEqual(value, {
    headers: [
      { name: 'x-custom-auth', value: '[REDACTED:header]' },
      { name: 'Cookie', value: '[REDACTED:header]' },
      { name: 'Accept', value: 'keep' },
    ],
  });
  assert.deepEqual(summary, { header: 2 });
  assert.deepEqual(touched, ['/headers/0/value', '/headers/1/value']);
});

test('configured json_keys match exact case only', () => {
  const { value } = redactTree({ sessionId: 'x', sessionid: 'y' }, policy);
  assert.deepEqual(value, { sessionId: '[REDACTED:json-key]', sessionid: 'y' });
});

test('built-in key-name detection is case-insensitive for token, password and secret', () => {
  const input = { ApiTOKEN: 'a', PassWord: 'b', SECRET_x: 'c', nested: { tokenized: 'd' }, plain: 'e' };
  const { value, summary } = redactTree(input, policy);
  assert.deepEqual(value, {
    ApiTOKEN: '[REDACTED:key-name]',
    PassWord: '[REDACTED:key-name]',
    SECRET_x: '[REDACTED:key-name]',
    nested: { tokenized: '[REDACTED:key-name]' },
    plain: 'e',
  });
  assert.deepEqual(summary, { 'key-name': 4 });
});

test('key rule replaces a container value wholesale and reports its pointer', () => {
  const { value, touched } = redactTree({ password: { inner: 'x' } }, policy);
  assert.deepEqual(value, { password: '[REDACTED:key-name]' });
  assert.deepEqual(touched, ['/password']);
});

test('removePaths with wildcards deletes matching members, counts them, and reports the parent', () => {
  const input = {
    results: [
      { check_id: 'a', extra: { metavars: { $X: { abstract_content: 'secret-code' } }, message: 'm' } },
      { check_id: 'b', extra: { metavars: {}, message: 'n' } },
    ],
  };
  const { value, summary, touched } = redactTree(input, policy, { removePaths: ['results.*.extra.metavars'] });
  assert.deepEqual(value, {
    results: [
      { check_id: 'a', extra: { message: 'm' } },
      { check_id: 'b', extra: { message: 'n' } },
    ],
  });
  assert.deepEqual(summary, { 'removed-path': 2 });
  assert.deepEqual(touched, ['/results/0/extra', '/results/1/extra']);
  assert.ok(!JSON.stringify(value).includes('secret-code'));
});

test('removePaths deletes a root key and reports the root pointer', () => {
  const { value, summary, touched } = redactTree({ a: 1, b: 2 }, policy, { removePaths: ['a'] });
  assert.deepEqual(value, { b: 2 });
  assert.deepEqual(summary, { 'removed-path': 1 });
  assert.deepEqual(touched, ['']);
});

test('touched pointers are RFC 6901 escaped and cover replaced strings', () => {
  const input = { 'a/b': { 'c~d': 'Bearer SyntheticBearer123' } };
  const { value, touched } = redactTree(input, policy);
  assert.deepEqual(value, { 'a/b': { 'c~d': '[REDACTED:bearer]' } });
  assert.deepEqual(touched, ['/a~1b/c~0d']);
});

test('summary counts every replacement by rule id and is sorted', () => {
  const input = { password: 'x', list: ['token=abc123xyz', 'token=def456uvw'] };
  const { summary } = redactTree(input, policy);
  assert.deepEqual(Object.keys(summary), ['assignment', 'key-name']);
  assert.deepEqual(summary, { assignment: 2, 'key-name': 1 });
});

test('input is not mutated', () => {
  const input = { Authorization: 'a', nested: { password: 'b', text: 'Bearer SyntheticBearer123' }, list: [{ name: 'Cookie', value: 'c' }] };
  const snapshot = JSON.stringify(input);
  const { value } = redactTree(input, policy, { removePaths: ['list.*.name'] });
  assert.equal(JSON.stringify(input), snapshot);
  assert.notEqual(value, input);
});

test('keys that are not plain identifiers survive as own properties', () => {
  const input = JSON.parse('{"__proto__": {"x": "keep"}, "plain": 1}') as Record<string, unknown>;
  const { value } = redactTree(input, policy);
  assert.deepEqual(Object.keys(value as object), ['__proto__', 'plain']);
  assert.equal(Object.getPrototypeOf(value), Object.prototype);
});

test('output is deterministic across runs', () => {
  const input = { password: 'x', list: [{ text: 'token=abc123xyz' }], n: 1, b: true, z: null };
  const first = redactTree(input, policy);
  const second = redactTree(input, policy);
  assert.deepEqual(first, second);
});

test('fail closed: cyclic structures throw RedactionError', () => {
  const cyclic: Record<string, unknown> = { a: 1 };
  cyclic.self = cyclic;
  assert.throws(() => redactTree(cyclic, policy), RedactionError);
  const arr: unknown[] = [];
  arr.push(arr);
  assert.throws(() => redactTree(arr, policy), RedactionError);
});

test('fail closed: non-JSON values throw RedactionError', () => {
  const bad: unknown[] = [
    { n: BigInt(1) },
    { f: () => 1 },
    { u: undefined },
    { n: Number.NaN },
    { n: Number.POSITIVE_INFINITY },
    { d: new Date(0) },
    { s: Symbol('x') },
    [, 1],
  ];
  for (const input of bad) assert.throws(() => redactTree(input, policy), RedactionError);
});

test('fail closed: non-JSON nested under a key that would be replaced still throws', () => {
  assert.throws(() => redactTree({ password: () => 1 }, policy), RedactionError);
});

test('fail closed: a hand-made or copied policy throws instead of skipping env values', () => {
  const env = { TOKEN_ONE: 'first-env-value-111' };
  const real = buildPolicy({ headers: [], json_keys: [], env_vars: ['TOKEN_ONE'] }, env);
  const copied = { ...real };
  assert.throws(() => redactTree('first-env-value-111', copied), RedactionError);
});
