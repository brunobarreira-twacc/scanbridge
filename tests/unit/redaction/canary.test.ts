import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildPolicy, redactText, redactTree } from '../../../src/core/redaction/index.js';
import { ENV_SECRET, VALUE_CASES } from './secrets.js';

const KEY_SECRET = 'synthetic-key-secret-7731';
const HEADER_SECRET = 'synthetic-header-secret-8842';
const JSON_KEY_SECRET = 'synthetic-json-key-secret-5520';
const PAIR_SECRET = 'synthetic-pair-secret-6613';

const policy = buildPolicy(
  { headers: ['X-Custom-Auth'], json_keys: ['sessionId'], env_vars: ['APP_SECRET'] },
  { APP_SECRET: ENV_SECRET },
);

test('secret canary: no synthetic secret survives in tree output, summary, touched or snippets', () => {
  const producer = {
    Authorization: HEADER_SECRET,
    'x-api-key': HEADER_SECRET,
    headers: [{ name: 'x-custom-auth', value: PAIR_SECRET }],
    sessionId: JSON_KEY_SECRET,
    apiToken: KEY_SECRET,
    results: VALUE_CASES.map((c) => ({ check_id: c.id, message: c.input, env: ENV_SECRET })),
  };
  const { value, summary, touched } = redactTree(producer, policy);
  const serialized = JSON.stringify({ value, summary, touched });
  const secrets = [
    HEADER_SECRET,
    PAIR_SECRET,
    JSON_KEY_SECRET,
    KEY_SECRET,
    ENV_SECRET,
    ...VALUE_CASES.map((c) => c.secret),
  ];
  for (const secret of secrets) assert.ok(!serialized.includes(secret), `secret leaked: ${secret}`);
});

test('secret canary: every value rule and built-in header and key rule is exercised', () => {
  const producer = {
    Cookie: 'c',
    'Set-Cookie': 'sc',
    passWORD: 'p',
    secret_x: 's',
    results: VALUE_CASES.map((c) => ({ message: c.input })),
  };
  const { summary } = redactTree({ ...producer, env: ENV_SECRET }, policy);
  assert.deepEqual(summary['header'], 2);
  assert.deepEqual(summary['key-name'], 2);
  for (const c of VALUE_CASES) assert.equal(summary[c.id], 1, `rule ${c.id}`);
  assert.equal(summary['env:APP_SECRET'], 1);
});

test('secret canary: snippets redacted with redactText carry no synthetic secret', () => {
  for (const c of VALUE_CASES) {
    const { text } = redactText(`line: ${c.input} ${ENV_SECRET}`, policy);
    assert.ok(!text.includes(c.secret), `secret leaked for ${c.id}: ${text}`);
    assert.ok(!text.includes(ENV_SECRET));
  }
});
