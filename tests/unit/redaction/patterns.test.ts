import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PolicyError, buildPolicy, redactText, VALUE_RULE_IDS } from '../../../src/core/redaction/index.js';
import { ENV_SECRET, NEAR_MISSES, VALUE_CASES } from './secrets.js';

const policy = buildPolicy({ headers: [], json_keys: [], env_vars: [] }, {});

test('[verify] V8: value-rule table has exactly the 12 fixed ids in order', () => {
  assert.deepEqual(VALUE_RULE_IDS, [
    'private-key',
    'bearer',
    'provider-github-token',
    'provider-github-pat',
    'provider-gitlab-pat',
    'provider-aws-access-key-id',
    'provider-slack-token',
    'provider-google-api-key',
    'provider-stripe-key',
    'provider-npm-token',
    'assignment',
    'env:<NAME>',
  ]);
});

for (const { id, input, secret } of VALUE_CASES) {
  test(`[verify] V8: rule ${id} replaces its synthetic secret`, () => {
    const { text, summary } = redactText(input, policy);
    assert.ok(!text.includes(secret), `secret leaked: ${text}`);
    assert.equal(summary[id], 1);
    assert.ok(text.includes(`[REDACTED:${id}]`));
  });
}

test('[verify] V8: near misses are not replaced', () => {
  for (const input of NEAR_MISSES) {
    const { text, summary } = redactText(input, policy);
    assert.equal(text, input);
    assert.deepEqual(summary, {});
  }
});

test('[verify] V8: assignment keeps name and separator, replaces only the value', () => {
  assert.equal(redactText('api_key: abc123xyz', policy).text, 'api_key: [REDACTED:assignment]');
  assert.equal(redactText('https://x.test/?token=abc123xyz&page=2', policy).text, 'https://x.test/?token=[REDACTED:assignment]&page=2');
  assert.equal(redactText('secret="hunter2hunter2"', policy).text, 'secret=[REDACTED:assignment]');
});

test('[verify] V8: earlier rules replace before later rules run', () => {
  const { text, summary } = redactText('Authorization: Bearer SyntheticBearer123', policy);
  assert.equal(text, 'Authorization: [REDACTED:bearer]');
  assert.deepEqual(summary, { bearer: 1 });
});

test('[verify] V8: a 1 MiB adversarial string finishes in bounded time for every rule', () => {
  const MIB = 1024 * 1024;
  const inputs = [
    'ghp_'.repeat(MIB / 4),
    '-----BEGIN '.repeat(Math.floor(MIB / 11)),
    'Bearer '.repeat(Math.floor(MIB / 7)),
    'token'.repeat(Math.floor(MIB / 5)),
    'a'.repeat(MIB),
  ];
  for (const input of inputs) {
    const started = performance.now();
    redactText(input, policy);
    const elapsed = performance.now() - started;
    assert.ok(elapsed < 10_000, `took ${elapsed.toFixed(0)} ms`);
  }
});

test('env values: exact substring, every occurrence, longest first', () => {
  const env = { APP_SECRET: ENV_SECRET, SHORT_PART: 'env-secret' };
  const p = buildPolicy({ headers: [], json_keys: [], env_vars: ['APP_SECRET', 'SHORT_PART'] }, env);
  const { text, summary } = redactText(`a ${ENV_SECRET} b ${ENV_SECRET} c env-secret`, p);
  assert.equal(text, 'a [REDACTED:env:APP_SECRET] b [REDACTED:env:APP_SECRET] c [REDACTED:env:SHORT_PART]');
  assert.deepEqual(summary, { 'env:APP_SECRET': 2, 'env:SHORT_PART': 1 });
});

test('env values are literal, not regular expressions', () => {
  const env = { DOTTED: 'a.b*c+d?e' };
  const p = buildPolicy({ headers: [], json_keys: [], env_vars: ['DOTTED'] }, env);
  assert.equal(redactText('x a.b*c+d?e y aXbc', p).text, 'x [REDACTED:env:DOTTED] y aXbc');
});

test('env name validation: rule failure names the variable, never a value', () => {
  const bad = 'not-a-name';
  assert.throws(
    () => buildPolicy({ headers: [], json_keys: [], env_vars: [bad] }, { [bad]: 'valuevalue' }),
    (err: unknown) => err instanceof PolicyError && err.message.includes(bad) && !err.message.includes('valuevalue'),
  );
  assert.throws(
    () => buildPolicy({ headers: [], json_keys: [], env_vars: ['1BAD'] }, { '1BAD': 'valuevalue' }),
    PolicyError,
  );
  assert.throws(
    () => buildPolicy({ headers: [], json_keys: [], env_vars: ['A'.repeat(65)] }, { ['A'.repeat(65)]: 'valuevalue' }),
    PolicyError,
  );
});

test('env value validation: missing or short values throw PolicyError without the value', () => {
  assert.throws(
    () => buildPolicy({ headers: [], json_keys: [], env_vars: ['SHORT'] }, { SHORT: 'short7!' }),
    (err: unknown) => err instanceof PolicyError && err.message.includes('SHORT') && !err.message.includes('short7!'),
  );
  assert.throws(() => buildPolicy({ headers: [], json_keys: [], env_vars: ['MISSING'] }, {}), (err: unknown) => {
    return err instanceof PolicyError && err.message.includes('MISSING');
  });
  assert.doesNotThrow(() => buildPolicy({ headers: [], json_keys: [], env_vars: ['EIGHT'] }, { EIGHT: '12345678' }));
});
