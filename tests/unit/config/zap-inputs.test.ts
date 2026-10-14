import assert from 'node:assert/strict';
import { join } from 'node:path';
import { inspect } from 'node:util';
import { test } from 'node:test';
import { SensitiveString } from '../../../src/contracts/sensitive.js';
import {
  loadConfig,
  resolveZapDoctorInputs,
  resolveZapLiveInputs,
  resolveZapOfflineInputs,
  type Config,
  type Env,
} from '../../../src/config/index.js';
import { BASE_ENV, CANARY_KEY, ENV_API_URL, ENV_TARGET_URL, FIXTURES, FIXTURE_ROOT } from './helpers.js';

function zapConfig(): Config {
  const result = loadConfig(join(FIXTURES, 'valid-minimal.yaml'), { root: FIXTURE_ROOT, env: {} });
  if (!result.ok) throw new Error(JSON.stringify(result.errors));
  return result.config;
}

/** An env reader that fails the test if any of `forbidden` is read. */
function guardedEnv(base: Env, forbidden: string[]): Env {
  return new Proxy(base, {
    get(target, key) {
      if (typeof key === 'string' && forbidden.includes(key)) throw new Error(`read forbidden variable ${key}`);
      return target[key as string];
    },
    has(target, key) {
      if (typeof key === 'string' && forbidden.includes(key)) throw new Error(`read forbidden variable ${key}`);
      return key in target;
    },
  });
}

test('doctor: key and URL present resolve with no problems', () => {
  const result = resolveZapDoctorInputs({ config: zapConfig(), env: BASE_ENV });
  assert.equal(result.apiUrl, ENV_API_URL);
  assert.ok(result.apiKey instanceof SensitiveString);
  assert.equal(result.apiKey?.reveal(), CANARY_KEY);
  assert.equal(result.apiKeyPresent, true);
  assert.deepEqual(result.problems, []);
});

test('doctor: a missing key gives apiKeyPresent false and one env problem', () => {
  const env = { SCANBRIDGE_ZAP_API_URL: ENV_API_URL };
  const result = resolveZapDoctorInputs({ config: zapConfig(), env });
  assert.equal(result.apiKey, null);
  assert.equal(result.apiKeyPresent, false);
  assert.equal(result.problems.length, 1);
  assert.deepEqual(result.problems[0], {
    source: 'env',
    code: 'tool_unavailable',
    message: 'SCANBRIDGE_ZAP_API_KEY is not set',
  });
});

test('doctor: an empty key counts as not present', () => {
  const env = { ...BASE_ENV, SCANBRIDGE_ZAP_API_KEY: '' };
  const result = resolveZapDoctorInputs({ config: zapConfig(), env });
  assert.equal(result.apiKeyPresent, false);
});

test('doctor: loopback forms are accepted, others are readiness problems', () => {
  for (const url of ['http://127.0.0.2:8080', 'http://127.255.0.1', 'http://[::1]:8080', 'https://localhost:9443']) {
    const result = resolveZapDoctorInputs({ config: zapConfig(), env: { ...BASE_ENV, SCANBRIDGE_ZAP_API_URL: url } });
    assert.deepEqual(result.problems, [], url);
    assert.equal(result.apiUrl, url);
  }
  for (const url of ['http://example.test:8080', 'http://10.0.0.5:8080', 'http://128.0.0.1', 'ftp://127.0.0.1', 'http://user:pw@127.0.0.1:8080', 'not a url']) {
    const result = resolveZapDoctorInputs({ config: zapConfig(), env: { ...BASE_ENV, SCANBRIDGE_ZAP_API_URL: url } });
    assert.equal(result.apiUrl, null, url);
    assert.equal(result.problems.length, 1, url);
    assert.equal(result.problems[0]?.code, 'tool_unavailable');
    assert.equal(JSON.stringify(result.problems).includes(url), false, `problem echoes ${url}`);
  }
});

test('doctor: never reads or reports the target variable', () => {
  const env = guardedEnv(
    { SCANBRIDGE_ZAP_API_URL: ENV_API_URL, SCANBRIDGE_ZAP_API_KEY: CANARY_KEY },
    ['SCANBRIDGE_ZAP_TARGET_URL'],
  );
  const result = resolveZapDoctorInputs({ config: zapConfig(), env });
  assert.deepEqual(result.problems, []);
  assert.equal(Object.keys(result).includes('targetUrl'), false);
});

test('live: the flag wins over the target variable and marks the override', () => {
  const flagUrl = 'http://127.0.0.1:8080/flag-target';
  const result = resolveZapLiveInputs({ config: zapConfig(), env: BASE_ENV, flags: { targetUrl: flagUrl } });
  assert.equal(result.targetUrl, flagUrl);
  assert.equal(result.targetUrlOverridden, true);
  assert.deepEqual(result.problems, []);
});

test('live: the env target is used without an override', () => {
  const result = resolveZapLiveInputs({ config: zapConfig(), env: BASE_ENV, flags: {} });
  assert.equal(result.targetUrl, ENV_TARGET_URL);
  assert.equal(result.targetUrlOverridden, false);
  assert.deepEqual(result.problems, []);
});

test('live: no target from flag or env is an env problem', () => {
  const env = { SCANBRIDGE_ZAP_API_URL: ENV_API_URL, SCANBRIDGE_ZAP_API_KEY: CANARY_KEY };
  const result = resolveZapLiveInputs({ config: zapConfig(), env, flags: {} });
  assert.equal(result.targetUrl, null);
  assert.equal(result.targetUrlOverridden, false);
  assert.equal(result.problems.length, 1);
  assert.equal(result.problems[0]?.source, 'env');
  assert.equal(result.problems[0]?.code, 'tool_unavailable');
});

test('live: a non-loopback API URL from env is an env problem, an invalid flag is a flag problem', () => {
  const fromEnv = resolveZapLiveInputs({
    config: zapConfig(),
    env: { ...BASE_ENV, SCANBRIDGE_ZAP_API_URL: 'http://zap.example.test:8080' },
    flags: {},
  });
  assert.equal(fromEnv.apiUrl, null);
  assert.deepEqual(fromEnv.problems.map((p) => [p.source, p.code]), [['env', 'tool_unavailable']]);

  const invalidFlag = resolveZapLiveInputs({ config: zapConfig(), env: BASE_ENV, flags: { targetUrl: 'not a url' } });
  assert.equal(invalidFlag.targetUrl, null);
  assert.deepEqual(invalidFlag.problems.map((p) => [p.source, p.code]), [['flag', 'usage_error']]);
});

test('live: an origin outside the allowlist is an env problem from env and a flag problem from the flag', () => {
  const fromEnv = resolveZapLiveInputs({
    config: zapConfig(),
    env: { ...BASE_ENV, SCANBRIDGE_ZAP_TARGET_URL: 'http://evil.test/app' },
    flags: {},
  });
  assert.deepEqual(fromEnv.problems.map((p) => [p.source, p.code]), [['env', 'tool_unavailable']]);

  const fromFlag = resolveZapLiveInputs({ config: zapConfig(), env: BASE_ENV, flags: { targetUrl: 'http://evil.test/app' } });
  assert.deepEqual(fromFlag.problems.map((p) => [p.source, p.code]), [['flag', 'usage_error']]);
  assert.equal(fromFlag.targetUrl, null);
});

test('live: a missing key is a problem and no problem text carries a value', () => {
  const env = { ...BASE_ENV, SCANBRIDGE_ZAP_API_KEY: undefined };
  const result = resolveZapLiveInputs({ config: zapConfig(), env, flags: { targetUrl: 'http://evil.test/x' } });
  assert.equal(result.apiKey, null);
  assert.ok(result.problems.some((p) => p.message.includes('SCANBRIDGE_ZAP_API_KEY')));
  assert.equal(JSON.stringify(result.problems).includes(CANARY_KEY), false);
});

test('offline: the flag target resolves and no API URL or key field exists', () => {
  const flagUrl = 'http://127.0.0.1:8080/offline';
  const result = resolveZapOfflineInputs({ config: zapConfig(), env: BASE_ENV, flags: { targetUrl: flagUrl } });
  assert.equal(result.targetUrl, flagUrl);
  assert.equal(result.targetUrlOverridden, true);
  assert.deepEqual(result.problems, []);
  assert.equal('apiKey' in result, false);
  assert.equal('apiUrl' in result, false);
});

test('offline: the env target resolves without an override', () => {
  const result = resolveZapOfflineInputs({ config: zapConfig(), env: BASE_ENV, flags: {} });
  assert.equal(result.targetUrl, ENV_TARGET_URL);
  assert.equal(result.targetUrlOverridden, false);
  assert.deepEqual(result.problems, []);
});

test('offline: neither source is an env problem; an unlisted origin is reported', () => {
  const none = resolveZapOfflineInputs({
    config: zapConfig(),
    env: { SCANBRIDGE_ZAP_TARGET_URL: undefined },
    flags: {},
  });
  assert.equal(none.targetUrl, null);
  assert.deepEqual(none.problems.map((p) => p.source), ['env']);

  const unlisted = resolveZapOfflineInputs({ config: zapConfig(), env: BASE_ENV, flags: { targetUrl: 'https://evil.test' } });
  assert.deepEqual(unlisted.problems.map((p) => [p.source, p.code]), [['flag', 'usage_error']]);
});

test('offline: never reads the API URL or API key variables', () => {
  const env = guardedEnv(
    { SCANBRIDGE_ZAP_TARGET_URL: ENV_TARGET_URL },
    ['SCANBRIDGE_ZAP_API_URL', 'SCANBRIDGE_ZAP_API_KEY'],
  );
  const result = resolveZapOfflineInputs({ config: zapConfig(), env, flags: {} });
  assert.equal(result.targetUrl, ENV_TARGET_URL);
  assert.deepEqual(result.problems, []);
});

test('the API key never appears in serialized, inspected or problem output', () => {
  const env = { ...BASE_ENV, SCANBRIDGE_ZAP_API_URL: 'http://zap.example.test' };
  const config = zapConfig();
  const results = [
    resolveZapDoctorInputs({ config, env }),
    resolveZapLiveInputs({ config, env, flags: { targetUrl: 'http://evil.test' } }),
    resolveZapOfflineInputs({ config, env, flags: {} }),
  ];
  for (const result of results) {
    const surfaces = [JSON.stringify(result), inspect(result, { depth: 10 }), String(result.problems)];
    for (const text of surfaces) assert.equal(text.includes(CANARY_KEY), false, text);
  }
  const key = resolveZapDoctorInputs({ config, env: BASE_ENV }).apiKey;
  assert.equal(key?.reveal(), CANARY_KEY);
  assert.equal(`${key}`, '[REDACTED]');
});
