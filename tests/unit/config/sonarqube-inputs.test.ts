import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import { SensitiveString } from '../../../src/contracts/sensitive.js';
import { loadConfig, resolveSonarQubeInputs, type Config } from '../../../src/config/index.js';
import { FIXTURES, FIXTURE_ROOT } from './helpers.js';

const SQ_ENV = {
  SONARQUBE_URL: 'https://sonarqube.example.com',
  SONARQUBE_TOKEN: 'sqtoken-test-abc123',
  SONARQUBE_PROJECT: 'my-project',
};

function sqConfig(): Config {
  const result = loadConfig(join(FIXTURES, 'valid-minimal.yaml'), { root: FIXTURE_ROOT, env: {} });
  if (!result.ok) throw new Error(JSON.stringify(result.errors));
  return result.config;
}

test('all env vars present: resolves with no problems', () => {
  const result = resolveSonarQubeInputs({ config: sqConfig(), env: SQ_ENV });
  assert.equal(result.apiUrl, SQ_ENV.SONARQUBE_URL);
  assert.ok(result.apiKey instanceof SensitiveString);
  // The SensitiveString holds the full Authorization header value (Bearer-prefixed).
  assert.equal(result.apiKey.reveal(), `Bearer ${SQ_ENV.SONARQUBE_TOKEN}`);
  assert.equal(result.projectKey, SQ_ENV.SONARQUBE_PROJECT);
  assert.deepEqual(result.problems, []);
});

test('missing SONARQUBE_URL: one env problem, apiUrl null', () => {
  const { SONARQUBE_URL: _unused, ...without } = SQ_ENV;
  const result = resolveSonarQubeInputs({ config: sqConfig(), env: without });
  assert.equal(result.apiUrl, null);
  assert.equal(result.problems.length, 1);
  assert.equal(result.problems[0]?.code, 'tool_unavailable');
  assert.ok(result.problems[0]?.message.includes('SONARQUBE_URL'));
});

test('missing SONARQUBE_TOKEN: one env problem, apiKey null', () => {
  const { SONARQUBE_TOKEN: _unused, ...without } = SQ_ENV;
  const result = resolveSonarQubeInputs({ config: sqConfig(), env: without });
  assert.equal(result.apiKey, null);
  assert.equal(result.problems.length, 1);
  assert.ok(result.problems[0]?.message.includes('SONARQUBE_TOKEN'));
});

test('missing SONARQUBE_PROJECT: one env problem, projectKey null', () => {
  const { SONARQUBE_PROJECT: _unused, ...without } = SQ_ENV;
  const result = resolveSonarQubeInputs({ config: sqConfig(), env: without });
  assert.equal(result.projectKey, null);
  assert.equal(result.problems.length, 1);
  assert.ok(result.problems[0]?.message.includes('SONARQUBE_PROJECT'));
});

test('empty string is treated as not set', () => {
  const result = resolveSonarQubeInputs({ config: sqConfig(), env: { ...SQ_ENV, SONARQUBE_TOKEN: '' } });
  assert.equal(result.apiKey, null);
  assert.equal(result.problems.length, 1);
});

test('all three missing: three problems', () => {
  const result = resolveSonarQubeInputs({ config: sqConfig(), env: {} });
  assert.equal(result.problems.length, 3);
  assert.ok(result.problems.every((p) => p.code === 'tool_unavailable'));
});

test('http and https URLs are accepted', () => {
  for (const url of ['http://sonarqube.corp:9000', 'https://sonarqube.example.com', 'http://10.0.0.5:9000', 'https://localhost:9443']) {
    const result = resolveSonarQubeInputs({ config: sqConfig(), env: { ...SQ_ENV, SONARQUBE_URL: url } });
    assert.deepEqual(result.problems, [], url);
    assert.equal(result.apiUrl, url);
  }
});

test('invalid URL or non-http(s) scheme is rejected', () => {
  for (const url of ['ftp://sonarqube.corp', 'not a url', 'sonarqube.corp:9000']) {
    const result = resolveSonarQubeInputs({ config: sqConfig(), env: { ...SQ_ENV, SONARQUBE_URL: url } });
    assert.equal(result.apiUrl, null, url);
    assert.equal(result.problems.length, 1, url);
    assert.ok(!JSON.stringify(result.problems).includes(url), `problem echoes ${url}`);
  }
});

test('URL with user info (credentials) is rejected', () => {
  const result = resolveSonarQubeInputs({ config: sqConfig(), env: { ...SQ_ENV, SONARQUBE_URL: 'https://admin:pw@sonarqube.corp' } });
  assert.equal(result.apiUrl, null);
  assert.equal(result.problems.length, 1);
});

test('loopback URL is accepted (not restricted like ZAP)', () => {
  const result = resolveSonarQubeInputs({ config: sqConfig(), env: { ...SQ_ENV, SONARQUBE_URL: 'http://127.0.0.1:9000' } });
  assert.deepEqual(result.problems, []);
  assert.equal(result.apiUrl, 'http://127.0.0.1:9000');
});

test('the API token never appears in serialized or problem output', () => {
  // URL is invalid so problems include a URL error; token IS resolved independently as SensitiveString.
  const result = resolveSonarQubeInputs({ config: sqConfig(), env: { ...SQ_ENV, SONARQUBE_URL: 'not-a-url' } });
  const text = JSON.stringify(result);
  assert.ok(!text.includes(SQ_ENV.SONARQUBE_TOKEN), 'token must not appear in serialized result');
  for (const p of result.problems) assert.ok(!p.message.includes(SQ_ENV.SONARQUBE_TOKEN));
  // The header value is accessible via reveal() but never leaks through toString/toJSON.
  assert.equal(result.apiKey?.reveal(), `Bearer ${SQ_ENV.SONARQUBE_TOKEN}`);
  assert.equal(`${result.apiKey}`, '[REDACTED]');
});

test('resolved apiKey serializes as [REDACTED], token never visible in JSON', () => {
  const result = resolveSonarQubeInputs({ config: sqConfig(), env: SQ_ENV });
  assert.equal(`${result.apiKey}`, '[REDACTED]');
  assert.equal(JSON.stringify(result.apiKey), '"[REDACTED]"');
  assert.ok(!JSON.stringify(result).includes(SQ_ENV.SONARQUBE_TOKEN));
  assert.ok(!JSON.stringify(result).includes('Bearer'));
});
