import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildPolicy } from '../../../src/core/redaction/index.js';

const ENV = { TOKEN_ONE: 'first-env-value-111', TOKEN_TWO: 'second-env-value-222' };

test('policy version is BUILTIN version plus 12 hex digits', () => {
  const { version } = buildPolicy({ headers: [], json_keys: [], env_vars: [] }, {});
  assert.match(version, /^1\+[0-9a-f]{12}$/);
});

test('policy version is stable for reordered and duplicated config lists', () => {
  const a = buildPolicy({ headers: ['X-B', 'X-A'], json_keys: ['beta', 'alpha'], env_vars: ['TOKEN_ONE', 'TOKEN_TWO'] }, ENV);
  const b = buildPolicy(
    { headers: ['X-A', 'X-B', 'X-A'], json_keys: ['alpha', 'beta'], env_vars: ['TOKEN_TWO', 'TOKEN_ONE', 'TOKEN_ONE'] },
    ENV,
  );
  assert.equal(a.version, b.version);
  assert.deepEqual(b.headers, ['X-A', 'X-B']);
  assert.deepEqual(b.envVars, ['TOKEN_ONE', 'TOKEN_TWO']);
});

test('policy version changes when a header, key or env name is added', () => {
  const base = buildPolicy({ headers: [], json_keys: [], env_vars: [] }, {});
  const withHeader = buildPolicy({ headers: ['X-Custom'], json_keys: [], env_vars: [] }, {});
  const withKey = buildPolicy({ headers: [], json_keys: ['sessionId'], env_vars: [] }, {});
  const withEnv = buildPolicy({ headers: [], json_keys: [], env_vars: ['TOKEN_ONE'] }, ENV);
  const versions = new Set([base.version, withHeader.version, withKey.version, withEnv.version]);
  assert.equal(versions.size, 4);
});

test('policy version is independent of env values', () => {
  const a = buildPolicy({ headers: [], json_keys: [], env_vars: ['TOKEN_ONE'] }, { TOKEN_ONE: 'first-env-value-111' });
  const b = buildPolicy({ headers: [], json_keys: [], env_vars: ['TOKEN_ONE'] }, { TOKEN_ONE: 'other-env-value-999' });
  assert.equal(a.version, b.version);
});

test('policy object never serializes env values', () => {
  const policy = buildPolicy({ headers: [], json_keys: [], env_vars: ['TOKEN_ONE'] }, ENV);
  const serialized = JSON.stringify(policy);
  assert.ok(!serialized.includes('first-env-value-111'));
  assert.deepEqual(policy.envVars, ['TOKEN_ONE']);
});

test('policy is frozen', () => {
  const policy = buildPolicy({ headers: ['X-A'], json_keys: [], env_vars: [] }, {});
  assert.ok(Object.isFrozen(policy));
  assert.ok(Object.isFrozen(policy.headers));
});
