import assert from 'node:assert/strict';
import { symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { loadConfig } from '../../../src/config/index.js';
import type { Config, ConfigError, Env } from '../../../src/config/index.js';
import { BASE_ENV, type Doc, docYaml, FIXTURES, FIXTURE_ROOT, scratchRepo } from './helpers.js';

function load(yaml: string, env: Env = {}, extra: Record<string, string> = {}) {
  const repo = scratchRepo(yaml, extra);
  return loadConfig(repo.configPath, { root: repo.root, env });
}

function errorsOf(yaml: string, env: Env = {}): ConfigError[] {
  const result = load(yaml, env);
  assert.equal(result.ok, false, 'expected rejection');
  return result.ok ? [] : result.errors;
}

function okConfig(result: ReturnType<typeof loadConfig>): Config {
  assert.equal(result.ok, true, result.ok ? '' : JSON.stringify(result.errors));
  if (!result.ok) throw new Error('unreachable');
  return result.config;
}

function assertNoEcho(errors: ConfigError[], secrets: string[]): void {
  const text = JSON.stringify(errors);
  for (const secret of secrets) assert.equal(text.includes(secret), false, `error echoes ${secret}`);
}

test('minimal fixture loads with defaults', () => {
  const config = okConfig(loadConfig(join(FIXTURES, 'valid-minimal.yaml'), { root: FIXTURE_ROOT, env: {} }));
  assert.equal(config.version, 1);
  assert.deepEqual(config.redaction, { headers: [], json_keys: [], env_vars: [] });
  assert.equal(config.tools.semgrep.ruleTimeoutSeconds, 5);
  assert.equal(config.tools.semgrep.timeoutSeconds, 600);
  assert.equal(config.tools.semgrep.rules.mode, 'local');
  assert.deepEqual(config.tools.zap.allowedTargetOrigins, ['http://127.0.0.1:8080']);
  assert.equal(config.tools.zap.sessionMode, 'require_clean');
  assert.equal(config.tools.zap.active, false);
  assert.equal(config.tools.zap.spiderTimeoutSeconds, 300);
  assert.equal(config.tools.zap.passiveTimeoutSeconds, 120);
});

test('full fixture loads every field, with rule files in config order and hashed', () => {
  const env = { SCANBRIDGE_FIXTURE_SECRET: 'fixture-secret-value' };
  const config = okConfig(loadConfig(join(FIXTURES, 'valid-full.yaml'), { root: FIXTURE_ROOT, env }));
  assert.deepEqual(config.redaction, {
    headers: ['X-Trace-Token'],
    json_keys: ['sessionId'],
    env_vars: ['SCANBRIDGE_FIXTURE_SECRET'],
  });
  assert.equal(config.tools.semgrep.rules.mode, 'local');
  if (config.tools.semgrep.rules.mode === 'local') {
    assert.deepEqual(
      config.tools.semgrep.rules.files.map((f) => f.path),
      ['rules/security.yaml', 'rules/extra.yaml'],
    );
    for (const file of config.tools.semgrep.rules.files) assert.match(file.sha256, /^[0-9a-f]{64}$/);
  }
  assert.equal(config.tools.semgrep.ruleTimeoutSeconds, 10);
  assert.equal(config.tools.semgrep.timeoutSeconds, 900);
  assert.deepEqual(config.tools.zap.allowedTargetOrigins, ['http://127.0.0.1:8080', 'https://staging.example.test']);
  assert.equal(config.tools.zap.sessionMode, 'reset');
  assert.equal(config.tools.zap.spiderTimeoutSeconds, 600);
  assert.equal(config.tools.zap.passiveTimeoutSeconds, 60);
});

test('unknown keys are rejected at every level', () => {
  const cases: [string, (d: Doc) => void][] = [
    ['root', (d) => (d.extra = 1)],
    ['redaction', (d) => (d.redaction = { headers: [], names: [] })],
    ['tools', (d) => (d.tools.other = { enabled: true })],
    ['semgrep tool', (d) => (d.tools.semgrep.extra = true)],
    ['semgrep config', (d) => (d.tools.semgrep.config.unknown = 1)],
    ['zap tool', (d) => (d.tools.zap.extra = true)],
    ['zap config', (d) => (d.tools.zap.config.unknown = 1)],
  ];
  for (const [label, mutate] of cases) {
    const errors = errorsOf(docYaml(mutate), BASE_ENV);
    assert.ok(errors.some((e) => e.message.includes('unknown key')), `${label}: ${JSON.stringify(errors)}`);
  }
});

test('version must be the number 1', () => {
  assert.ok(errorsOf(docYaml((d) => (d.version = 2)), BASE_ENV).length > 0, 'version 2');
  assert.ok(errorsOf(docYaml((d) => (d.version = '1')), BASE_ENV).length > 0, 'version "1"');
  assert.ok(errorsOf(docYaml((d) => delete d.version), BASE_ENV).length > 0, 'missing version');
});

test('zero or several Semgrep rule modes are rejected', () => {
  const none = docYaml((d) => delete d.tools.semgrep.config.rules);
  assert.ok(errorsOf(none, BASE_ENV).length > 0, 'none');

  const autoFalse = docYaml((d) => {
    delete d.tools.semgrep.config.rules;
    d.tools.semgrep.config.use_auto = false;
  });
  assert.ok(errorsOf(autoFalse, BASE_ENV).length > 0, 'use_auto false alone');

  const rulesAndAuto = docYaml((d) => (d.tools.semgrep.config.use_auto = true));
  assert.ok(errorsOf(rulesAndAuto, BASE_ENV).length > 0, 'rules and use_auto');

  const rulesAndRegistry = docYaml((d) => (d.tools.semgrep.config.registry_ids = ['p/ci']));
  assert.ok(errorsOf(rulesAndRegistry, BASE_ENV).length > 0, 'rules and registry_ids');

  const emptyRules = docYaml((d) => (d.tools.semgrep.config.rules = []));
  assert.ok(errorsOf(emptyRules, BASE_ENV).length > 0, 'empty rules');
});

test('registry and auto modes load without rule files', () => {
  const registry = okConfig(
    load(
      docYaml((d) => {
        delete d.tools.semgrep.config.rules;
        d.tools.semgrep.config.registry_ids = ['p/ci'];
      }),
      BASE_ENV,
    ),
  );
  assert.deepEqual(registry.tools.semgrep.rules, { mode: 'registry', ids: ['p/ci'] });

  const auto = okConfig(
    load(
      docYaml((d) => {
        delete d.tools.semgrep.config.rules;
        d.tools.semgrep.config.use_auto = true;
      }),
      BASE_ENV,
    ),
  );
  assert.deepEqual(auto.tools.semgrep.rules, { mode: 'auto' });
});

test('a directory, an escaping path, a symlink escape and a missing file are rejected as rule files', () => {
  const dir = errorsOf(docYaml((d) => (d.tools.semgrep.config.rules = ['rules'])), BASE_ENV);
  assert.ok(dir.some((e) => e.message.includes('must be a file')), 'directory');

  const escaping = scratchRepo(docYaml((d) => (d.tools.semgrep.config.rules = ['../outside.yaml'])));
  writeFileSync(join(escaping.root, '..', 'outside.yaml'), 'rules: []\n');
  const escapingResult = loadConfig(escaping.configPath, { root: escaping.root, env: BASE_ENV });
  assert.equal(escapingResult.ok, false, 'escaping path');

  const link = scratchRepo(docYaml((d) => (d.tools.semgrep.config.rules = ['rules/link.yaml'])));
  writeFileSync(join(link.root, '..', 'outside-link.yaml'), 'rules: []\n');
  symlinkSync(join(link.root, '..', 'outside-link.yaml'), join(link.root, 'rules', 'link.yaml'));
  const linkResult = loadConfig(link.configPath, { root: link.root, env: BASE_ENV });
  assert.equal(linkResult.ok, false, 'symlink escape');
  if (!linkResult.ok) assert.ok(linkResult.errors.some((e) => e.message.includes('escapes')));

  assert.ok(errorsOf(docYaml((d) => (d.tools.semgrep.config.rules = ['rules/missing.yaml'])), BASE_ENV).length > 0);
});

test('Semgrep timeout bounds are enforced (V9 constants from limits.ts)', () => {
  // [verify] V9: bounds come from src/contracts/limits.ts and are not yet confirmed against real fixtures.
  for (const value of [0, 61]) {
    const yaml = docYaml((d) => (d.tools.semgrep.config.rule_timeout_seconds = value));
    assert.ok(errorsOf(yaml, BASE_ENV).length > 0, `rule ${value}`);
  }
  for (const value of [1, 60]) {
    const yaml = docYaml((d) => (d.tools.semgrep.config.rule_timeout_seconds = value));
    assert.equal(load(yaml, BASE_ENV).ok, true, `rule ${value}`);
  }
  for (const value of [59, 3601]) {
    const yaml = docYaml((d) => (d.tools.semgrep.config.timeout_seconds = value));
    assert.ok(errorsOf(yaml, BASE_ENV).length > 0, `process ${value}`);
  }
  for (const value of [60, 3600]) {
    const yaml = docYaml((d) => (d.tools.semgrep.config.timeout_seconds = value));
    assert.equal(load(yaml, BASE_ENV).ok, true, `process ${value}`);
  }
  const stringValue = docYaml((d) => (d.tools.semgrep.config.timeout_seconds = '600'));
  assert.ok(errorsOf(stringValue, BASE_ENV).length > 0, 'string timeout');
});

test('ZAP timeouts, session_mode and active are validated', () => {
  const spider = docYaml((d) => (d.tools.zap.config.spider_timeout_seconds = 0));
  assert.ok(errorsOf(spider, BASE_ENV).length > 0, 'spider 0');
  const passive = docYaml((d) => (d.tools.zap.config.passive_timeout_seconds = 3601));
  assert.ok(errorsOf(passive, BASE_ENV).length > 0, 'passive 3601');
  const session = docYaml((d) => (d.tools.zap.config.session_mode = 'keep'));
  assert.ok(errorsOf(session, BASE_ENV).length > 0, 'session_mode keep');
  const active = docYaml((d) => (d.tools.zap.config.active = true));
  assert.ok(errorsOf(active, BASE_ENV).length > 0, 'active true');
});

test('environment-variable name fields reject a URL without echoing it', () => {
  const url = 'http://127.0.0.1:8080';
  for (const field of ['api_url_env', 'api_key_env', 'target_url_env']) {
    const errors = errorsOf(docYaml((d) => (d.tools.zap.config[field] = url)), BASE_ENV);
    assert.ok(errors.some((e) => e.path.includes(field)), field);
    assertNoEcho(errors, [url]);
  }
  assert.ok(errorsOf(docYaml((d) => (d.tools.zap.config.api_key_env = '1BAD')), BASE_ENV).length > 0);
});

test('the target URL has no field in the schema and is never echoed', () => {
  const target = 'http://127.0.0.1:8080/app';
  const errors = errorsOf(docYaml((d) => (d.tools.zap.config.target_url = target)), BASE_ENV);
  assert.ok(errors.some((e) => e.message.includes('unknown key')));
  assertNoEcho(errors, [target]);
});

test('URLs with user information are rejected anywhere, without echoing them', () => {
  const secretUrl = 'http://svc-user:pass-secret-99@127.0.0.1:8080';
  const errors = errorsOf(
    docYaml((d) => {
      d.tools.zap.config.allowed_target_origins = [secretUrl];
      d.redaction = { headers: [`x-${secretUrl}`] };
    }),
    BASE_ENV,
  );
  assert.ok(errors.length >= 2);
  assertNoEcho(errors, ['svc-user', 'pass-secret-99']);
});

test('allowed_target_origins accepts normalized origins and rejects everything else', () => {
  const plain = okConfig(
    load(docYaml((d) => (d.tools.zap.config.allowed_target_origins = ['https://Staging.Example.test:443'])), BASE_ENV),
  );
  assert.deepEqual(plain.tools.zap.allowedTargetOrigins, ['https://staging.example.test']);

  for (const bad of [
    'http://127.0.0.1:8080/',
    'http://127.0.0.1:8080/path',
    'http://127.0.0.1:8080?q=1',
    'http://127.0.0.1:8080#frag',
    'ftp://127.0.0.1:21',
    'not a url',
    'http://user@127.0.0.1:8080',
  ]) {
    const errors = errorsOf(docYaml((d) => (d.tools.zap.config.allowed_target_origins = [bad])), BASE_ENV);
    assert.ok(errors.some((e) => e.path.includes('allowed_target_origins')), bad);
    assertNoEcho(errors, [bad]);
  }
});

test('short or unset redaction env values are rejected, naming only the variable', () => {
  const yaml = docYaml((d) => (d.redaction = { env_vars: ['SHORT_SECRET_NAME'] }));
  const short = errorsOf(yaml, { SHORT_SECRET_NAME: 'tiny' });
  assert.ok(short.some((e) => e.message.includes('SHORT_SECRET_NAME')));
  assertNoEcho(short, ['tiny']);

  const unset = errorsOf(docYaml((d) => (d.redaction = { env_vars: ['UNSET_SECRET_NAME'] })), {});
  assert.ok(unset.some((e) => e.message.includes('UNSET_SECRET_NAME')));
});

test('invalid redaction env names are rejected', () => {
  assert.ok(errorsOf(docYaml((d) => (d.redaction = { env_vars: ['bad-name'] })), {}).length > 0, 'hyphen');
  assert.ok(errorsOf(docYaml((d) => (d.redaction = { env_vars: ['9LEADING'] })), {}).length > 0, 'leading digit');
});

test('a redaction env value of at least 8 characters is accepted', () => {
  const config = okConfig(
    load(docYaml((d) => (d.redaction = { env_vars: ['GOOD_SECRET_NAME'], headers: ['X-A'] })), {
      GOOD_SECRET_NAME: 'eight-plus',
    }),
  );
  assert.deepEqual(config.redaction.env_vars, ['GOOD_SECRET_NAME']);
});

test('an unreadable config path is rejected', () => {
  const result = loadConfig(join(FIXTURES, 'does-not-exist.yaml'), { root: FIXTURE_ROOT, env: {} });
  assert.equal(result.ok, false);
});

test('YAML syntax errors do not echo the source text', () => {
  const errors = errorsOf('version: 1\ntools: [\n  secret: "unterminated-canary-value\n', {});
  assert.equal(errors.length, 1);
  assertNoEcho(errors, ['unterminated-canary-value']);
});
