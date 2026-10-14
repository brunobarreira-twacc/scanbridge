import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { configurationDigest, loadConfig, rulesDigest, type Config, type RuleFile } from '../../../src/config/index.js';
import { BASE_ENV, docYaml, scratchRepo } from './helpers.js';

const FILE_A: RuleFile = { path: 'rules/a.yaml', sha256: 'a'.repeat(64) };
const FILE_B: RuleFile = { path: 'rules/b.yaml', sha256: 'b'.repeat(64) };

function loadOk(yaml: string, env: Record<string, string | undefined> = BASE_ENV, extra: Record<string, string> = {}) {
  const repo = scratchRepo(yaml, extra);
  const result = loadConfig(repo.configPath, { root: repo.root, env });
  assert.equal(result.ok, true, result.ok ? '' : JSON.stringify(result.errors));
  if (!result.ok) throw new Error('unreachable');
  return { config: result.config, root: repo.root };
}

function localFiles(config: Config): RuleFile[] {
  return config.tools.semgrep.rules.mode === 'local' ? config.tools.semgrep.rules.files : [];
}

function digestOf(config: Config, tool: 'semgrep' | 'zap' = 'semgrep', files = localFiles(config)): string {
  return configurationDigest({
    tool,
    config,
    redactionPolicyInput: config.redaction,
    ruleFiles: files,
  });
}

test('rulesDigest is null for registry and auto modes', () => {
  const registry = loadOk(
    docYaml((d) => {
      delete d.tools.semgrep.config.rules;
      d.tools.semgrep.config.registry_ids = ['p/ci'];
    }),
  ).config;
  const auto = loadOk(
    docYaml((d) => {
      delete d.tools.semgrep.config.rules;
      d.tools.semgrep.config.use_auto = true;
    }),
  ).config;
  assert.equal(rulesDigest(registry.tools.semgrep.rules.mode === 'local' ? localFiles(registry) : null), null);
  assert.equal(rulesDigest(auto.tools.semgrep.rules.mode === 'local' ? localFiles(auto) : null), null);
});

test('rulesDigest is a SHA-256 hex digest that ignores file order', () => {
  const digest = rulesDigest([FILE_A, FILE_B]);
  assert.match(digest ?? '', /^[0-9a-f]{64}$/);
  assert.equal(rulesDigest([FILE_B, FILE_A]), digest);
  assert.notEqual(rulesDigest([FILE_A]), digest);
});

test('rulesDigest changes with a file path or its content hash', () => {
  const base = rulesDigest([FILE_A]);
  assert.notEqual(rulesDigest([{ ...FILE_A, path: 'rules/renamed.yaml' }]), base);
  assert.notEqual(rulesDigest([{ ...FILE_A, sha256: 'c'.repeat(64) }]), base);
});

test('configurationDigest is stable when YAML keys are reordered', () => {
  const ordered = loadOk(docYaml()).config;
  const reordered = loadOk(
    [
      'tools:',
      '  zap:',
      '    config:',
      '      allowed_target_origins: ["http://127.0.0.1:8080"]',
      '      target_url_env: SCANBRIDGE_ZAP_TARGET_URL',
      '      api_key_env: SCANBRIDGE_ZAP_API_KEY',
      '      api_url_env: SCANBRIDGE_ZAP_API_URL',
      '    enabled: true',
      '  semgrep:',
      '    config:',
      '      rules: [rules/security.yaml]',
      '    enabled: true',
      'version: 1',
      '',
    ].join('\n'),
  ).config;
  assert.equal(digestOf(reordered), digestOf(ordered));
  assert.equal(digestOf(reordered, 'zap'), digestOf(ordered, 'zap'));
});

test('configurationDigest changes with the validated config', () => {
  const base = digestOf(loadOk(docYaml()).config);
  const timeout = digestOf(loadOk(docYaml((d) => (d.tools.semgrep.config.timeout_seconds = 601))).config);
  assert.notEqual(timeout, base);
});

test('configurationDigest changes with rule file content', () => {
  const repo = scratchRepo(docYaml());
  const first = loadConfig(repo.configPath, { root: repo.root, env: BASE_ENV });
  if (!first.ok) throw new Error('setup');
  const before = digestOf(first.config);

  // Rewriting the rule file changes its bytes, so the loader hashes different content.
  writeFileSync(join(repo.root, 'rules', 'security.yaml'), 'rules: []\n# changed\n');
  const second = loadConfig(repo.configPath, { root: repo.root, env: BASE_ENV });
  if (!second.ok) throw new Error('setup');
  assert.notEqual(digestOf(second.config), before);
});

test('configurationDigest ignores redaction env values, and includes names only', () => {
  const yaml = docYaml((d) => (d.redaction = { env_vars: ['DIGEST_SECRET'] }));
  const one = loadOk(yaml, { ...BASE_ENV, DIGEST_SECRET: 'first-secret-value' }).config;
  const two = loadOk(yaml, { ...BASE_ENV, DIGEST_SECRET: 'second-secret-value' }).config;
  assert.equal(digestOf(one), digestOf(two));

  const withoutName = digestOf(loadOk(docYaml()).config);
  assert.notEqual(digestOf(one), withoutName);
});

test('configurationDigest ignores the API key and the target URL values', () => {
  const config = loadOk(docYaml()).config;
  const first = digestOf(config, 'zap');
  const second = digestOf(loadOk(docYaml(), { ...BASE_ENV, SCANBRIDGE_ZAP_API_KEY: 'another-key-value-99', SCANBRIDGE_ZAP_TARGET_URL: 'http://127.0.0.1:8080/other' }).config, 'zap');
  assert.equal(first, second);
});

test('configurationDigest is a SHA-256 hex digest', () => {
  assert.match(digestOf(loadOk(docYaml()).config), /^[0-9a-f]{64}$/);
});
