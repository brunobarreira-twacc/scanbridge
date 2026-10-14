import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after } from 'node:test';
import { fileURLToPath } from 'node:url';
import { stringify } from 'yaml';

export const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', 'tests', 'fixtures', 'config');
export const FIXTURE_ROOT = join(FIXTURES, 'repo');

// Synthetic, test-only values. None is a working credential.
export const CANARY_KEY = 'canary-zap-api-key-5c2e9b7a';
export const ENV_API_URL = 'http://127.0.0.1:8080';
export const ENV_TARGET_URL = 'http://127.0.0.1:8080/app?session=abc';

export const BASE_ENV: Record<string, string> = {
  SCANBRIDGE_ZAP_API_URL: ENV_API_URL,
  SCANBRIDGE_ZAP_API_KEY: CANARY_KEY,
  SCANBRIDGE_ZAP_TARGET_URL: ENV_TARGET_URL,
};

const RULE_FILE = 'rules:\n  - id: synthetic-scratch-rule\n    languages: [javascript]\n    severity: WARNING\n    message: Synthetic.\n    pattern: call($X)\n';

const scratchDirs: string[] = [];
after(() => {
  for (const dir of scratchDirs) rmSync(dir, { recursive: true, force: true });
});

/** Creates `<base>/repo` with `rules/security.yaml`, extra files relative to the repo, and `<base>/tools.yaml`. */
export function scratchRepo(config: string, extra: Record<string, string> = {}): { root: string; configPath: string } {
  const base = mkdtempSync(join(tmpdir(), 'scanbridge-config-'));
  scratchDirs.push(base);
  const root = join(base, 'repo');
  mkdirSync(join(root, 'rules'), { recursive: true });
  writeFileSync(join(root, 'rules', 'security.yaml'), RULE_FILE);
  for (const [rel, text] of Object.entries(extra)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  const configPath = join(base, 'tools.yaml');
  writeFileSync(configPath, config);
  return { root, configPath };
}

export type Doc = Record<string, any>;

export const BASE_DOC: Doc = {
  version: 1,
  tools: {
    semgrep: { enabled: true, config: { rules: ['rules/security.yaml'] } },
    zap: {
      enabled: true,
      config: {
        api_url_env: 'SCANBRIDGE_ZAP_API_URL',
        api_key_env: 'SCANBRIDGE_ZAP_API_KEY',
        target_url_env: 'SCANBRIDGE_ZAP_TARGET_URL',
        allowed_target_origins: ['http://127.0.0.1:8080'],
      },
    },
  },
};

/** YAML text of the base document after `mutate` has changed a deep copy of it. */
export function docYaml(mutate: (doc: Doc) => void = () => {}): string {
  const doc = structuredClone(BASE_DOC);
  mutate(doc);
  return stringify(doc);
}
