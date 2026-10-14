import { readFileSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import { parseDocument } from 'yaml';
import { z } from 'zod';
import { normalizeOrigin, sha256Hex } from '../core/fingerprints/index.js';
import { buildPolicy, PolicyError } from '../core/redaction/index.js';
import {
  SEMGREP_PROCESS_TIMEOUT_DEFAULT,
  SEMGREP_PROCESS_TIMEOUT_MAX,
  SEMGREP_PROCESS_TIMEOUT_MIN,
  SEMGREP_RULE_TIMEOUT_DEFAULT,
  SEMGREP_RULE_TIMEOUT_MAX,
  SEMGREP_RULE_TIMEOUT_MIN,
  ZAP_DEADLINE_MAX,
  ZAP_DEADLINE_MIN,
  ZAP_PASSIVE_TIMEOUT_DEFAULT,
  ZAP_SPIDER_TIMEOUT_DEFAULT,
} from '../contracts/limits.js';
import type { Config, ConfigError, Env, RuleFile, SemgrepRules } from './types.js';

export type LoadConfigResult = { ok: true; config: Config } | { ok: false; errors: ConfigError[] };

const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const ENV_NAME_MESSAGE = 'must be an environment variable name';
// Matches `scheme://user@` or `scheme://user:pass@` anywhere in a string value.
const USER_INFO_URL = /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s/?#@]*@/;
// Key names are echoed in errors only when they look like plain identifiers.
const SAFE_KEY = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/;

const nonEmpty = z.string().min(1);
const envName = z.string().regex(ENV_NAME_PATTERN, ENV_NAME_MESSAGE);
const seconds = (min: number, max: number, fallback: number) =>
  z.number().int().min(min).max(max).default(fallback);

const redactionSchema = z
  .strictObject({
    headers: z.array(nonEmpty).default([]),
    json_keys: z.array(nonEmpty).default([]),
    env_vars: z.array(envName).default([]),
  })
  .default({ headers: [], json_keys: [], env_vars: [] });

const semgrepConfigSchema = z.strictObject({
  rules: z.array(nonEmpty).min(1).optional(),
  registry_ids: z.array(nonEmpty).min(1).optional(),
  use_auto: z.boolean().optional(),
  // [verify] V9: bounds come from src/contracts/limits.ts, revisited with real fixtures.
  rule_timeout_seconds: seconds(SEMGREP_RULE_TIMEOUT_MIN, SEMGREP_RULE_TIMEOUT_MAX, SEMGREP_RULE_TIMEOUT_DEFAULT),
  timeout_seconds: seconds(SEMGREP_PROCESS_TIMEOUT_MIN, SEMGREP_PROCESS_TIMEOUT_MAX, SEMGREP_PROCESS_TIMEOUT_DEFAULT),
});

// Deliberately has no field for the target URL or the API URL: their values never belong in the file.
const zapConfigSchema = z.strictObject({
  api_url_env: envName,
  api_key_env: envName,
  target_url_env: envName,
  allowed_target_origins: z.array(z.string()),
  session_mode: z.enum(['require_clean', 'reset']).default('require_clean'),
  active: z.literal(false).default(false),
  spider_timeout_seconds: seconds(ZAP_DEADLINE_MIN, ZAP_DEADLINE_MAX, ZAP_SPIDER_TIMEOUT_DEFAULT),
  passive_timeout_seconds: seconds(ZAP_DEADLINE_MIN, ZAP_DEADLINE_MAX, ZAP_PASSIVE_TIMEOUT_DEFAULT),
});

const rootSchema = z.strictObject({
  version: z.literal(1),
  redaction: redactionSchema,
  tools: z.strictObject({
    semgrep: z.strictObject({ enabled: z.boolean(), config: semgrepConfigSchema }),
    zap: z.strictObject({ enabled: z.boolean(), config: zapConfigSchema }),
  }),
});

/**
 * Reads and strictly validates `.pr-review/tools.yaml`. Rule files are resolved against `root`
 * and hashed here; the digest functions never read files.
 */
export function loadConfig(path: string, options: { root: string; env: Env }): LoadConfigResult {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return fail([{ path: 'file', message: 'configuration file cannot be read' }]);
  }

  const doc = parseDocument(text);
  if (doc.errors.length > 0) {
    const line = doc.errors[0]?.linePos?.[0]?.line;
    return fail([{ path: 'file', message: line === undefined ? 'YAML syntax error' : `YAML syntax error at line ${line}` }]);
  }
  let raw: unknown;
  try {
    raw = doc.toJS();
  } catch {
    return fail([{ path: 'file', message: 'YAML could not be parsed' }]);
  }

  const errors: ConfigError[] = [];
  findUserInfoUrls(raw, [], errors);

  const parsed = rootSchema.safeParse(raw);
  if (!parsed.success) {
    for (const issue of parsed.error.issues) {
      if (issue.code === 'unrecognized_keys') {
        for (const key of issue.keys) {
          const label = SAFE_KEY.test(key) ? `"${key}"` : '<non-standard key>';
          errors.push({ path: formatPath(issue.path), message: `unknown key ${label}` });
        }
      } else {
        errors.push({ path: formatPath(issue.path), message: issue.message });
      }
    }
    return fail(errors);
  }
  const data = parsed.data;

  // Redaction: names via the regex in the schema; values via the injected env (names only in messages).
  const redaction = {
    headers: uniqueSorted(data.redaction.headers),
    json_keys: uniqueSorted(data.redaction.json_keys),
    env_vars: uniqueSorted(data.redaction.env_vars),
  };
  try {
    buildPolicy(redaction, options.env);
  } catch (error) {
    if (!(error instanceof PolicyError)) throw error;
    errors.push({ path: 'redaction.env_vars', message: error.message });
  }

  const semgrep = data.tools.semgrep.config;
  const modes = [semgrep.rules !== undefined, semgrep.registry_ids !== undefined, semgrep.use_auto === true].filter(
    Boolean,
  ).length;
  if (modes !== 1) {
    errors.push({
      path: 'tools.semgrep.config',
      message: 'exactly one of rules, registry_ids or use_auto: true is required',
    });
  }
  let rules: SemgrepRules = { mode: 'auto' };
  if (semgrep.rules !== undefined) {
    const rootReal = realRoot(options.root);
    if (rootReal === null) return fail([{ path: 'root', message: 'repository root cannot be resolved' }]);
    const files: RuleFile[] = [];
    semgrep.rules.forEach((relPath, index) => {
      const resolved = resolveRuleFile(rootReal, relPath);
      if (resolved.ok) files.push(resolved.file);
      else errors.push({ path: `tools.semgrep.config.rules[${index}]`, message: resolved.message });
    });
    rules = { mode: 'local', files };
  } else if (semgrep.registry_ids !== undefined) {
    rules = { mode: 'registry', ids: uniqueSorted(semgrep.registry_ids) };
  }

  const zap = data.tools.zap.config;
  const origins: string[] = [];
  zap.allowed_target_origins.forEach((origin, index) => {
    try {
      origins.push(normalizeOrigin(origin));
    } catch {
      errors.push({
        path: `tools.zap.config.allowed_target_origins[${index}]`,
        message: 'must be a normalized http(s) origin (scheme://host[:port])',
      });
    }
  });

  if (errors.length > 0) return fail(errors);

  const config: Config = {
    version: 1,
    redaction,
    tools: {
      semgrep: {
        enabled: data.tools.semgrep.enabled,
        rules,
        ruleTimeoutSeconds: semgrep.rule_timeout_seconds,
        timeoutSeconds: semgrep.timeout_seconds,
      },
      zap: {
        enabled: data.tools.zap.enabled,
        apiUrlEnv: zap.api_url_env,
        apiKeyEnv: zap.api_key_env,
        targetUrlEnv: zap.target_url_env,
        allowedTargetOrigins: uniqueSorted(origins),
        sessionMode: zap.session_mode,
        active: zap.active,
        spiderTimeoutSeconds: zap.spider_timeout_seconds,
        passiveTimeoutSeconds: zap.passive_timeout_seconds,
      },
    },
  };
  return { ok: true, config };
}

function fail(errors: ConfigError[]): { ok: false; errors: ConfigError[] } {
  return { ok: false, errors };
}

function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}

function formatPath(path: readonly PropertyKey[]): string {
  if (path.length === 0) return 'root';
  return path.reduce<string>((acc, key) => {
    if (typeof key === 'number') return `${acc}[${key}]`;
    const name = String(key);
    return acc === '' ? name : `${acc}.${name}`;
  }, '');
}

function findUserInfoUrls(value: unknown, path: readonly PropertyKey[], errors: ConfigError[]): void {
  if (typeof value === 'string') {
    if (USER_INFO_URL.test(value)) {
      errors.push({ path: formatPath(path), message: 'URL with user information is not allowed' });
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => findUserInfoUrls(item, [...path, index], errors));
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) findUserInfoUrls(item, [...path, key], errors);
  }
}

function realRoot(root: string): string | null {
  try {
    return realpathSync(root);
  } catch {
    return null;
  }
}

type RuleFileResult = { ok: true; file: RuleFile } | { ok: false; message: string };

/** Repository-relative, existing, a regular file, and real path inside `rootReal` (symlinks resolved). */
function resolveRuleFile(rootReal: string, relPath: string): RuleFileResult {
  if (isAbsolute(relPath)) return { ok: false, message: 'rule path must be repository-relative' };
  let real: string;
  try {
    real = realpathSync(resolve(rootReal, relPath));
  } catch {
    return { ok: false, message: 'rule file does not exist' };
  }
  const inside = relative(rootReal, real);
  if (inside === '' || inside === '..' || inside.startsWith(`..${sep}`) || isAbsolute(inside)) {
    return { ok: false, message: 'rule path escapes the repository root' };
  }
  if (!statSync(real).isFile()) return { ok: false, message: 'rule path must be a file' };
  return { ok: true, file: { path: inside.split(sep).join('/'), sha256: sha256Hex(readFileSync(real)) } };
}
