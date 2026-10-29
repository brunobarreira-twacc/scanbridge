import { BUILTIN_REDACTION_VERSION } from '../contracts/enums.js';
import { canonicalJson, sha256Hex, type CanonicalJson } from '../core/fingerprints/index.js';
import type { PolicyInput } from '../core/redaction/index.js';
import type { Config, RuleFile } from './types.js';

/**
 * Digest of the rule set. `null` for registry and auto modes (pass `null`).
 * [verify] V7: a resolved-rule digest for registry/auto is not derived; `null` stays until verified.
 */
export function rulesDigest(ruleFiles: readonly RuleFile[] | null): string | null {
  if (ruleFiles === null) return null;
  return sha256Hex(canonicalJson(rulePairs(ruleFiles)));
}

/**
 * SHA-256 over the canonical validated section for `tool`, the effective redaction policy (built-in
 * version plus config additions, names only) and the sorted `(path, SHA-256)` pairs of local rule files.
 * Environment values and the API key never enter this digest.
 */
export function configurationDigest(input: {
  tool: 'semgrep' | 'zap' | 'sonarqube';
  config: Config;
  redactionPolicyInput: PolicyInput;
  ruleFiles: readonly RuleFile[];
}): string {
  const { tool, config, redactionPolicyInput, ruleFiles } = input;
  const section = tool === 'semgrep' ? semgrepSection(config) : tool === 'zap' ? zapSection(config) : sonarqubeSection(config);
  const redaction = {
    builtin: BUILTIN_REDACTION_VERSION,
    headers: [...redactionPolicyInput.headers],
    json_keys: [...redactionPolicyInput.json_keys],
    env_vars: [...redactionPolicyInput.env_vars],
  };
  return sha256Hex(canonicalJson({ tool, config: section, redaction, rules: rulePairs(ruleFiles) }));
}

function rulePairs(ruleFiles: readonly RuleFile[]): CanonicalJson[] {
  return [...ruleFiles]
    .sort((a, b) => compare(a.path, b.path) || compare(a.sha256, b.sha256))
    .map((file) => [file.path, file.sha256]);
}

function semgrepSection(config: Config): CanonicalJson {
  const semgrep = config.tools.semgrep;
  const rules: CanonicalJson =
    semgrep.rules.mode === 'local'
      ? { mode: 'local', paths: semgrep.rules.files.map((file) => file.path) }
      : semgrep.rules.mode === 'registry'
        ? { mode: 'registry', ids: [...semgrep.rules.ids] }
        : { mode: 'auto' };
  return {
    enabled: semgrep.enabled,
    rules,
    rule_timeout_seconds: semgrep.ruleTimeoutSeconds,
    timeout_seconds: semgrep.timeoutSeconds,
  };
}

function zapSection(config: Config): CanonicalJson {
  const zap = config.tools.zap;
  return {
    enabled: zap.enabled,
    api_url_env: zap.apiUrlEnv,
    api_key_env: zap.apiKeyEnv,
    target_url_env: zap.targetUrlEnv,
    allowed_target_origins: [...zap.allowedTargetOrigins],
    session_mode: zap.sessionMode,
    active: zap.active,
    spider_timeout_seconds: zap.spiderTimeoutSeconds,
    passive_timeout_seconds: zap.passiveTimeoutSeconds,
  };
}

function sonarqubeSection(config: Config): CanonicalJson {
  const sq = config.tools.sonarqube;
  return {
    enabled: sq.enabled,
    api_url_env: sq.apiUrlEnv,
    api_key_env: sq.apiKeyEnv,
    project_key_env: sq.projectKeyEnv,
    timeout_seconds: sq.timeoutSeconds,
  };
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
