import { createHash } from 'node:crypto';
import { BUILTIN_REDACTION_VERSION } from '../../contracts/enums.js';
import { PolicyError, RedactionError } from './errors.js';

export type PolicyInput = {
  headers: readonly string[];
  json_keys: readonly string[];
  env_vars: readonly string[];
};

export type Policy = {
  /** `<BUILTIN_REDACTION_VERSION>+<first 12 hex of sha256 over the canonical policy JSON>` */
  readonly version: string;
  /** Configured header names, sorted and deduplicated. */
  readonly headers: readonly string[];
  /** Configured JSON key names, sorted and deduplicated. */
  readonly jsonKeys: readonly string[];
  /** Configured environment variable names, sorted and deduplicated. Values are never exposed here. */
  readonly envVars: readonly string[];
};

export type EnvValue = { name: string; value: string };

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const ENV_VALUE_MIN_CHARS = 8;

// Env values live outside the Policy object so that a policy never serializes or inspects to a secret.
const ENV_VALUES = new WeakMap<Policy, readonly EnvValue[]>();

function sortedUnique(list: readonly string[]): string[] {
  return [...new Set(list)].sort();
}

export function buildPolicy(input: PolicyInput, env: Readonly<Record<string, string | undefined>>): Policy {
  const headers = sortedUnique(input.headers);
  const jsonKeys = sortedUnique(input.json_keys);
  const envVars = sortedUnique(input.env_vars);

  const values: EnvValue[] = [];
  for (const name of envVars) {
    if (!ENV_NAME.test(name)) {
      throw new PolicyError(`redaction env var "${name}" breaks the name rule ^[A-Za-z_][A-Za-z0-9_]{0,63}$`);
    }
    const value = env[name];
    if (typeof value !== 'string' || Array.from(value).length < ENV_VALUE_MIN_CHARS) {
      throw new PolicyError(`redaction env var "${name}" must be set to at least ${ENV_VALUE_MIN_CHARS} characters`);
    }
    values.push({ name, value });
  }
  // Longer values first so a value that contains another is replaced whole; ties by name.
  values.sort((a, b) => b.value.length - a.value.length || compare(a.name, b.name));

  const canonical = JSON.stringify({ headers, json_keys: jsonKeys, env_vars: envVars });
  const digest = createHash('sha256').update(canonical).digest('hex').slice(0, 12);

  const policy: Policy = Object.freeze({
    version: `${BUILTIN_REDACTION_VERSION}+${digest}`,
    headers: Object.freeze(headers),
    jsonKeys: Object.freeze(jsonKeys),
    envVars: Object.freeze(envVars),
  });
  ENV_VALUES.set(policy, Object.freeze(values));
  return policy;
}

/** Env values of a policy built by `buildPolicy`. A copied or hand-made policy fails closed. */
export function envValuesOf(policy: Policy): readonly EnvValue[] {
  const values = ENV_VALUES.get(policy);
  if (values === undefined) throw new RedactionError('redaction policy was not built by buildPolicy');
  return values;
}

function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
