import { RedactionError } from './errors.js';
import { envValuesOf, type Policy } from './policy.js';

export type Summary = Record<string, number>;

type ValueRule = {
  id: string;
  pattern: RegExp;
  /** Leading capture groups kept verbatim; the rest of the match is replaced. */
  keep: number;
};

// Fixed value-pattern table, BUILTIN_REDACTION_VERSION = "1". Copied verbatim from T03.
// Changing any pattern or id requires a version bump in T01, never here.
// [verify] V8: the set is not claimed sufficient. The provider set (rules 3–10) is bounded at 8 and
// must not grow to a ninth provider format.

// 1 `private-key`
const RULE_1 = /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]{0,16384}?(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|$)/;
// 2 `bearer`
const RULE_2 = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,512}/gi;
// 3 `provider-github-token`
const RULE_3 = /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/;
// 4 `provider-github-pat`
const RULE_4 = /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/;
// 5 `provider-gitlab-pat`
const RULE_5 = /\bglpat-[A-Za-z0-9_-]{20,50}/;
// 6 `provider-aws-access-key-id`
const RULE_6 = /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/;
// 7 `provider-slack-token`
const RULE_7 = /\bxox[abprs]-[A-Za-z0-9-]{10,200}/;
// 8 `provider-google-api-key`
const RULE_8 = /\bAIza[0-9A-Za-z_-]{35}/;
// 9 `provider-stripe-key`
const RULE_9 = /\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,99}\b/;
// 10 `provider-npm-token`
const RULE_10 = /\bnpm_[A-Za-z0-9]{36}\b/;
// 11 `assignment`: only the value (group 3) is replaced; name and separator are kept.
const RULE_11 = /\b([A-Za-z0-9_.-]{0,64}(?:token|password|secret|api_key|apikey)[A-Za-z0-9_.-]{0,64})(\s{0,8}[:=]\s{0,8})("[^"\r\n]{1,512}"|'[^'\r\n]{1,512}'|[^\s"'&;,]{1,512})/gi;

const VALUE_RULES: readonly ValueRule[] = [
  { id: 'private-key', pattern: RULE_1, keep: 0 },
  { id: 'bearer', pattern: RULE_2, keep: 0 },
  { id: 'provider-github-token', pattern: RULE_3, keep: 0 },
  { id: 'provider-github-pat', pattern: RULE_4, keep: 0 },
  { id: 'provider-gitlab-pat', pattern: RULE_5, keep: 0 },
  { id: 'provider-aws-access-key-id', pattern: RULE_6, keep: 0 },
  { id: 'provider-slack-token', pattern: RULE_7, keep: 0 },
  { id: 'provider-google-api-key', pattern: RULE_8, keep: 0 },
  { id: 'provider-stripe-key', pattern: RULE_9, keep: 0 },
  { id: 'provider-npm-token', pattern: RULE_10, keep: 0 },
  { id: 'assignment', pattern: RULE_11, keep: 2 },
].map((rule) => ({ ...rule, pattern: withGlobal(rule.pattern) }));

/** The 12 value-rule ids in application order; `env:<NAME>` is the placeholder for rule 12. */
export const VALUE_RULE_IDS: readonly string[] = [...VALUE_RULES.map((rule) => rule.id), 'env:<NAME>'];

function withGlobal(re: RegExp): RegExp {
  return re.global ? re : new RegExp(re.source, `${re.flags}g`);
}

export function bump(summary: Summary, id: string, count = 1): void {
  summary[id] = (summary[id] ?? 0) + count;
}

export function sortSummary(summary: Summary): Summary {
  return Object.fromEntries(Object.entries(summary).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

function applyRule(text: string, rule: ValueRule, summary: Summary): string {
  const token = `[REDACTED:${rule.id}]`;
  return text.replace(rule.pattern, (_match: string, ...groups: unknown[]) => {
    bump(summary, rule.id);
    return groups.slice(0, rule.keep).join('') + token;
  });
}

/** Value patterns first, then exact env values (longest first). Pure and linear per rule. */
export function redactString(text: string, policy: Policy, summary: Summary): string {
  let out = text;
  for (const rule of VALUE_RULES) out = applyRule(out, rule, summary);
  for (const { name, value } of envValuesOf(policy)) {
    const parts = out.split(value);
    if (parts.length === 1) continue;
    bump(summary, `env:${name}`, parts.length - 1);
    out = parts.join(`[REDACTED:env:${name}]`);
  }
  return out;
}

/** Redacts a source snippet. Key and header rules do not apply to plain text. */
export function redactText(text: string, policy: Policy): { text: string; summary: Summary } {
  if (typeof text !== 'string') throw new RedactionError('redactText expects a string');
  const summary: Summary = {};
  const redacted = redactString(text, policy, summary);
  return { text: redacted, summary: sortSummary(summary) };
}
