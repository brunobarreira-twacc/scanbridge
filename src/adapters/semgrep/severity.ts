import type { JsonValue, Severity } from '../../contracts/enums.js';

/** `semgrep-1`: exact, case-sensitive. Anything else is `unknown`. */
const SEMGREP_1 = new Map<string, Severity>([
  ['CRITICAL', 'critical'],
  ['HIGH', 'high'],
  ['ERROR', 'high'],
  ['MEDIUM', 'medium'],
  ['WARNING', 'medium'],
  ['LOW', 'low'],
  ['INFO', 'info'],
  ['EXPERIMENT', 'info'],
  ['INVENTORY', 'info'],
]);

export function mapSeverity(original: JsonValue | undefined): Severity {
  return (typeof original === 'string' ? SEMGREP_1.get(original) : undefined) ?? 'unknown';
}
