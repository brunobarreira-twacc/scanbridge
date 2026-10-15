import type { JsonValue, Severity } from '../../contracts/enums.js';

/** `zap-1`: exact, case-sensitive. Anything else is `unknown`. [verify] V3: risk strings on real ZAP. */
const ZAP_1 = new Map<string, Severity>([
  ['Informational', 'info'],
  ['Low', 'low'],
  ['Medium', 'medium'],
  ['High', 'high'],
]);

export function mapSeverity(original: JsonValue | undefined): Severity {
  return (typeof original === 'string' ? ZAP_1.get(original) : undefined) ?? 'unknown';
}
