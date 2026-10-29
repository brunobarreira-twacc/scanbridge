import type { Severity } from '../../contracts/enums.js';

const MAP: ReadonlyMap<string, Severity> = new Map([
  ['BLOCKER', 'critical'],
  ['HIGH', 'high'],
  ['MEDIUM', 'medium'],
  ['LOW', 'low'],
  ['INFO', 'info'],
]);

export function mapSeverity(raw: string): Severity {
  return MAP.get(raw) ?? 'unknown';
}
