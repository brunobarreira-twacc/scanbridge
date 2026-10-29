import type { JsonValue } from '../../contracts/enums.js';

export type ImpactEntry = { softwareQuality: string; severity: string };

export type UsableIssue = {
  key: string;
  rule: string;
  component: string;
  type: string;
  message: string;
  impacts: ImpactEntry[];
  hash: string | null;
  line: number | null;
  textRange: { startLine: number; startOffset: number; endLine: number; endOffset: number } | null;
};

export type SonarQubeDocument = {
  issues: JsonValue[];
  total: number;
  projectKey: string;
};

export function asSonarQubeDocument(value: JsonValue): SonarQubeDocument | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const { issues, total, projectKey } = value as Record<string, JsonValue>;
  if (!Array.isArray(issues)) return null;
  if (typeof total !== 'number') return null;
  if (typeof projectKey !== 'string') return null;
  return { issues, total, projectKey };
}

export function asUsableIssue(value: JsonValue): UsableIssue | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const v = value as Record<string, JsonValue>;

  const key = v['key'];
  const rule = v['rule'];
  const component = v['component'];
  const type = v['type'];
  const message = v['message'];
  const rawImpacts = v['impacts'];

  if (typeof key !== 'string' || key === '') return null;
  if (typeof rule !== 'string' || rule === '') return null;
  if (typeof component !== 'string' || component === '') return null;
  if (typeof type !== 'string' || type === '') return null;
  if (typeof message !== 'string' || message === '') return null;
  if (!Array.isArray(rawImpacts) || rawImpacts.length === 0) return null;

  const impacts: ImpactEntry[] = [];
  for (const entry of rawImpacts) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue;
    const e = entry as Record<string, JsonValue>;
    if (typeof e['softwareQuality'] !== 'string' || typeof e['severity'] !== 'string') continue;
    impacts.push({ softwareQuality: e['softwareQuality'] as string, severity: e['severity'] as string });
  }
  if (impacts.length === 0) return null;

  const rawHash = v['hash'];
  const hash = typeof rawHash === 'string' && rawHash !== '' ? rawHash : null;

  const rawLine = v['line'];
  const line = typeof rawLine === 'number' && Number.isInteger(rawLine) ? rawLine : null;

  let textRange: UsableIssue['textRange'] = null;
  const tr = v['textRange'];
  if (typeof tr === 'object' && tr !== null && !Array.isArray(tr)) {
    const t = tr as Record<string, JsonValue>;
    const sl = t['startLine'];
    const so = t['startOffset'];
    const el = t['endLine'];
    const eo = t['endOffset'];
    if (
      typeof sl === 'number' && Number.isInteger(sl) &&
      typeof so === 'number' && Number.isInteger(so) &&
      typeof el === 'number' && Number.isInteger(el) &&
      typeof eo === 'number' && Number.isInteger(eo)
    ) {
      textRange = { startLine: sl, startOffset: so, endLine: el, endOffset: eo };
    }
  }

  return { key, rule, component, type, message, impacts, hash, line, textRange };
}
