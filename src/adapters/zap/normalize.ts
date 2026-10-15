import type { Candidate, NormalizeContext, NormalizeOutput, RawDiagnostic } from '../../contracts/adapter.js';
import type { Completeness, JsonValue, ScanReason } from '../../contracts/enums.js';
import { ZAP_MAPPING_VERSION } from '../../contracts/enums.js';
import type { SourceText } from '../../contracts/ports.js';
import { normalizeOrigin, normalizeUrl } from '../../core/fingerprints/index.js';
import { asAlertsDocument, isObject } from './parse.js';
import { mapSeverity } from './severity.js';

// ZAP alert field names and casing, centralized. [verify] V3: taken from ZAP source, not yet confirmed
// against a real alerts-API response.
const FIELDS = {
  pluginId: 'pluginId',
  alertRef: 'alertRef',
  name: 'name',
  alert: 'alert',
  description: 'description',
  risk: 'risk',
  confidence: 'confidence',
  url: 'url',
  method: 'method',
  param: 'param',
  attack: 'attack',
  evidence: 'evidence',
  other: 'other',
  inputVector: 'inputVector',
  messageId: 'messageId',
  reference: 'reference',
} as const;

/** One usable alert, read from `unknown`. Every field here takes part in dedup and sorting. */
type AlertRecord = {
  ruleId: string;
  producerReference: string | null;
  title: string;
  description: string | null;
  confidence: string | null;
  severityOriginal: string;
  url: string;
  method: string;
  param: string;
  references: string[];
  evidence: Record<string, string | null>;
};

type KeptAlert = { record: AlertRecord; redactionsApplied: boolean };

const ALERT_POINTER = /^\/alerts\/(\d+)(?:\/|$)/;

function text(value: JsonValue | undefined): string | null {
  return typeof value === 'string' ? value : null;
}

/** Null when `pluginId` or `url` is missing or not a string. */
function readAlert(entry: JsonValue): AlertRecord | null {
  if (!isObject(entry)) return null;
  const ruleId = text(entry[FIELDS.pluginId]);
  const url = text(entry[FIELDS.url]);
  if (ruleId === null || url === null) return null;
  const alertRef = text(entry[FIELDS.alertRef]);
  const title = text(entry[FIELDS.name]) ?? text(entry[FIELDS.alert]) ?? '';
  const reference = text(entry[FIELDS.reference]) ?? '';
  return {
    ruleId,
    producerReference: alertRef === null || alertRef === '' ? null : alertRef,
    title,
    description: text(entry[FIELDS.description]),
    confidence: text(entry[FIELDS.confidence]),
    severityOriginal: text(entry[FIELDS.risk]) ?? '',
    url,
    method: text(entry[FIELDS.method]) ?? '',
    param: text(entry[FIELDS.param]) ?? '',
    references: reference.split(/\s+/).filter((r) => r !== ''),
    evidence: {
      attack: text(entry[FIELDS.attack]),
      evidence: text(entry[FIELDS.evidence]),
      other: text(entry[FIELDS.other]),
      input_vector: text(entry[FIELDS.inputVector]),
      message_id: text(entry[FIELDS.messageId]),
    },
  };
}

/** Origin of an alert URL, or null when it cannot be parsed (including control characters). */
function originOf(url: string): string | null {
  try {
    return normalizeUrl(url).origin;
  } catch {
    return null;
  }
}

function dedupKey(record: AlertRecord): string {
  return JSON.stringify([
    record.ruleId,
    record.producerReference,
    record.title,
    record.description,
    record.confidence,
    record.severityOriginal,
    record.url,
    record.method,
    record.param,
    record.references,
    record.evidence,
  ]);
}

function toCandidate({ record, redactionsApplied }: KeptAlert): Candidate {
  return {
    producer: 'zap',
    ruleId: record.ruleId,
    producerReference: record.producerReference,
    producerFingerprint: null,
    title: record.title,
    description: record.description,
    confidence: record.confidence,
    category: null,
    references: record.references,
    severityOriginal: record.severityOriginal,
    severity: mapSeverity(record.severityOriginal),
    location: { runtime: { url: record.url, method: record.method, param: record.param } },
    evidence: record.evidence,
    redactionsApplied,
  };
}

function failedOutput(ctx: NormalizeContext): NormalizeOutput {
  return {
    candidates: [],
    unusableCount: 0,
    diagnostics: [{ code: 'malformed_report', level: 'error', tool: 'zap', message: 'ZAP document has an unsupported shape' }],
    coverageLoss: [],
    completeness: 'failed',
    reasons: offlineReasons(ctx),
    severityMappingVersion: ZAP_MAPPING_VERSION,
    producerVersion: ctx.producerVersion,
  };
}

function offlineReasons(ctx: NormalizeContext): ScanReason[] {
  return ctx.mode === 'offline' ? ['offline_report'] : [];
}

/** Ignores `sources`: ZAP has no source mapping. */
export function normalize(doc: JsonValue, ctx: NormalizeContext, _sources: ReadonlyMap<string, SourceText>): NormalizeOutput {
  const alerts = asAlertsDocument(doc);
  if (!alerts) return failedOutput(ctx);

  const touchedAlerts = new Set<number>();
  for (const pointer of ctx.redactionTouched) {
    const match = ALERT_POINTER.exec(pointer);
    if (match) touchedAlerts.add(Number(match[1]));
  }
  const origin = ctx.targetOrigin === null ? null : normalizeOrigin(ctx.targetOrigin);

  let unusableCount = 0;
  let outOfScopeCount = 0;
  const kept = new Map<string, KeptAlert>();
  alerts.forEach((entry, index) => {
    const record = readAlert(entry);
    if (!record) {
      unusableCount++;
      return;
    }
    if (origin !== null && originOf(record.url) !== origin) {
      outOfScopeCount++;
      return;
    }
    const redactionsApplied = touchedAlerts.has(index);
    const key = dedupKey(record);
    const existing = kept.get(key);
    if (existing) existing.redactionsApplied ||= redactionsApplied;
    else kept.set(key, { record, redactionsApplied });
  });

  const ordered = [...kept.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, alert]) => alert);
  const candidates = ordered.map(toCandidate);
  const unmappedSeverity = candidates.filter((c) => c.severity === 'unknown').length;

  const diagnostics: RawDiagnostic[] = [];
  if (unmappedSeverity > 0) {
    diagnostics.push({
      code: 'unmapped_severity',
      level: 'warn',
      tool: 'zap',
      message: `${unmappedSeverity} alerts have a risk outside the zap-1 table`,
    });
  }
  if (unusableCount > 0) {
    diagnostics.push({
      code: 'malformed_report',
      level: 'warn',
      tool: 'zap',
      message: `${unusableCount} alerts lack pluginId or url and were excluded`,
    });
  }
  if (outOfScopeCount > 0) {
    diagnostics.push({
      code: 'out_of_scope_target',
      level: 'warn',
      tool: 'zap',
      message: `${outOfScopeCount} alerts were excluded: outside the target origin or URL not origin-checkable`,
    });
  }

  const coverageLoss = [...ctx.coverageLoss];
  let completeness: Completeness;
  if (ctx.mode === 'offline') completeness = 'unverified';
  else if (coverageLoss.length > 0) completeness = 'partial';
  else completeness = 'complete';

  return {
    candidates,
    unusableCount,
    diagnostics,
    coverageLoss,
    completeness,
    reasons: offlineReasons(ctx),
    severityMappingVersion: ZAP_MAPPING_VERSION,
    producerVersion: ctx.producerVersion,
  };
}
