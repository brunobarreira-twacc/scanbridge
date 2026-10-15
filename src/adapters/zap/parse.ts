import type { ParseResult, SourceRef } from '../../contracts/adapter.js';
import type { JsonValue } from '../../contracts/enums.js';

export type JsonObject = { [key: string]: JsonValue };

export function isObject(value: JsonValue | undefined): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The alerts-API dump is exactly `{"alerts":[...]}`; any other key (e.g. a Traditional report's `site`) is rejected. */
export function asAlertsDocument(doc: JsonValue): JsonValue[] | null {
  if (!isObject(doc) || Object.keys(doc).length !== 1) return null;
  const { alerts } = doc;
  return Array.isArray(alerts) ? alerts : null;
}

export function parse(raw: Uint8Array): ParseResult {
  let doc: JsonValue;
  try {
    doc = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)) as JsonValue;
  } catch {
    return { ok: false, reason: 'invalid_json' };
  }
  return asAlertsDocument(doc) ? { ok: true, doc } : { ok: false, reason: 'unsupported_shape' };
}

/** ZAP has no source mapping: no line ranges are ever needed. */
export function sourceRefs(_doc: JsonValue): SourceRef[] {
  return [];
}
