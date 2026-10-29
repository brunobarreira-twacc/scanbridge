import type { ParseResult, SourceRef } from '../../contracts/adapter.js';
import type { JsonValue } from '../../contracts/enums.js';
import { asSonarQubeDocument } from './document.js';

export function parse(raw: Uint8Array): ParseResult {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder().decode(raw));
  } catch {
    return { ok: false, reason: 'invalid_json' };
  }
  if (asSonarQubeDocument(value as JsonValue) === null) return { ok: false, reason: 'unsupported_shape' };
  return { ok: true, doc: value as JsonValue };
}

/** SonarQube is an API-pull adapter; no local source files are read. */
export function sourceRefs(_doc: JsonValue): SourceRef[] {
  return [];
}
