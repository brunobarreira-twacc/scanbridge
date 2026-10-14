import type { ParseResult, SourceRef } from '../../contracts/adapter.js';
import type { JsonValue } from '../../contracts/enums.js';
import { asSemgrepDocument, sourceKey, usableResult } from './document.js';

export function parse(raw: Uint8Array): ParseResult {
  let doc: JsonValue;
  try {
    doc = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)) as JsonValue;
  } catch {
    return { ok: false, reason: 'invalid_json' };
  }
  return asSemgrepDocument(doc) ? { ok: true, doc } : { ok: false, reason: 'unsupported_shape' };
}

/** One ref per usable result. */
export function sourceRefs(doc: JsonValue): SourceRef[] {
  const semgrep = asSemgrepDocument(doc);
  if (!semgrep) return [];
  return semgrep.results.flatMap((entry) => {
    const result = usableResult(entry);
    if (!result) return [];
    const { path, start, end } = result;
    return [{ key: sourceKey(path, start.line, end.line), path, startLine: start.line, endLine: end.line }];
  });
}
