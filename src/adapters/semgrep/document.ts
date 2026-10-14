import type { JsonValue } from '../../contracts/enums.js';

export type JsonObject = { [key: string]: JsonValue };

export type SemgrepDocument = {
  results: JsonValue[];
  errors: JsonValue[];
  paths: { scanned: JsonValue[] };
  version: JsonValue | undefined;
};

export type Position = { line: number; col: number };

export type UsableResult = {
  ruleId: string;
  path: string;
  start: Position;
  end: Position;
  extra: JsonObject;
};

export function isObject(value: JsonValue | undefined): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Typed view when the document has the shape `parse` requires; null otherwise. `paths.scanned` may be absent. */
export function asSemgrepDocument(doc: JsonValue): SemgrepDocument | null {
  if (!isObject(doc)) return null;
  const { results, errors, paths, version } = doc;
  if (!Array.isArray(results) || !Array.isArray(errors) || !isObject(paths)) return null;
  const scanned = paths.scanned;
  let scannedList: JsonValue[];
  if (scanned === undefined) scannedList = [];
  else if (Array.isArray(scanned)) scannedList = scanned;
  else return null;
  return { results, errors, paths: { scanned: scannedList }, version };
}

/** Repository-root-relative POSIX path. Semgrep reports paths relative to the scan cwd, which is the root. */
export function toRootRelative(path: string): string {
  return path.replace(/^(?:\.\/)+/, '');
}

export function sourceKey(path: string, startLine: number, endLine: number): string {
  return `${path}:${startLine}:${endLine}`;
}

function position(value: JsonValue | undefined): Position | null {
  if (!isObject(value)) return null;
  const { line, col } = value;
  return typeof line === 'number' && Number.isInteger(line) && typeof col === 'number' && Number.isInteger(col)
    ? { line, col }
    : null;
}

/** An entry is usable when `check_id`, `path`, `start` and `end` are present and well-formed; `offset` is ignored. */
export function usableResult(entry: JsonValue): UsableResult | null {
  if (!isObject(entry)) return null;
  const { check_id: ruleId, path } = entry;
  if (typeof ruleId !== 'string' || typeof path !== 'string') return null;
  const start = position(entry.start);
  const end = position(entry.end);
  if (!start || !end) return null;
  return {
    ruleId,
    path: toRootRelative(path),
    start,
    end,
    extra: isObject(entry.extra) ? entry.extra : {},
  };
}
