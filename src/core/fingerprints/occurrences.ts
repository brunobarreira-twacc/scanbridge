// Canonical occurrence order (spec 04). Only the fields that order occurrences
// are declared here; callers pass their own occurrence objects.

export interface SourceLocationKey {
  path: string;
  start_line: number;
  start_col: number;
  end_line: number;
  end_col: number;
}

export interface RuntimeLocationKey {
  url: string;
  method: string;
  param: string;
}

export interface OccurrenceOrderInput {
  source_location?: SourceLocationKey | null;
  runtime_location?: RuntimeLocationKey | null;
  evidence?: {
    attack?: string | null;
    evidence?: { text: string } | null;
    message_id?: string | null;
  } | null;
}

/**
 * Total preorder over occurrences. Source-location occurrences come first, then
 * runtime occurrences, then any with neither. Source locations compare by
 * (path, start_line, start_col, end_line, end_col). Runtime occurrences compare by
 * (url, method, param, attack, evidence, message_id), with `null` first and
 * code-point string comparison.
 */
export function compareOccurrences(a: OccurrenceOrderInput, b: OccurrenceOrderInput): number {
  const rankDiff = occurrenceRank(a) - occurrenceRank(b);
  if (rankDiff !== 0) return rankDiff;

  if (a.source_location && b.source_location) {
    const x = a.source_location;
    const y = b.source_location;
    return (
      compareCodePoints(x.path, y.path) ||
      x.start_line - y.start_line ||
      x.start_col - y.start_col ||
      x.end_line - y.end_line ||
      x.end_col - y.end_col
    );
  }

  if (a.runtime_location && b.runtime_location) {
    const x = a.runtime_location;
    const y = b.runtime_location;
    return (
      compareCodePoints(x.url, y.url) ||
      compareCodePoints(x.method, y.method) ||
      compareCodePoints(x.param, y.param) ||
      compareNullable(a.evidence?.attack, b.evidence?.attack) ||
      compareNullable(a.evidence?.evidence?.text, b.evidence?.evidence?.text) ||
      compareNullable(a.evidence?.message_id, b.evidence?.message_id)
    );
  }

  return 0;
}

function occurrenceRank(o: OccurrenceOrderInput): number {
  if (o.source_location) return 0;
  if (o.runtime_location) return 1;
  return 2;
}

function compareNullable(a: string | null | undefined, b: string | null | undefined): number {
  if (a == null || b == null) return (a == null ? 0 : 1) - (b == null ? 0 : 1);
  return compareCodePoints(a, b);
}

/** Compares strings by Unicode code point, not by UTF-16 code unit. */
export function compareCodePoints(a: string, b: string): number {
  const x = [...a];
  const y = [...b];
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const cx = x[i]?.codePointAt(0) ?? 0;
    const cy = y[i]?.codePointAt(0) ?? 0;
    if (cx !== cy) return cx < cy ? -1 : 1;
  }
  return x.length - y.length;
}
