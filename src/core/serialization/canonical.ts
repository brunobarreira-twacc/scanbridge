import { compareCodePoints, compareOccurrences, type OccurrenceOrderInput } from '../fingerprints/occurrences.js';
import { LAYOUT, type Layout, type Rule } from './layout.js';

/**
 * Canonical bytes for a value of a named object type (a key of `OBJECT_TYPES`): objects are
 * rebuilt in declared order, arrays are sorted by their rule, 2-space indent, LF, one trailing
 * newline. Throws on undeclared keys and non-integer numbers instead of guessing.
 */
export function serializeCanonical(typeName: string, value: unknown): string {
  return `${JSON.stringify(canonicalObject(typeName, value, '$'), null, 2)}\n`;
}

function canonicalObject(typeName: string, value: unknown, path: string): Record<string, unknown> {
  const layout: Layout | undefined = Object.hasOwn(LAYOUT, typeName) ? LAYOUT[typeName] : undefined;
  if (!layout) throw new TypeError(`serializeCanonical: unknown object type ${typeName}`);
  const input = plainObject(value, path);
  for (const key of Object.keys(input)) {
    if (!Object.hasOwn(layout, key)) throw new TypeError(`${path}: field "${key}" is not declared for ${typeName}`);
  }
  const entries: [string, unknown][] = [];
  for (const [key, rule] of Object.entries(layout)) {
    const field = input[key];
    if (field === undefined) continue;
    entries.push([key, canonicalValue(rule, field, `${path}.${key}`)]);
  }
  return Object.fromEntries(entries);
}

function canonicalValue(rule: Rule, value: unknown, path: string): unknown {
  if (value === null) return null;
  switch (rule.kind) {
    case 'scalar':
      return scalar(value, path);
    case 'object':
      return canonicalObject(rule.type, value, path);
    case 'union': {
      const tag = plainObject(value, path)[rule.by];
      const type = typeof tag === 'string' && Object.hasOwn(rule.members, tag) ? rule.members[tag] : undefined;
      if (!type) throw new TypeError(`${path}: unknown ${rule.by} ${String(tag)}`);
      return canonicalObject(type, value, path);
    }
    case 'items': {
      const list = array(value, path).map((item, i) => canonicalObject(rule.type, item, `${path}[${i}]`));
      if (rule.sort === 'fingerprint') list.sort((a, b) => compareCodePoints(String(a.fingerprint), String(b.fingerprint)));
      if (rule.sort === 'occurrence') list.sort((a, b) => compareOccurrences(occurrenceOrderInput(a), occurrenceOrderInput(b)));
      return list;
    }
    case 'strings':
      return strings(value, rule.order, path);
    case 'counts':
      return counts(value, path);
  }
}

function scalar(value: unknown, path: string): string | boolean | number {
  if (typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  throw new TypeError(`${path}: expected a string, boolean, null or safe integer`);
}

function strings(value: unknown, order: 'ordered' | 'set' | 'multiset', path: string): string[] {
  const list = array(value, path).map((item, i) => {
    if (typeof item !== 'string') throw new TypeError(`${path}[${i}]: expected a string`);
    return item;
  });
  if (order === 'ordered') return list;
  const sorted = list.sort(compareCodePoints);
  if (order === 'multiset') return sorted;
  return sorted.filter((item, i) => i === 0 || item !== sorted[i - 1]);
}

/** Record of counts keyed by rule id: keys in code-point order. */
function counts(value: unknown, path: string): Record<string, number> {
  const record = plainObject(value, path);
  const keys = Object.keys(record).sort(compareCodePoints);
  return Object.fromEntries(
    keys.map((key) => {
      // Integer-like keys are reordered by the JS engine, which would break the declared order.
      if (/^(?:0|[1-9][0-9]*)$/.test(key)) throw new TypeError(`${path}: count key "${key}" is an array index`);
      const count = record[key];
      if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 0) {
        throw new TypeError(`${path}.${key}: expected a non-negative safe integer`);
      }
      return [key, count];
    }),
  );
}

/**
 * Maps a canonical occurrence to the comparator's input. `evidence.attack` is a text field here
 * but a plain string in `OccurrenceOrderInput` (see spec 04 ordering keys), so its text is used.
 */
function occurrenceOrderInput(occurrence: Record<string, unknown>): OccurrenceOrderInput {
  const evidence = (occurrence.evidence ?? {}) as {
    attack?: { text: string } | null;
    evidence?: { text: string } | null;
    message_id?: string | null;
  };
  return {
    source_location: (occurrence.source_location ?? null) as OccurrenceOrderInput['source_location'],
    runtime_location: (occurrence.runtime_location ?? null) as OccurrenceOrderInput['runtime_location'],
    evidence: {
      attack: evidence.attack?.text ?? null,
      evidence: evidence.evidence ?? null,
      message_id: evidence.message_id ?? null,
    },
  };
}

function plainObject(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`${path}: expected an object`);
  }
  return value as Record<string, unknown>;
}

function array(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) throw new TypeError(`${path}: expected an array`);
  return value;
}
