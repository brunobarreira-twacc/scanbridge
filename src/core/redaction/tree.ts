import { RedactionError } from './errors.js';
import { bump, redactString, sortSummary, type Summary } from './patterns.js';
import type { Policy } from './policy.js';

export type RedactTreeOptions = { removePaths?: readonly string[] };
export type RedactTreeResult<T> = { value: T; summary: Summary; touched: string[] };

const BUILTIN_HEADERS = ['Authorization', 'Cookie', 'Set-Cookie', 'X-API-Key'];
const KEY_NAME = /token|password|secret/i;

type KeyRule = 'header' | 'json-key' | 'key-name';

type Ctx = {
  policy: Policy;
  headers: ReadonlySet<string>;
  jsonKeys: ReadonlySet<string>;
  summary: Summary;
  touched: string[];
};

/**
 * Redacts a parsed JSON tree. The input is never mutated; the result is a new tree.
 * Throws `RedactionError` on cyclic, non-JSON or otherwise unredactable input (fail closed).
 */
export function redactTree<T>(value: T, policy: Policy, opts: RedactTreeOptions = {}): RedactTreeResult<T> {
  try {
    assertJson(value, new Set());
    const ctx: Ctx = {
      policy,
      headers: new Set([...BUILTIN_HEADERS, ...policy.headers].map((name) => name.toLowerCase())),
      jsonKeys: new Set(policy.jsonKeys),
      summary: {},
      touched: [],
    };
    const patterns = (opts.removePaths ?? []).map((path) => path.split('.'));
    const out = walk(value, '', 0, patterns, ctx);
    return { value: out as T, summary: sortSummary(ctx.summary), touched: ctx.touched };
  } catch (err) {
    if (err instanceof RedactionError) throw err;
    // Includes stack exhaustion on deeply nested input: fail closed with a message that carries no data.
    throw new RedactionError('input could not be redacted safely');
  }
}

function assertJson(node: unknown, ancestors: Set<object>): void {
  if (node === null || typeof node === 'string' || typeof node === 'boolean') return;
  if (typeof node === 'number') {
    if (!Number.isFinite(node)) throw new RedactionError('non-finite number is not JSON');
    return;
  }
  if (typeof node !== 'object') throw new RedactionError(`value of type ${typeof node} is not JSON`);
  if (ancestors.has(node)) throw new RedactionError('cyclic structure is not JSON');
  if (!Array.isArray(node)) {
    const proto: unknown = Object.getPrototypeOf(node);
    if (proto !== Object.prototype && proto !== null) throw new RedactionError('non-plain object is not JSON');
  }
  ancestors.add(node);
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) {
      if (!(i in node)) throw new RedactionError('sparse array is not JSON');
      assertJson(node[i], ancestors);
    }
  } else {
    for (const key of Object.keys(node)) assertJson((node as Record<string, unknown>)[key], ancestors);
  }
  ancestors.delete(node);
}

function walk(node: unknown, pointer: string, depth: number, patterns: string[][], ctx: Ctx): unknown {
  if (typeof node === 'string') {
    const text = redactString(node, ctx.policy, ctx.summary);
    if (text !== node) ctx.touched.push(pointer);
    return text;
  }
  if (node === null || typeof node !== 'object') return node;

  if (Array.isArray(node)) {
    const out: unknown[] = [];
    let removed = false;
    for (let i = 0; i < node.length; i++) {
      const key = String(i);
      if (removes(key, depth, patterns)) {
        bump(ctx.summary, 'removed-path');
        removed = true;
        continue;
      }
      out.push(walk(node[i], `${pointer}/${key}`, depth + 1, childPatterns(key, depth, patterns), ctx));
    }
    if (removed) ctx.touched.push(pointer);
    return out;
  }

  const record = node as Record<string, unknown>;
  // A `{name, value}` pair whose name is a header name: the value is a header value.
  const isHeaderPair = typeof record.name === 'string' && ctx.headers.has(record.name.toLowerCase());
  const entries: [string, unknown][] = [];
  let removed = false;
  for (const key of Object.keys(record)) {
    const childPointer = `${pointer}/${escapePointer(key)}`;
    if (removes(key, depth, patterns)) {
      bump(ctx.summary, 'removed-path');
      removed = true;
      continue;
    }
    const rule = keyRule(key, ctx) ?? (isHeaderPair && key === 'value' ? 'header' : null);
    if (rule !== null) {
      bump(ctx.summary, rule);
      ctx.touched.push(childPointer);
      entries.push([key, `[REDACTED:${rule}]`]);
      continue;
    }
    entries.push([key, walk(record[key], childPointer, depth + 1, childPatterns(key, depth, patterns), ctx)]);
  }
  if (removed) ctx.touched.push(pointer);
  return Object.fromEntries(entries);
}

function keyRule(key: string, ctx: Ctx): KeyRule | null {
  if (ctx.headers.has(key.toLowerCase())) return 'header';
  if (ctx.jsonKeys.has(key)) return 'json-key';
  if (KEY_NAME.test(key)) return 'key-name';
  return null;
}

/** True when a configured path ends at this child. `*` matches any member at its depth. */
function removes(key: string, depth: number, patterns: readonly string[][]): boolean {
  return patterns.some((path) => path.length === depth + 1 && (path[depth] === '*' || path[depth] === key));
}

/** Paths that continue below this child. */
function childPatterns(key: string, depth: number, patterns: readonly string[][]): string[][] {
  return patterns.filter((path) => path.length > depth + 1 && (path[depth] === '*' || path[depth] === key));
}

function escapePointer(segment: string): string {
  return segment.replace(/~/g, '~0').replace(/\//g, '~1');
}
