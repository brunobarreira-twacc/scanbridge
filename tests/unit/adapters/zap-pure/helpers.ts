import assert from 'node:assert/strict';
import type { Candidate, NormalizeContext } from '../../../../src/contracts/adapter.js';
import type { SourceText } from '../../../../src/contracts/ports.js';

export const TARGET_ORIGIN = 'http://127.0.0.1:8080';

export const LIVE_CONTEXT: NormalizeContext = {
  mode: 'live',
  targetRel: '',
  targetOrigin: TARGET_ORIGIN,
  producerVersion: null,
  redactionTouched: new Set(),
  coverageLoss: [],
  scanDiagnostics: [],
  scanReasons: [],
};

export const NO_SOURCES: ReadonlyMap<string, SourceText> = new Map();

export function alert(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    pluginId: '10038',
    alertRef: '10038-1',
    name: 'Content Security Policy (CSP) Header Not Set',
    risk: 'Low',
    confidence: 'High',
    url: `${TARGET_ORIGIN}/`,
    method: 'GET',
    param: '',
    ...overrides,
  };
}

export function isPlain(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Candidate with the fields the fixtures and assertions read. Nested objects are compared as subsets. */
export function project(c: Candidate): Record<string, unknown> {
  return {
    ruleId: c.ruleId,
    producerReference: c.producerReference,
    title: c.title,
    description: c.description,
    confidence: c.confidence,
    references: c.references,
    severityOriginal: c.severityOriginal,
    severity: c.severity,
    redactionsApplied: c.redactionsApplied,
    url: c.location.runtime?.url,
    method: c.location.runtime?.method,
    param: c.location.runtime?.param,
    evidence: c.evidence,
  };
}

/** Every key in `expected` must match `actual`; keys absent from `expected` are not checked. */
export function assertMatches(actual: unknown, expected: unknown, at = '$'): void {
  if (isPlain(expected)) {
    assert.ok(isPlain(actual), `${at} should be an object`);
    for (const key of Object.keys(expected)) assertMatches(actual[key], expected[key], `${at}.${key}`);
    return;
  }
  assert.deepEqual(actual, expected, at);
}

/** Deterministic Fisher–Yates shuffle with a fixed-seed LCG. */
export function shuffled<T>(items: readonly T[], seed: number): T[] {
  const out = [...items];
  let state = seed;
  for (let i = out.length - 1; i > 0; i--) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    const j = state % (i + 1);
    [out[i], out[j]] = [out[j] as T, out[i] as T];
  }
  return out;
}
