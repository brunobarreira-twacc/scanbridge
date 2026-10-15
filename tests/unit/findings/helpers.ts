import type { Candidate } from '../../../src/contracts/adapter.js';
import { buildFindings, type BuildFindingsResult } from '../../../src/core/findings/index.js';

export function semgrepCandidate(overrides: Partial<Candidate> = {}): Candidate {
  return {
    producer: 'semgrep',
    ruleId: 'rules.sql-injection',
    producerReference: null,
    producerFingerprint: null,
    title: 'rules.sql-injection',
    description: 'User input reaches a SQL query.',
    confidence: null,
    category: null,
    references: [],
    severityOriginal: 'ERROR',
    severity: 'high',
    location: { source: { path: 'src/db.ts', startLine: 42, startCol: 3, endLine: 42, endCol: 58 } },
    evidence: { producer_lines: 'db.query(...)' },
    snippet: { ok: true, text: 'db.query("SELECT * FROM t WHERE id=" + id)' },
    redactionsApplied: false,
    ...overrides,
  };
}

export function zapCandidate(overrides: Partial<Candidate> = {}): Candidate {
  return {
    producer: 'zap',
    ruleId: '10202',
    producerReference: '10202',
    producerFingerprint: null,
    title: 'Absence of Anti-CSRF Tokens',
    description: null,
    confidence: 'Low',
    category: null,
    references: [],
    severityOriginal: 'Medium',
    severity: 'medium',
    location: { runtime: { url: 'http://127.0.0.1:8080/login', method: 'POST', param: '' } },
    evidence: { attack: null, evidence: '<form action="/login">', message_id: '17' },
    redactionsApplied: false,
    ...overrides,
  };
}

export function buildSemgrep(candidates: Candidate[]): BuildFindingsResult {
  return buildFindings(candidates, { producer: 'semgrep' });
}

export function buildZap(candidates: Candidate[]): BuildFindingsResult {
  return buildFindings(candidates, { producer: 'zap' });
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
