import type { RawDiagnostic } from '../../contracts/adapter.js';
import type { JsonValue } from '../../contracts/enums.js';
import { isObject } from './document.js';

// Completeness classification for `errors[]` (spec 05, Semgrep completeness table).
const COVERAGE_LOSS = new Set([
  'Timeout',
  'Lexical error',
  'Syntax error',
  'Other syntax error',
  'AST builder error',
  'PartialParsing',
  'Out of memory',
  'Stack overflow',
  'Fixpoint timeout',
  'Timeout during interfile analysis',
  'OOM during interfile analysis',
  'Too many matches',
]);
const RULE_PROBLEM = new Set([
  'Rule parse error',
  'InvalidRuleSchemaError',
  'Incompatible rule',
  'Pattern parse error',
  'Missing plugin',
]);
const INTERNAL = new Set(['Internal matching error', 'Fatal error']);
const DIAGNOSTIC_ONLY = new Set(['SemgrepWarning']);

type ErrorClass = 'coverage' | 'rule' | 'unmapped' | 'internal' | 'info';

// When a list-encoded type mixes classes, the strongest one decides the entry. [verify] V2: wire format unverified.
const RANK: Record<ErrorClass, number> = { info: 0, internal: 1, unmapped: 2, rule: 3, coverage: 4 };

function classifyType(type: string, level: JsonValue | undefined): ErrorClass {
  if (COVERAGE_LOSS.has(type)) return 'coverage';
  if (RULE_PROBLEM.has(type)) return 'rule';
  if (INTERNAL.has(type)) return 'internal';
  if (level === 'info' || DIAGNOSTIC_ONLY.has(type)) return 'info';
  return 'unmapped';
}

function classifyEntry(entry: JsonValue): { cls: ErrorClass; detail: string | undefined } {
  if (!isObject(entry)) return { cls: 'unmapped', detail: undefined };
  const { type, level, message } = entry;
  const detail = typeof message === 'string' ? message : undefined;
  if (typeof type === 'string') return { cls: classifyType(type, level), detail };
  if (Array.isArray(type) && type.length > 0) {
    const classes = type.map((t) => (typeof t === 'string' ? classifyType(t, level) : 'unmapped'));
    const cls = classes.reduce((a, b) => (RANK[b] > RANK[a] ? b : a));
    return { cls, detail };
  }
  return { cls: 'unmapped', detail };
}

export type ErrorOutcome = {
  coverageLoss: RawDiagnostic[];
  diagnostics: RawDiagnostic[];
  failed: boolean;
};

/**
 * `findings` and `scannedFiles` decide whether an internal error leaves the scan partial or failed.
 * Intentional exclusions are never read here, so they never make a scan partial. [verify] V6.
 */
export function classifyErrors(
  entries: readonly JsonValue[],
  evidence: { findings: boolean; scannedFiles: boolean },
): ErrorOutcome {
  const coverageLoss: RawDiagnostic[] = [];
  const diagnostics: RawDiagnostic[] = [];
  let failed = false;
  const internalPartial = evidence.findings && evidence.scannedFiles;
  for (const entry of entries) {
    const { cls, detail } = classifyEntry(entry);
    const withDetail = (d: RawDiagnostic): RawDiagnostic => (detail === undefined ? d : { ...d, detail });
    switch (cls) {
      case 'coverage':
        coverageLoss.push(withDetail({ code: 'partial_coverage', level: 'warn', tool: 'semgrep', message: 'Semgrep reported lost coverage during matching' }));
        break;
      case 'rule':
        coverageLoss.push(withDetail({ code: 'partial_coverage', level: 'warn', tool: 'semgrep', message: 'A Semgrep rule did not run; other rules still ran' }));
        break;
      case 'unmapped':
        coverageLoss.push(withDetail({ code: 'unmapped_error_type', level: 'warn', tool: 'semgrep', message: 'Semgrep reported an error type Scanbridge does not classify' }));
        break;
      case 'internal':
        if (internalPartial) {
          coverageLoss.push(withDetail({ code: 'partial_coverage', level: 'warn', tool: 'semgrep', message: 'Semgrep reported an internal error after producing findings' }));
        } else {
          failed = true;
          diagnostics.push(withDetail({ code: 'tool_execution_failed', level: 'error', tool: 'semgrep', message: 'Semgrep reported an internal error without usable evidence' }));
        }
        break;
      case 'info':
        // Informational entries need a diagnostic code that spec 04 does not define; not surfaced yet.
        break;
    }
  }
  return { coverageLoss, diagnostics, failed };
}
