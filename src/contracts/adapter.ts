import type { Completeness, DiagnosticCode, JsonValue, ScanReason, Severity } from './enums.js';
import type { Clock, HttpClient, Runner, SourceFailure, SourceText } from './ports.js';
import type { SensitiveString } from './sensitive.js';

export type RuleSource =
  | { mode: 'local'; ruleFiles: readonly string[] }
  | { mode: 'registry'; ids: readonly string[] }
  | { mode: 'auto' };

// Probe contexts carry only what a readiness check needs; scan contexts carry what a scan needs.
export type SemgrepProbeContext = { producer: 'semgrep' };
export type ZapProbeContext = { producer: 'zap'; apiUrl: string; apiKey: SensitiveString };

export type SemgrepScanContext = {
  producer: 'semgrep';
  rootAbs: string;
  targetRel: string;
  rules: RuleSource;
  ruleTimeoutSeconds: number;
  timeoutSeconds: number;
  excludeRelToTarget: string | null;
};

export type ZapLiveScanContext = {
  producer: 'zap';
  mode: 'live';
  scanId: string;
  targetOrigin: string;
  apiUrl: string;
  apiKey: SensitiveString;
  sessionMode: 'require_clean' | 'reset';
  spiderTimeoutSeconds: number;
  passiveTimeoutSeconds: number;
};
// Offline ZAP has no probe or scan context: the orchestrator calls neither `probe` nor `scan`.

export type Deps = { runner: Runner; http: HttpClient; clock: Clock };

/** `detail` is untrusted and unsanitized. */
export type RawDiagnostic = {
  code: DiagnosticCode;
  level: 'info' | 'warn' | 'error';
  tool?: string;
  message: string;
  detail?: string;
};

export type ProbeResult = {
  status: 'ready' | 'unavailable';
  version: string | null;
  diagnostics: RawDiagnostic[];
};

export type ParseResult = { ok: true; doc: JsonValue } | { ok: false; reason: 'invalid_json' | 'unsupported_shape' };

export type ScanOutput = {
  outcome: 'ok' | 'failed' | 'unavailable';
  raw: Uint8Array | null;
  /** Operational: non_deterministic_rules, tool_timeout (when failed), bad_api_key, ... */
  diagnostics: RawDiagnostic[];
  /** Concrete coverage loss seen while scanning: makes the scan partial. */
  coverageLoss: RawDiagnostic[];
  /** Scan-level non-authoritative reasons known at scan time (registry_rules, auto_rules). */
  reasons: ScanReason[];
};

export type NormalizeContext = {
  mode: 'live' | 'offline';
  targetRel: string;
  targetOrigin: string | null;
  producerVersion: string | null;
  /** RFC 6901 pointers. */
  redactionTouched: ReadonlySet<string>;
  coverageLoss: readonly RawDiagnostic[];
  scanDiagnostics: readonly RawDiagnostic[];
  scanReasons: readonly ScanReason[];
};

export type SourceRef = { key: string; path: string; startLine: number; endLine: number };

export type Candidate = {
  producer: 'semgrep' | 'zap';
  ruleId: string;
  producerReference: string | null;
  producerFingerprint: string | null;
  title: string;
  description: string | null;
  confidence: string | null;
  category: string | null;
  references: string[];
  severityOriginal: string;
  severity: Severity;
  location: {
    source?: { path: string; startLine: number; startCol: number; endLine: number; endCol: number };
    runtime?: { url: string; method: string; param: string };
  };
  evidence: Record<string, string | null>;
  snippet?: { ok: true; text: string } | { ok: false; reason: SourceFailure };
  redactionsApplied: boolean;
};

export type NormalizeOutput = {
  candidates: Candidate[];
  unusableCount: number;
  diagnostics: RawDiagnostic[];
  coverageLoss: RawDiagnostic[];
  /** Offline gives 'unverified'; any coverage loss gives 'partial'; else 'complete'. */
  completeness: Completeness;
  /** Derived at normalize time (offline_report); the orchestrator unions with ScanOutput.reasons. */
  reasons: ScanReason[];
  severityMappingVersion: string;
  producerVersion: string | null;
};

export interface Adapter<
  P extends SemgrepProbeContext | ZapProbeContext,
  S extends SemgrepScanContext | ZapLiveScanContext,
> {
  name: 'semgrep' | 'zap';
  probe(c: P, d: Deps): Promise<ProbeResult>;
  scan(c: S, d: Deps): Promise<ScanOutput>;
  parse(raw: Uint8Array): ParseResult;
  sourceRefs(doc: JsonValue): SourceRef[];
  normalize(doc: JsonValue, c: NormalizeContext, sources: ReadonlyMap<string, SourceText>): NormalizeOutput;
}

export type ToolCatalog = {
  semgrep: Adapter<SemgrepProbeContext, SemgrepScanContext>;
  zap: Adapter<ZapProbeContext, ZapLiveScanContext>;
};
