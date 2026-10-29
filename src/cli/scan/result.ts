import type { RawDiagnostic } from '../../contracts/adapter.js';
import { SCHEMA_VERSION, type Completeness, type ScanReason } from '../../contracts/enums.js';
import { finalizeDiagnostics } from '../../core/findings/index.js';
import { redactText, type Policy } from '../../core/redaction/index.js';
import { serializeCanonical } from '../../core/serialization/index.js';
import { ScanResultSchema, type ScanResult } from '../../schemas/index.js';

export type ScanExit = ScanResult['exit_code'];

export type Exclusion = { path: string; reason: string };

/** Everything the `scan-result.json` envelope needs; `artifacts` paths are relative to the scan directory. */
export type ScanSummary = {
  status: Completeness;
  exitCode: ScanExit;
  scanId: string;
  adapter: 'semgrep' | 'zap' | 'sonarqube';
  startedAt: Date;
  finishedAt: Date;
  authoritative: boolean;
  reasons: readonly ScanReason[];
  findingsCount: number;
  exclusions: readonly Exclusion[];
  diagnostics: readonly RawDiagnostic[];
  artifacts: { directory: string | null; raw: string[] | null; normalized: string | null };
};

/** Producer text in `detail` is redacted before it becomes a schema diagnostic; a detail that cannot be redacted is dropped. */
export function sanitizeDiagnostics(raw: readonly RawDiagnostic[], policy: Policy | null): RawDiagnostic[] {
  const seen = new Set<string>();
  const out: RawDiagnostic[] = [];
  for (const diagnostic of raw) {
    const key = JSON.stringify([diagnostic.code, diagnostic.level, diagnostic.tool, diagnostic.message, diagnostic.detail]);
    if (seen.has(key)) continue;
    seen.add(key);
    const { detail, ...rest } = diagnostic;
    const copy: RawDiagnostic = { ...rest };
    if (detail !== undefined && policy !== null) {
      try {
        copy.detail = redactText(detail, policy).text;
      } catch {
        // dropped: unredacted producer text never reaches the envelope
      }
    }
    out.push(copy);
  }
  return out;
}

/** The exact bytes of `scan-result.json` and of stdout. */
export function scanResultText(summary: ScanSummary, policy: Policy | null): string {
  const durationMs = Math.max(0, summary.finishedAt.getTime() - summary.startedAt.getTime());
  const result = ScanResultSchema.parse({
    schema_version: SCHEMA_VERSION,
    command: 'scan',
    status: summary.status,
    exit_code: summary.exitCode,
    scan_id: summary.scanId,
    adapter: summary.adapter,
    started_at: summary.startedAt.toISOString(),
    finished_at: summary.finishedAt.toISOString(),
    duration_ms: durationMs,
    authoritative: summary.authoritative,
    non_authoritative_reasons: [...summary.reasons],
    findings_count: summary.findingsCount,
    exclusions: summary.exclusions.map((e) => ({ path: e.path, reason: e.reason })),
    diagnostics: finalizeDiagnostics(sanitizeDiagnostics(summary.diagnostics, policy)),
    artifacts: summary.artifacts,
  });
  return serializeCanonical('ScanResult', result);
}
