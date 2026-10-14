import type { Candidate, NormalizeContext, NormalizeOutput, RawDiagnostic } from '../../contracts/adapter.js';
import type { Completeness, JsonValue } from '../../contracts/enums.js';
import { SEMGREP_MAPPING_VERSION } from '../../contracts/enums.js';
import type { SourceText } from '../../contracts/ports.js';
import { asSemgrepDocument, isObject, sourceKey, usableResult, type JsonObject } from './document.js';
import { classifyErrors } from './errors.js';
import { mapSeverity } from './severity.js';

function isStringArray(value: JsonValue | undefined): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === 'string');
}

export function normalize(
  doc: JsonValue,
  ctx: NormalizeContext,
  sources: ReadonlyMap<string, SourceText>,
): NormalizeOutput {
  const semgrep = asSemgrepDocument(doc);
  if (!semgrep) {
    return {
      candidates: [],
      unusableCount: 0,
      diagnostics: [{ code: 'malformed_report', level: 'error', tool: 'semgrep', message: 'Semgrep document has an unsupported shape' }],
      coverageLoss: [],
      completeness: 'failed',
      reasons: [],
      severityMappingVersion: SEMGREP_MAPPING_VERSION,
      producerVersion: ctx.producerVersion,
    };
  }

  const candidates: Candidate[] = [];
  const diagnostics: RawDiagnostic[] = [];
  const coverageLoss: RawDiagnostic[] = [...ctx.coverageLoss];
  let unusableCount = 0;
  let unmappedSeverity = 0;

  semgrep.results.forEach((entry, index) => {
    const result = usableResult(entry);
    if (!result) {
      unusableCount++;
      return;
    }
    const { ruleId, path, start, end, extra } = result;
    const metadata: JsonObject = isObject(extra.metadata) ? extra.metadata : {};
    const severity = mapSeverity(extra.severity);
    if (severity === 'unknown') unmappedSeverity++;

    const source = sources.get(sourceKey(path, start.line, end.line));
    const pointerPrefix = `/results/${index}/`;
    const touched = [...ctx.redactionTouched].some((p) => p.startsWith(pointerPrefix));

    const candidate: Candidate = {
      producer: 'semgrep',
      ruleId,
      producerReference: null,
      producerFingerprint: typeof extra.fingerprint === 'string' ? extra.fingerprint : null,
      title: ruleId,
      description: typeof extra.message === 'string' ? extra.message : null,
      confidence: typeof metadata.confidence === 'string' ? metadata.confidence : null,
      category: typeof metadata.category === 'string' ? metadata.category : null,
      references: isStringArray(metadata.references) ? metadata.references : [],
      severityOriginal: typeof extra.severity === 'string' ? extra.severity : '',
      severity,
      location: {
        source: { path, startLine: start.line, startCol: start.col, endLine: end.line, endCol: end.col },
      },
      evidence: { producer_lines: typeof extra.lines === 'string' ? extra.lines : null },
      redactionsApplied: touched || (source?.ok === true && source.redacted),
    };
    if (source) {
      candidate.snippet = source.ok ? { ok: true, text: source.text } : { ok: false, reason: source.reason };
    }
    candidates.push(candidate);
  });

  const scannedCount = semgrep.paths.scanned.filter((s) => typeof s === 'string').length;
  const errors = classifyErrors(semgrep.errors, {
    findings: candidates.length > 0,
    scannedFiles: scannedCount > 0,
  });
  coverageLoss.push(...errors.coverageLoss);
  diagnostics.push(...errors.diagnostics);

  if (unmappedSeverity > 0) {
    diagnostics.push({
      code: 'unmapped_severity',
      level: 'warn',
      tool: 'semgrep',
      message: `${unmappedSeverity} results have a severity outside the semgrep-1 table`,
    });
  }
  if (unusableCount > 0) {
    diagnostics.push({
      code: 'malformed_report',
      level: 'warn',
      tool: 'semgrep',
      message: `${unusableCount} results lack required fields and were excluded`,
    });
  }
  const noFiles = scannedCount === 0;
  if (noFiles) {
    diagnostics.push({ code: 'no_files_scanned', level: 'warn', tool: 'semgrep', message: 'Semgrep scanned no files' });
  }

  let completeness: Completeness;
  if (errors.failed || (unusableCount > 0 && candidates.length === 0)) {
    completeness = 'failed';
  } else if (coverageLoss.length > 0 || unusableCount > 0 || noFiles) {
    completeness = 'partial';
  } else {
    completeness = 'complete';
  }

  return {
    candidates,
    unusableCount,
    diagnostics,
    coverageLoss,
    completeness,
    reasons: [],
    severityMappingVersion: SEMGREP_MAPPING_VERSION,
    producerVersion: typeof semgrep.version === 'string' ? semgrep.version : ctx.producerVersion,
  };
}
