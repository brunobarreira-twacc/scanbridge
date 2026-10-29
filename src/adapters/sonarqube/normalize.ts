import type { Candidate, NormalizeContext, NormalizeOutput, RawDiagnostic } from '../../contracts/adapter.js';
import type { JsonValue } from '../../contracts/enums.js';
import { SONARQUBE_MAPPING_VERSION } from '../../contracts/enums.js';
import type { SourceText } from '../../contracts/ports.js';
import { asSonarQubeDocument, asUsableIssue, type ImpactEntry } from './document.js';
import { mapSeverity } from './severity.js';

const REDACTION_POINTER = /^\/issues\/(\d+)(?:\/|$)/;

function diag(code: RawDiagnostic['code'], level: RawDiagnostic['level'], message: string): RawDiagnostic {
  return { code, level, tool: 'sonarqube', message };
}

/**
 * Picks the severity from the impacts array. For VULNERABILITY, prefer the SECURITY impact;
 * for BUG, prefer the RELIABILITY impact. Fall back to the highest-ranked impact severity.
 */
function pickSeverityOriginal(type: string, impacts: ImpactEntry[]): string {
  const preferred = type === 'VULNERABILITY' ? 'SECURITY' : 'RELIABILITY';
  const match = impacts.find((i) => i.softwareQuality === preferred);
  if (match) return match.severity;

  const RANK: Record<string, number> = { BLOCKER: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const best = impacts.reduce((a, b) => ((RANK[b.severity] ?? -1) > (RANK[a.severity] ?? -1) ? b : a));
  return best.severity;
}

/**
 * Extracts a repository-relative path from a SonarQube component reference.
 * Component format: "projectKey:path/to/file.java"
 */
function componentToPath(component: string, projectKey: string): string {
  const prefix = `${projectKey}:`;
  return component.startsWith(prefix) ? component.slice(prefix.length) : component;
}

export function normalize(
  doc: JsonValue,
  ctx: NormalizeContext,
  _sources: ReadonlyMap<string, SourceText>,
): NormalizeOutput {
  const document = asSonarQubeDocument(doc);
  if (document === null) {
    return {
      candidates: [],
      unusableCount: 0,
      diagnostics: [diag('malformed_report', 'error', 'SonarQube document has an unsupported shape')],
      coverageLoss: [],
      completeness: 'failed',
      reasons: ctx.mode === 'offline' ? ['offline_report'] : [],
      severityMappingVersion: SONARQUBE_MAPPING_VERSION,
      producerVersion: ctx.producerVersion,
    };
  }

  const candidates: Candidate[] = [];
  const diagnostics: RawDiagnostic[] = [];
  let unusableCount = 0;

  for (let i = 0; i < document.issues.length; i++) {
    const issue = asUsableIssue(document.issues[i] ?? null);
    if (issue === null) {
      unusableCount++;
      continue;
    }

    const severityOriginal = pickSeverityOriginal(issue.type, issue.impacts);
    const severity = mapSeverity(severityOriginal);
    if (severity === 'unknown') {
      diagnostics.push(diag('unmapped_severity', 'warn', `Unmapped severity value: ${severityOriginal}`));
    }

    const path = componentToPath(issue.component, document.projectKey);

    let sourceLocation: Candidate['location']['source'] | undefined;
    if (issue.textRange !== null) {
      sourceLocation = {
        path,
        startLine: issue.textRange.startLine,
        startCol: issue.textRange.startOffset,
        endLine: issue.textRange.endLine,
        endCol: issue.textRange.endOffset,
      };
    } else if (issue.line !== null) {
      sourceLocation = { path, startLine: issue.line, startCol: 0, endLine: issue.line, endCol: 0 };
    }

    const redactionsApplied = [...ctx.redactionTouched].some((ptr) => {
      const m = REDACTION_POINTER.exec(ptr);
      return m !== null && Number(m[1]) === i;
    });

    candidates.push({
      producer: 'sonarqube',
      ruleId: issue.rule,
      producerReference: issue.key,
      producerFingerprint: issue.hash,
      title: issue.message,
      description: null,
      confidence: null,
      category: issue.type,
      references: [],
      severityOriginal,
      severity,
      location: sourceLocation !== undefined ? { source: sourceLocation } : {},
      evidence: {},
      redactionsApplied,
    });
  }

  const coverageLoss = [...ctx.coverageLoss];
  let completeness: NormalizeOutput['completeness'];
  if (coverageLoss.length > 0 || unusableCount > 0) {
    completeness = 'partial';
  } else if (ctx.mode === 'offline') {
    completeness = 'unverified';
  } else {
    completeness = 'complete';
  }

  return {
    candidates,
    unusableCount,
    diagnostics,
    coverageLoss,
    completeness,
    reasons: ctx.mode === 'offline' ? ['offline_report'] : [],
    severityMappingVersion: SONARQUBE_MAPPING_VERSION,
    producerVersion: ctx.producerVersion,
  };
}
