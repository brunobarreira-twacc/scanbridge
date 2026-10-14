import type { Candidate, RawDiagnostic } from '../../contracts/adapter.js';
import { SEVERITY_RANK, type ScanReason, type Severity } from '../../contracts/enums.js';
import {
  FINDINGS_MAX,
  OCCURRENCES_PER_FINDING_MAX,
  REFERENCE_MAX,
  REFERENCES_PER_FINDING_MAX,
} from '../../contracts/limits.js';
import type { Finding, Occurrence } from '../../schemas/index.js';
import { canonicalJson, compareOccurrences, type CanonicalJson } from '../fingerprints/index.js';
import { compareCodePoints, type OccurrenceOrderInput } from '../fingerprints/occurrences.js';
import { resolveCandidate, type ResolvedCandidate } from './candidate.js';
import { sanitizeText } from './text.js';

export interface BuildFindingsResult {
  findings: Finding[];
  diagnostics: RawDiagnostic[];
  coverageLoss: RawDiagnostic[];
  reasons: ScanReason[];
}

/**
 * Groups candidates by fingerprint and builds the normalized findings. Caps keep the
 * first entries in canonical order. Diagnostics and reasons describe the findings kept.
 */
export function buildFindings(
  candidates: readonly Candidate[],
  options: { producer: Candidate['producer'] },
): BuildFindingsResult {
  const groups = new Map<string, ResolvedCandidate[]>();
  for (const candidate of candidates) {
    if (candidate.producer !== options.producer) {
      throw new TypeError(`candidate producer ${candidate.producer} does not match ${options.producer}`);
    }
    const resolved = resolveCandidate(candidate);
    const group = groups.get(resolved.fingerprint);
    if (group) group.push(resolved);
    else groups.set(resolved.fingerprint, [resolved]);
  }

  const sortedGroups = [...groups].sort(([a], [b]) => compareCodePoints(a, b));
  const keptGroups = sortedGroups.slice(0, FINDINGS_MAX);
  const droppedFindings = sortedGroups.length - keptGroups.length;

  const findings: Finding[] = [];
  const reasons = new Set<ScanReason>();
  const tally = { oversized: 0, invalid: 0, unreadableSource: 0 };
  let droppedOccurrences = 0;
  let referencesOversized = 0;
  let referencesBeyondCap = 0;

  for (const [fingerprint, group] of keptGroups) {
    const records = sortRecords(group);
    const first = records[0];
    if (!first) throw new Error('empty fingerprint group');

    const severity = aggregateSeverity(records);
    const occurrences = records.slice(0, OCCURRENCES_PER_FINDING_MAX).map((record) => record.occurrence);
    droppedOccurrences += records.length - occurrences.length;

    const references = resolveReferences(records.flatMap((record) => record.references));
    referencesOversized += references.oversized;
    referencesBeyondCap += references.beyondCap;

    for (const record of records) {
      tally.oversized += record.issues.oversized;
      tally.invalid += record.issues.invalid;
      if (record.issues.unreadableSource) tally.unreadableSource++;
    }

    const degraded = records.some((record) => record.degraded);
    const finding: Finding = {
      fingerprint,
      fingerprint_quality: degraded ? 'degraded' : 'exact',
      rule_id: first.ruleId,
      producer_reference: first.producerReference,
      title: first.title,
      severity: severity.severity,
      severity_original: severity.severityOriginal,
      severity_complete: severity.complete,
      confidence: firstPresent(records, (record) => record.confidence),
      category: firstPresent(records, (record) => record.category),
      references: references.references,
      status: 'open',
      redactions_applied: records.some((record) => record.redactionsApplied),
      occurrence_count: records.length,
      occurrences,
    };
    const description = firstPresent(records, (record) => record.description);
    if (description !== null) finding.description = description;
    const producerFingerprint = firstPresent(records, (record) => record.producerFingerprint);
    if (producerFingerprint !== null) finding.producer_fingerprint = producerFingerprint;
    findings.push(finding);

    if (degraded) reasons.add('fingerprint_degraded');
    if (!severity.complete) reasons.add('unmapped_severity');
  }

  const tool = options.producer;
  const diagnostics: RawDiagnostic[] = [];
  const coverageLoss: RawDiagnostic[] = [];
  if (tally.unreadableSource > 0) {
    diagnostics.push({
      code: 'fingerprint_degraded',
      level: 'warn',
      tool,
      message: `${tally.unreadableSource} occurrences use location-based fingerprints because their source could not be read`,
    });
  }
  if (tally.oversized > 0) {
    diagnostics.push({
      code: 'resource_limit_exceeded',
      level: 'warn',
      tool,
      message: `${tally.oversized} identifier values exceeded their limit and were replaced by placeholders`,
    });
  }
  if (tally.invalid > 0) {
    diagnostics.push({
      code: 'malformed_report',
      level: 'warn',
      tool,
      message: `${tally.invalid} identifier values contained control characters and were replaced by placeholders`,
    });
  }
  if (referencesOversized + referencesBeyondCap > 0) {
    diagnostics.push({
      code: 'resource_limit_exceeded',
      level: 'warn',
      tool,
      message: `${referencesOversized} references longer than ${REFERENCE_MAX} code points and ${referencesBeyondCap} references beyond ${REFERENCES_PER_FINDING_MAX} per finding were omitted`,
    });
  }
  if (droppedOccurrences > 0) {
    coverageLoss.push({
      code: 'partial_coverage',
      level: 'warn',
      tool,
      message: `${droppedOccurrences} occurrences beyond ${OCCURRENCES_PER_FINDING_MAX} per finding were dropped`,
    });
  }
  if (droppedFindings > 0) {
    coverageLoss.push({
      code: 'partial_coverage',
      level: 'warn',
      tool,
      message: `${droppedFindings} findings beyond ${FINDINGS_MAX} were dropped`,
    });
  }

  return { findings, diagnostics, coverageLoss, reasons: [...reasons].sort(compareCodePoints) };
}

/** Canonical occurrence order, then a content key so shuffled input gives identical output. */
function sortRecords(group: readonly ResolvedCandidate[]): ResolvedCandidate[] {
  return group
    .map((record) => ({ record, key: recordKey(record) }))
    .sort(
      (a, b) =>
        compareOccurrences(orderInput(a.record.occurrence), orderInput(b.record.occurrence)) ||
        compareCodePoints(a.key, b.key),
    )
    .map((entry) => entry.record);
}

function recordKey(record: ResolvedCandidate): string {
  return canonicalJson(
    toCanonical({
      occurrence: record.occurrence,
      title: record.title,
      description: record.description,
      confidence: record.confidence,
      category: record.category,
      producerFingerprint: record.producerFingerprint,
      references: record.references,
      redactionsApplied: record.redactionsApplied,
    }),
  );
}

function toCanonical(value: unknown): CanonicalJson {
  return JSON.parse(JSON.stringify(value)) as CanonicalJson;
}

function orderInput(occurrence: Occurrence): OccurrenceOrderInput {
  const evidence = occurrence.evidence;
  return {
    source_location: occurrence.source_location ?? null,
    runtime_location: occurrence.runtime_location ?? null,
    evidence: {
      attack: evidence.attack?.text ?? null,
      evidence: evidence.evidence ? { text: evidence.evidence.text } : null,
      message_id: evidence.message_id ?? null,
    },
  };
}

/**
 * Group severity is the highest-ranked known occurrence severity. Its original
 * comes from the first occurrence in canonical order with that severity. Records
 * arrive in canonical order, so the first match is the canonical one.
 */
function aggregateSeverity(records: readonly ResolvedCandidate[]): {
  severity: Severity;
  severityOriginal: string;
  complete: boolean;
} {
  const complete = records.every((record) => record.occurrence.severity !== 'unknown');

  let best: ResolvedCandidate | undefined;
  let bestRank = -1;
  for (const record of records) {
    const severity = record.occurrence.severity;
    if (severity === 'unknown') continue;
    const rank = SEVERITY_RANK[severity];
    if (rank > bestRank) {
      best = record;
      bestRank = rank;
    }
  }

  if (best) {
    return { severity: best.occurrence.severity, severityOriginal: best.occurrence.severity_original, complete };
  }
  const first = records[0];
  return { severity: 'unknown', severityOriginal: first?.occurrence.severity_original ?? '', complete };
}

function firstPresent<T>(records: readonly ResolvedCandidate[], pick: (record: ResolvedCandidate) => T | null): T | null {
  for (const record of records) {
    const value = pick(record);
    if (value !== null) return value;
  }
  return null;
}

/**
 * Sanitizes, drops references over the limit (never truncated), sorts by code
 * point, deduplicates and keeps the first per-finding maximum.
 */
function resolveReferences(raw: readonly string[]): { references: string[]; oversized: number; beyondCap: number } {
  const unique = [...new Set(raw.map(sanitizeText))];
  const fitting = unique.filter((reference) => [...reference].length <= REFERENCE_MAX).sort(compareCodePoints);
  const references = fitting.slice(0, REFERENCES_PER_FINDING_MAX);
  return {
    references,
    oversized: unique.length - fitting.length,
    beyondCap: fitting.length - references.length,
  };
}
