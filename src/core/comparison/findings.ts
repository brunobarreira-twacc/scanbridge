import { SEVERITY_RANK, type Severity } from '../../contracts/enums.js';
import type { CompareFinding, Finding, FindingReference } from '../../schemas/index.js';

type ChangedField = CompareFinding['changed_fields'][number];
type CompareState = CompareFinding['state'];

/** Finding reference: everything except occurrences and evidence (spec 07). */
export function referenceOf(finding: Finding): FindingReference {
  return {
    rule_id: finding.rule_id,
    producer_reference: finding.producer_reference,
    title: finding.title,
    fingerprint_quality: finding.fingerprint_quality,
    severity: finding.severity,
    severity_original: finding.severity_original,
    severity_complete: finding.severity_complete,
    confidence: finding.confidence,
    occurrence_count: finding.occurrence_count,
    occurrence_severities: sorted(finding.occurrences.map((occurrence) => occurrence.severity_original)),
  };
}

/** `unknown` has no rank. */
export function rankOf(severity: Severity): number | undefined {
  return severity === 'unknown' ? undefined : SEVERITY_RANK[severity];
}

/** A severity comparison needs both severities known and complete, under the same mapping version. */
export function severityComparable(base: Finding, head: Finding, sameMappingVersion: boolean): boolean {
  return (
    sameMappingVersion &&
    base.severity_complete &&
    head.severity_complete &&
    rankOf(base.severity) !== undefined &&
    rankOf(head.severity) !== undefined
  );
}

/** Sorted by field name, as the spec requires. */
export function changedFields(base: Finding, head: Finding): ChangedField[] {
  const fields: ChangedField[] = [];
  if ((base.confidence?.text ?? null) !== (head.confidence?.text ?? null)) fields.push('confidence');
  if (!sameList(evidenceTexts(base), evidenceTexts(head))) fields.push('evidence');
  if (base.occurrence_count !== head.occurrence_count) fields.push('occurrence_count');
  if (!sameList(occurrenceSeverities(base), occurrenceSeverities(head))) fields.push('occurrence_severities');
  if (base.severity_original !== head.severity_original) fields.push('severity_original');
  if (base.title.text !== head.title.text) fields.push('title');
  return fields;
}

/** Entry for a fingerprint present on both sides. */
export function matchedEntry(
  fingerprint: string,
  base: Finding,
  head: Finding,
  sameMappingVersion: boolean,
): CompareFinding {
  const comparable = severityComparable(base, head, sameMappingVersion);
  const fields = changedFields(base, head);
  const baseRank = rankOf(base.severity);
  const headRank = rankOf(head.severity);

  let state: CompareState = 'unchanged';
  if (comparable && baseRank !== undefined && headRank !== undefined && baseRank !== headRank) {
    state = headRank > baseRank ? 'severity_increased' : 'severity_decreased';
  } else if (fields.length > 0) {
    state = 'changed';
  }

  return {
    fingerprint,
    state,
    severity_comparison: comparable ? 'comparable' : 'incomparable',
    changed_fields: fields,
    base: referenceOf(base),
    head: referenceOf(head),
  };
}

/** Entry for a fingerprint present on one side only. Severity comparison is always incomparable. */
export function oneSidedEntry(
  fingerprint: string,
  side: { base: Finding } | { head: Finding },
  state: CompareState,
): CompareFinding {
  return {
    fingerprint,
    state,
    severity_comparison: 'incomparable',
    changed_fields: [],
    base: 'base' in side ? referenceOf(side.base) : null,
    head: 'head' in side ? referenceOf(side.head) : null,
  };
}

/** Per-occurrence `{text}` evidence values (snippet, attack, evidence), flattened and sorted. Ignores message_id and locations. */
function evidenceTexts(finding: Finding): string[] {
  const texts: string[] = [];
  for (const occurrence of finding.occurrences) {
    for (const field of [occurrence.evidence.snippet, occurrence.evidence.attack, occurrence.evidence.evidence]) {
      if (field) texts.push(field.text);
    }
  }
  return sorted(texts);
}

function occurrenceSeverities(finding: Finding): string[] {
  return sorted(finding.occurrences.map((occurrence) => occurrence.severity_original));
}

function sorted(values: string[]): string[] {
  return [...values].sort();
}

function sameList(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
