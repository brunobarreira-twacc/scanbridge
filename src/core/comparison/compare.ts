import { COMPARE_REASONS, type CompareReason } from '../../contracts/enums.js';
import type { CompareFinding, CompareResult, NormalizedDocument } from '../../schemas/index.js';
import { matchedEntry, oneSidedEntry } from './findings.js';
import { compareTargets } from './targets.js';

export type CompareError = 'incompatible_reports' | 'partial_input_refused';

export type CompareOutcome = { ok: true; result: CompareResult } | { ok: false; error: CompareError };

export interface CompareOptions {
  allowPartial: boolean;
}

export function compareDocuments(
  base: NormalizedDocument,
  head: NormalizedDocument,
  opts: CompareOptions,
): CompareOutcome {
  if (base.producer !== head.producer) {
    return { ok: false, error: 'incompatible_reports' };
  }
  if (!opts.allowPartial && (base.completeness === 'partial' || head.completeness === 'partial')) {
    return { ok: false, error: 'partial_input_refused' };
  }

  const target = compareTargets(base.target, head.target);
  const sameFingerprintVersion = base.fingerprint_version === head.fingerprint_version;
  const sameMappingVersion = base.severity_mapping_version === head.severity_mapping_version;
  const reasons = comparisonReasons(base, head, opts, target.comparable);
  const sharedAbsenceTrusted = absenceClaimsTrusted(base, head, target.subjectMatches);

  const findings = sameFingerprintVersion
    ? matchedEntries(base, head, sameMappingVersion, sharedAbsenceTrusted)
    : unmatchedEntries(base, head);

  return {
    ok: true,
    result: {
      command: 'compare',
      // Authoritative only when no compare-level reason applies. Non-authoritative inputs and
      // allowed partial inputs both add a reason, so an empty list covers every condition.
      authoritative: reasons.length === 0,
      non_authoritative_reasons: reasons,
      base: inputSection(base),
      head: inputSection(head),
      summary: summarize(findings),
      findings,
      metadata: {
        configuration_digest_equal: base.configuration_digest === head.configuration_digest,
      },
    },
  };
}

function comparisonReasons(
  base: NormalizedDocument,
  head: NormalizedDocument,
  opts: CompareOptions,
  targetComparable: boolean,
): CompareReason[] {
  const reasons = new Set<CompareReason>();

  if (opts.allowPartial && (base.completeness === 'partial' || head.completeness === 'partial')) {
    reasons.add('partial_input_allowed');
  }
  if (!base.authoritative) reasons.add('base_input_non_authoritative');
  if (!head.authoritative) reasons.add('head_input_non_authoritative');

  if (base.producer_version === null || head.producer_version === null) {
    reasons.add('producer_version_incomparable');
  } else if (base.producer_version !== head.producer_version) {
    reasons.add('producer_version_mismatch');
  }

  if (base.rules_digest !== head.rules_digest) reasons.add('rules_mismatch');
  if (base.redaction_policy_version !== head.redaction_policy_version) reasons.add('redaction_policy_mismatch');
  if (base.fingerprint_version !== head.fingerprint_version) reasons.add('fingerprint_version_mismatch');
  if (base.severity_mapping_version !== head.severity_mapping_version) {
    reasons.add('severity_mapping_version_mismatch');
  }
  if (!targetComparable) reasons.add('target_identity_incomparable');

  // Spec 04 keeps the closed list in a fixed order; output follows it.
  return COMPARE_REASONS.filter((reason) => reasons.has(reason));
}

/**
 * Conditions shared by both one-sided directions. A one-sided entry is trusted only when these
 * hold and the input lacking the finding is `complete`.
 */
function absenceClaimsTrusted(base: NormalizedDocument, head: NormalizedDocument, subjectMatches: boolean): boolean {
  return (
    subjectMatches &&
    base.rules_digest === head.rules_digest &&
    base.redaction_policy_version === head.redaction_policy_version &&
    !base.non_authoritative_reasons.includes('fingerprint_degraded') &&
    !head.non_authoritative_reasons.includes('fingerprint_degraded')
  );
}

function matchedEntries(
  base: NormalizedDocument,
  head: NormalizedDocument,
  sameMappingVersion: boolean,
  sharedAbsenceTrusted: boolean,
): CompareFinding[] {
  const baseByFingerprint = new Map(base.findings.map((finding) => [finding.fingerprint, finding] as const));
  const headByFingerprint = new Map(head.findings.map((finding) => [finding.fingerprint, finding] as const));
  const fingerprints = [...new Set([...baseByFingerprint.keys(), ...headByFingerprint.keys()])].sort();

  return fingerprints.flatMap((fingerprint) => {
    const baseFinding = baseByFingerprint.get(fingerprint);
    const headFinding = headByFingerprint.get(fingerprint);

    if (baseFinding && headFinding) {
      return [matchedEntry(fingerprint, baseFinding, headFinding, sameMappingVersion)];
    }
    if (baseFinding) {
      // Base-only: the head input is the one lacking the finding.
      const trusted = sharedAbsenceTrusted && head.completeness === 'complete';
      return [oneSidedEntry(fingerprint, { base: baseFinding }, trusted ? 'resolved' : 'incomparable')];
    }
    if (headFinding) {
      // Head-only: the base input is the one lacking the finding.
      const trusted = sharedAbsenceTrusted && base.completeness === 'complete';
      return [oneSidedEntry(fingerprint, { head: headFinding }, trusted ? 'new' : 'incomparable')];
    }
    return [];
  });
}

/** Different fingerprint versions: no matching; every finding of both inputs is its own incomparable entry. */
function unmatchedEntries(base: NormalizedDocument, head: NormalizedDocument): CompareFinding[] {
  const entries: CompareFinding[] = [
    ...base.findings.map((finding) => oneSidedEntry(finding.fingerprint, { base: finding }, 'incomparable')),
    ...head.findings.map((finding) => oneSidedEntry(finding.fingerprint, { head: finding }, 'incomparable')),
  ];
  // Base entries come before head entries for the same fingerprint.
  return entries.sort((left, right) => {
    if (left.fingerprint !== right.fingerprint) return left.fingerprint < right.fingerprint ? -1 : 1;
    return (left.base ? 0 : 1) - (right.base ? 0 : 1);
  });
}

function inputSection(document: NormalizedDocument): CompareResult['base'] {
  const { target } = document;
  return {
    producer_version: document.producer_version,
    completeness: document.completeness,
    authoritative: document.authoritative,
    non_authoritative_reasons: document.non_authoritative_reasons,
    asserted_revision:
      target.kind === 'http_origin' && target.asserted_revision !== undefined
        ? { value: target.asserted_revision, asserted: true }
        : null,
  };
}

function summarize(findings: CompareFinding[]): CompareResult['summary'] {
  const summary: CompareResult['summary'] = {
    new: 0,
    resolved: 0,
    unchanged: 0,
    changed: 0,
    severity_increased: 0,
    severity_decreased: 0,
    incomparable: 0,
    severity_comparison_incomparable: 0,
  };
  for (const finding of findings) {
    summary[finding.state] += 1;
    if (finding.severity_comparison === 'incomparable') summary.severity_comparison_incomparable += 1;
  }
  return summary;
}
